#[cfg(test)]
mod permission_tests {
    use chain_lib::chainlib::ChainLib;
    use chain_lib::interfaces::IChainLib::{
        IChainLib, IChainLibDispatcher, IChainLibDispatcherTrait,
    };
    use snforge_std::{
        CheatSpan, ContractClassTrait, DeclareResultTrait, cheat_caller_address, declare,
    };
    use starknet::ContractAddress;
    use starknet::class_hash::ClassHash;
    use starknet::contract_address::contract_address_const;
    use starknet::get_caller_address;
    use core::array::ArrayTrait;
    use core::option::OptionTrait;
    use chain_lib::base::types::{
        permission_flags, AccessRule, AccessType, VerificationRequirement, VerificationType,
        Permissions,
    };
    use chain_lib::chainlib::ChainLib::ChainLib::{ContentType, Category, ContentMetadata};

    fn setup() -> (ContractAddress, ContractAddress) {
        let declare_result = declare("ChainLib");
        assert(declare_result.is_ok(), 'declare failed');
        let admin_address: ContractAddress = contract_address_const::<'admin'>();

        let contract_class = declare_result.unwrap().contract_class();
        let mut calldata = array![admin_address.into()];

        let deploy_result = contract_class.deploy(@calldata);
        assert(deploy_result.is_ok(), 'deploy failed');

        let (contract_address, _) = deploy_result.unwrap();

        (contract_address, admin_address)
    }

    #[test]
    fn test_content_access_rules_workflow() {
        let (contract_address, _) = setup();
        let dispatcher = IChainLibDispatcher { contract_address };
        let content_id = 123;
        let user = contract_address_const::<'user'>();
        let admin = contract_address_const::<'admin'>();

        // Test set_content_access_rules
        let mut rules = ArrayTrait::new();
        rules
            .append(
                AccessRule {
                    access_type: AccessType::View,
                    permission_level: 1,
                    conditions: Option::None,
                    expires_at: 0,
                },
            );
        rules
            .append(
                AccessRule {
                    access_type: AccessType::Edit,
                    permission_level: 2,
                    conditions: Option::None,
                    expires_at: 0,
                },
            );

        // Only admin or creator can set rules
        cheat_caller_address(contract_address, admin, CheatSpan::Indefinite);
        assert!(dispatcher.set_content_access_rules(content_id, rules), "Failed to set rules");

        // Test get_content_access_rules
        let retrieved_rules = dispatcher.get_content_access_rules(content_id);
        assert(retrieved_rules.len() == 2, 'Incorrect number of rules');
        assert(*retrieved_rules[0].access_type == AccessType::View, 'First rule incorrect');
        assert(*retrieved_rules[1].access_type == AccessType::Edit, 'Second rule incorrect');

        // Test add_content_access_rule
        let new_rule = AccessRule {
            access_type: AccessType::Admin,
            permission_level: 3,
            conditions: Option::None,
            expires_at: 0,
        };
        assert!(dispatcher.add_content_access_rule(content_id, new_rule), "Failed to add rule");

        let updated_rules = dispatcher.get_content_access_rules(content_id);
        assert(updated_rules.len() == 3, 'Rule not added');
        assert(*updated_rules[2].access_type == AccessType::Admin, 'New rule incorrect');
    }

    #[test]
    fn test_verification_workflow() {
        let (contract_address, admin_address) = setup();
        let dispatcher = IChainLibDispatcher { contract_address };
        let content_id = 456;
        let user = contract_address_const::<0x03>();

        // Test set_verification_requirements
        let mut requirements = ArrayTrait::new();
        requirements
            .append(
                VerificationRequirement {
                    requirement_type: VerificationType::Identity, valid_until: 0, threshold: 1,
                },
            );
        requirements
            .append(
                VerificationRequirement {
                    requirement_type: VerificationType::Payment, valid_until: 0, threshold: 1,
                },
            );

        cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);
        assert!(
            dispatcher.set_verification_requirements(content_id, requirements),
            "Failed to set requirements",
        );

        // Test get_verification_requirements
        let retrieved_reqs = dispatcher.get_verification_requirements(content_id);
        assert(retrieved_reqs.len() == 2, 'Incorrect No. of requirements');
        assert(
            *retrieved_reqs[0].requirement_type == VerificationType::Identity,
            'First req incorrect',
        );
        assert(
            *retrieved_reqs[1].requirement_type == VerificationType::Payment,
            'Second req incorrect',
        );

        // Test set_user_verification
        assert!(
            dispatcher.set_user_verification(user, VerificationType::Identity, true),
            "Failed to set identity verification",
        );
        assert!(
            dispatcher.set_user_verification(user, VerificationType::Payment, true),
            "Failed to set payment verification",
        );

        // Test check_verification_requirements
        assert!(
            dispatcher.check_verification_requirements(user, content_id),
            "Verification check failed",
        );

        // Test with one verification missing
        assert!(
            dispatcher.set_user_verification(user, VerificationType::Payment, false),
            "Failed to unset verification",
        );
        assert(
            !dispatcher.check_verification_requirements(user, content_id),
            'Verification check should fail',
        );
    }

    #[test]
    fn test_edge_cases() {
        let (contract_address, admin_address) = setup();
        let dispatcher = IChainLibDispatcher { contract_address };
        let content_id = 999;
        let user = contract_address_const::<0x08>();
        let admin = contract_address_const::<0x09>();

        // Test empty rules
        cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);
        let empty_rules = ArrayTrait::new();
        assert!(
            dispatcher.set_content_access_rules(content_id, empty_rules),
            "Failed to set empty rules",
        );
        assert(dispatcher.get_content_access_rules(content_id).len() == 0, 'Should have no rules');

        // Test expired verification requirements
        let mut requirements = ArrayTrait::new();
        requirements
            .append(
                VerificationRequirement {
                    requirement_type: VerificationType::Identity,
                    valid_until: 1, // Very old timestamp
                    threshold: 1,
                },
            );
        assert!(
            dispatcher.set_verification_requirements(content_id, requirements),
            "Failed to set requirements",
        );

        // Test permission with empty permissions
        assert!(
            !dispatcher.has_content_permission(content_id, user, permission_flags::READ),
            "Should not have permissions",
        );
    }

    #[test]
    #[should_panic]
    fn test_unauthorized_access() {
        let (contract_address, _) = setup();
        let dispatcher = IChainLibDispatcher { contract_address };
        let content_id = 111;
        let non_admin = contract_address_const::<0x0a>();

        // Non-admin trying to set rules
        cheat_caller_address(contract_address, non_admin, CheatSpan::Indefinite);
        let rules = ArrayTrait::new();
        dispatcher.set_content_access_rules(content_id, rules);
    }

    #[test]
    fn test_multiple_verification_types() {
        let (contract_address, admin_address) = setup();
        let dispatcher = IChainLibDispatcher { contract_address };
        let content_id = 222;
        let user = contract_address_const::<0x0b>();
        let admin = contract_address_const::<0x0c>();

        // Set requirements for all verification types
        let mut requirements = ArrayTrait::new();
        requirements
            .append(
                VerificationRequirement {
                    requirement_type: VerificationType::Identity, valid_until: 0, threshold: 1,
                },
            );
        requirements
            .append(
                VerificationRequirement {
                    requirement_type: VerificationType::Payment, valid_until: 0, threshold: 1,
                },
            );
        requirements
            .append(
                VerificationRequirement {
                    requirement_type: VerificationType::Reputation, valid_until: 0, threshold: 1,
                },
            );

        cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);
        assert!(
            dispatcher.set_verification_requirements(content_id, requirements),
            "Failed to set requirements",
        );

        // Verify all types
        assert!(
            dispatcher.set_user_verification(user, VerificationType::Identity, true),
            "Identity failed",
        );
        assert!(
            dispatcher.set_user_verification(user, VerificationType::Payment, true),
            "Payment failed",
        );
        assert!(
            dispatcher.set_user_verification(user, VerificationType::Reputation, true),
            "Reputation failed",
        );

        // All requirements should be met
        assert!(
            dispatcher.check_verification_requirements(user, content_id),
            "All verifications should pass",
        );

        // Remove one verification
        assert!(
            dispatcher.set_user_verification(user, VerificationType::Reputation, false),
            "Failed to unset reputation",
        );
        assert!(
            !dispatcher.check_verification_requirements(user, content_id),
            "Should fail with missing verification",
        );
    }
}
