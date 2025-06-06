#[cfg(test)]
mod permission_tests {
    use chain_lib::base::types::{Permissions, permission_flags};
    use chain_lib::chainlib::ChainLib;
    use chain_lib::interfaces::IChainLib::{
        IChainLib, IChainLibDispatcher, IChainLibDispatcherTrait,
    };
    use snforge_std::{
        CheatSpan, ContractClassTrait, DeclareResultTrait, cheat_caller_address, declare,
    };
    use starknet::class_hash::ClassHash;
    use starknet::contract_address::contract_address_const;
    use starknet::{ContractAddress, get_caller_address};

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
    fn test_token_account_owner_permissions() {
        let (contract_address, _) = setup();
        let dispatcher = IChainLibDispatcher { contract_address };

        // Test input values
        let user_name: felt252 = 'Alice';
        let init_param1: felt252 = 'alice@mail.com';
        let init_param2: felt252 = 'alice profile';

        // Create account
        let account_id = dispatcher.create_token_account(user_name, init_param1, init_param2);

        // Get the token account
        let token_account = dispatcher.get_token_bound_account(account_id);

        // Verify the account has full permissions for the owner
        assert(token_account.owner_permissions.value == permission_flags::FULL, 'wrong perm');
    }

    #[test]
    fn test_set_and_get_operator_permissions() {
        let (contract_address, _) = setup();
        let dispatcher = IChainLibDispatcher { contract_address };

        // Test input values
        let user_name: felt252 = 'Bob';
        let init_param1: felt252 = 'bob@mail.com';
        let init_param2: felt252 = 'bob profile';

        // Create account
        let account_id = dispatcher.create_token_account(user_name, init_param1, init_param2);

        // Create operator address
        let operator_address: ContractAddress = contract_address_const::<'operator'>();

        // Set READ and EXECUTE permissions for the operator
        let permissions = Permissions { value: permission_flags::READ | permission_flags::EXECUTE };

        // Grant permissions to the operator
        let result = dispatcher.set_operator_permissions(account_id, operator_address, permissions);
        assert(result, 'set perm failed');

        // Check operator permissions
        let operator_permissions = dispatcher.get_permissions(account_id, operator_address);
        assert(
            operator_permissions.value == (permission_flags::READ | permission_flags::EXECUTE),
            'wrong perm',
        );

        // Verify the operator has specific permissions
        let has_read = dispatcher
            .has_permission(account_id, operator_address, permission_flags::READ);
        let has_execute = dispatcher
            .has_permission(account_id, operator_address, permission_flags::EXECUTE);
        let has_write = dispatcher
            .has_permission(account_id, operator_address, permission_flags::WRITE);

        assert(has_read, 'no READ perm');
        assert(has_execute, 'no EXEC perm');
        assert(!has_write, 'has WRITE perm');

        // Revoke operator permissions
        let revoke_result = dispatcher.revoke_operator(account_id, operator_address);
        assert(revoke_result, 'revoke failed');

        // Verify permissions after revocation
        let has_read_after = dispatcher
            .has_permission(account_id, operator_address, permission_flags::READ);
        assert(!has_read_after, 'still has READ');

        // Check that operator permissions are set to NONE
        let operator_permissions_after = dispatcher.get_permissions(account_id, operator_address);
        assert(operator_permissions_after.value == permission_flags::NONE, 'not NONE');
    }

    #[test]
    fn test_manage_operators_permission() {
        let (contract_address, _) = setup();
        let dispatcher = IChainLibDispatcher { contract_address };

        // Create a token account
        let user_name = 'Eve';
        let init_param1 = 'eve@example.com';
        let init_param2 = 'eve profile';

        let account_id = dispatcher.create_token_account(user_name, init_param1, init_param2);

        // Create operator addresses
        let operator1: ContractAddress = contract_address_const::<'operator1'>();
        let operator2: ContractAddress = contract_address_const::<'operator2'>();

        // Give operator1 the MANAGE_OPERATORS permission
        let manage_permissions = Permissions { value: permission_flags::MANAGE_OPERATORS };
        dispatcher.set_operator_permissions(account_id, operator1, manage_permissions);

        // Switch caller to operator1
        cheat_caller_address(contract_address, operator1, CheatSpan::Indefinite);

        // Have operator1 set permissions for operator2
        let read_permissions = Permissions { value: permission_flags::READ };
        let result = dispatcher.set_operator_permissions(account_id, operator2, read_permissions);
        assert(result, 'set perm failed');

        // Verify operator2 has READ permission
        let has_read = dispatcher.has_permission(account_id, operator2, permission_flags::READ);
        assert(has_read, 'no READ perm');
    }

    #[test]
    fn test_modify_account_permissions() {
        let (contract_address, _) = setup();
        let dispatcher = IChainLibDispatcher { contract_address };

        // Create token account
        let user_name: felt252 = 'Charlie';
        let init_param1: felt252 = 'charlie@mail.com';
        let init_param2: felt252 = 'charlie profile';

        let account_id = dispatcher.create_token_account(user_name, init_param1, init_param2);

        // Get initial permissions
        let token_account = dispatcher.get_token_bound_account(account_id);
        assert(token_account.owner_permissions.value == permission_flags::FULL, 'wrong init perm');

        // Modify permissions - remove WRITE permission
        let modified_permissions = Permissions {
            value: permission_flags::FULL & ~permission_flags::WRITE,
        };

        let result = dispatcher.modify_account_permissions(account_id, modified_permissions);
        assert(result, 'mod perm failed');

        // Verify permissions were updated
        let updated_account = dispatcher.get_token_bound_account(account_id);
        let has_write = (updated_account.owner_permissions.value
            & permission_flags::WRITE) == permission_flags::WRITE;
        assert(!has_write, 'still has WRITE');
    }

    #[test]
    fn test_multiple_operators() {
        let (contract_address, _) = setup();
        let dispatcher = IChainLibDispatcher { contract_address };

        // Create token account
        let user_name: felt252 = 'Dave';
        let init_param1: felt252 = 'dave@mail.com';
        let init_param2: felt252 = 'dave profile';

        let account_id = dispatcher.create_token_account(user_name, init_param1, init_param2);

        // Create three operator addresses
        let operator1: ContractAddress = contract_address_const::<'op1'>();
        let operator2: ContractAddress = contract_address_const::<'op2'>();
        let operator3: ContractAddress = contract_address_const::<'op3'>();

        // Assign different permissions to each operator
        dispatcher
            .set_operator_permissions(
                account_id, operator1, Permissions { value: permission_flags::READ },
            );

        dispatcher
            .set_operator_permissions(
                account_id, operator2, Permissions { value: permission_flags::EXECUTE },
            );

        dispatcher
            .set_operator_permissions(
                account_id, operator3, Permissions { value: permission_flags::WRITE },
            );

        // Verify each operator has correct permissions
        assert(
            dispatcher.has_permission(account_id, operator1, permission_flags::READ), 'op1 no READ',
        );
        assert(
            !dispatcher.has_permission(account_id, operator1, permission_flags::EXECUTE),
            'op1 has EXEC',
        );

        assert(
            dispatcher.has_permission(account_id, operator2, permission_flags::EXECUTE),
            'op2 no EXEC',
        );
        assert(
            !dispatcher.has_permission(account_id, operator2, permission_flags::READ),
            'op2 has READ',
        );

        assert(
            dispatcher.has_permission(account_id, operator3, permission_flags::WRITE),
            'op3 no WRITE',
        );
        assert(
            !dispatcher.has_permission(account_id, operator3, permission_flags::READ),
            'op3 has READ',
        );

        // Revoke one operator and check others still have permissions
        dispatcher.revoke_operator(account_id, operator1);

        assert(
            !dispatcher.has_permission(account_id, operator1, permission_flags::READ),
            'op1 still has READ',
        );
        assert(
            dispatcher.has_permission(account_id, operator2, permission_flags::EXECUTE),
            'op2 lost EXEC',
        );
        assert(
            dispatcher.has_permission(account_id, operator3, permission_flags::WRITE),
            'op3 lost WRITE',
        );
    }

    #[test]
    fn test_permission_combinations() {
        let (contract_address, _) = setup();
        let dispatcher = IChainLibDispatcher { contract_address };

        // Create token account
        let user_name: felt252 = 'Frank';
        let init_param1: felt252 = 'frank@mail.com';
        let init_param2: felt252 = 'frank profile';

        let account_id = dispatcher.create_token_account(user_name, init_param1, init_param2);

        // Create operator address
        let operator: ContractAddress = contract_address_const::<'operator'>();

        // Test various permission combinations
        let test_combinations = array![
            (permission_flags::READ | permission_flags::WRITE, 'READ+WRITE'),
            (permission_flags::READ | permission_flags::EXECUTE, 'READ+EXEC'),
            (permission_flags::WRITE | permission_flags::TRANSFER, 'WRITE+TRANSFER'),
            (
                permission_flags::MANAGE_PERMISSIONS | permission_flags::MANAGE_OPERATORS,
                'MANAGE combo',
            ),
        ];

        let mut i: u32 = 0;
        while i < test_combinations.len() {
            let (perm_value, _name) = *test_combinations.at(i);

            // Set the permission combination
            dispatcher
                .set_operator_permissions(account_id, operator, Permissions { value: perm_value });

            // Verify permissions
            let stored_perm = dispatcher.get_permissions(account_id, operator);
            assert(stored_perm.value == perm_value, 'wrong combo perm');

            // Revoke and reset for next test
            dispatcher.revoke_operator(account_id, operator);

            i += 1;
        }
    }

    #[test]
    #[should_panic(expected: 'No permission')]
    fn test_unauthorized_set_operator() {
        let (contract_address, _) = setup();
        let dispatcher = IChainLibDispatcher { contract_address };

        // Create token account
        let user_name: felt252 = 'Greg';
        let init_param1: felt252 = 'greg@mail.com';
        let init_param2: felt252 = 'greg profile';

        let account_id = dispatcher.create_token_account(user_name, init_param1, init_param2);

        // Set up unauthorized caller
        let unauthorized: ContractAddress = contract_address_const::<'hacker'>();
        cheat_caller_address(contract_address, unauthorized, CheatSpan::Indefinite);

        // Attempt to set operator permissions (should fail)
        let operator: ContractAddress = contract_address_const::<'operator'>();
        let permissions = Permissions { value: permission_flags::READ };

        // This call should panic with 'No permission'
        dispatcher.set_operator_permissions(account_id, operator, permissions);
    }

    #[test]
    #[should_panic(expected: 'No permission')]
    fn test_insufficient_permissions() {
        let (contract_address, _) = setup();
        let dispatcher = IChainLibDispatcher { contract_address };

        // Create token account
        let user_name: felt252 = 'Henry';
        let init_param1: felt252 = 'henry@mail.com';
        let init_param2: felt252 = 'henry profile';

        let account_id = dispatcher.create_token_account(user_name, init_param1, init_param2);

        // Create operator with only READ permission
        let operator: ContractAddress = contract_address_const::<'operator'>();
        dispatcher
            .set_operator_permissions(
                account_id, operator, Permissions { value: permission_flags::READ },
            );

        // Switch to operator
        cheat_caller_address(contract_address, operator, CheatSpan::Indefinite);

        // Attempt to add another operator (should fail as it requires MANAGE_OPERATORS permission)
        let new_operator: ContractAddress = contract_address_const::<'new_op'>();
        let permissions = Permissions { value: permission_flags::READ };

        // This call should panic with 'No permission'
        dispatcher.set_operator_permissions(account_id, new_operator, permissions);
    }

    #[test]
    fn test_nonexistent_account() {
        let (contract_address, _) = setup();
        let dispatcher = IChainLibDispatcher { contract_address };

        // Attempt to get permissions for a non-existent account
        let nonexistent_account_id = 9999_u256;
        let operator: ContractAddress = contract_address_const::<'operator'>();

        // Test that we get default permissions (NONE) for non-existent account
        let permissions = dispatcher.get_permissions(nonexistent_account_id, operator);
        assert(permissions.value == permission_flags::NONE, 'should return NONE');

        // Check has_permission also returns false
        let has_read = dispatcher
            .has_permission(nonexistent_account_id, operator, permission_flags::READ);
        assert(!has_read, 'should not have permission');
    }
}
