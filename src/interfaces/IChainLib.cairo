use core::array::Array;
use starknet::ContractAddress;
use crate::base::types::{
    AccessRule, Permissions, Purchase, PurchaseStatus, Rank, Receipt, Role, TokenBoundAccount, User,
    VerificationRequirement, VerificationType,
};
use crate::chainlib::ChainLib::ChainLib::{
    Category, ContentMetadata, ContentType, DelegationInfo, Payment, PlanType, Subscription,
};

#[starknet::interface]
pub trait IChainLib<TContractState> {
    // Existing interface functions
    fn create_token_account(
        ref self: TContractState, user_name: felt252, init_param1: felt252, init_param2: felt252,
    ) -> u256;
    fn get_token_bound_account(ref self: TContractState, id: u256) -> TokenBoundAccount;

    fn get_token_bound_account_by_owner(
        ref self: TContractState, address: ContractAddress,
    ) -> TokenBoundAccount;

    // User Management
    fn register_user(
        ref self: TContractState, username: felt252, role: Role, rank: Rank, metadata: felt252,
    ) -> u256;

    fn verify_user(ref self: TContractState, user_id: u256) -> bool;

    fn retrieve_user_profile(ref self: TContractState, user_id: u256) -> User;

    fn update_user_profile(
        ref self: TContractState,
        id: u256,
        username: felt252,
        wallet_address: ContractAddress,
        role: Role,
        rank: Rank,
        metadata: felt252,
    );

    fn deactivate_profile(ref self: TContractState, user_id: u256) -> bool;

    fn getAdmin(self: @TContractState) -> ContractAddress;

    fn is_verified(ref self: TContractState, user_id: u256) -> bool;

    // Permission System
    fn get_permissions(
        self: @TContractState, account_id: u256, operator: ContractAddress,
    ) -> Permissions;
    fn set_operator_permissions(
        ref self: TContractState,
        account_id: u256,
        operator: ContractAddress,
        permissions: Permissions,
    ) -> bool;
    fn revoke_operator(
        ref self: TContractState, account_id: u256, operator: ContractAddress,
    ) -> bool;
    fn has_permission(
        self: @TContractState, account_id: u256, operator: ContractAddress, permission: u64,
    ) -> bool;
    fn modify_account_permissions(
        ref self: TContractState, account_id: u256, permissions: Permissions,
    ) -> bool;

    // Content Management
    fn register_content(
        ref self: TContractState,
        title: felt252,
        description: felt252,
        content_type: ContentType,
        category: Category,
    ) -> felt252;
    fn get_content(ref self: TContractState, content_id: felt252) -> ContentMetadata;


    fn set_content_price(ref self: TContractState, content_id: felt252, price: u256);

    // Payment System
    fn process_initial_payment(
        ref self: TContractState, amount: u256, subscriber: ContractAddress,
    ) -> bool;

    fn process_recurring_payment(ref self: TContractState, subscription_id: u256) -> bool;

    fn verify_payment(ref self: TContractState, payment_id: u256) -> bool;

    fn process_refund(ref self: TContractState, subscription_id: u256) -> bool;

    // Content Access Control
    fn set_content_access_rules(
        ref self: TContractState, content_id: felt252, rules: Array<AccessRule>,
    ) -> bool;

    fn check_verification_requirements(
        self: @TContractState, user: ContractAddress, content_id: felt252,
    ) -> bool;

    fn get_content_access_rules(self: @TContractState, content_id: felt252) -> Array<AccessRule>;

    fn add_content_access_rule(
        ref self: TContractState, content_id: felt252, rule: AccessRule,
    ) -> bool;

    fn set_verification_requirements(
        ref self: TContractState, content_id: felt252, requirements: Array<VerificationRequirement>,
    ) -> bool;

    fn get_verification_requirements(
        self: @TContractState, content_id: felt252,
    ) -> Array<VerificationRequirement>;

    fn set_user_verification(
        ref self: TContractState,
        user: ContractAddress,
        verification_type: VerificationType,
        is_verified: bool,
    ) -> bool;

    fn grant_content_permissions(
        ref self: TContractState,
        content_id: felt252,
        user: ContractAddress,
        permissions: Permissions,
    ) -> bool;

    fn has_content_permission(
        self: @TContractState, content_id: felt252, user: ContractAddress, permission: u64,
    ) -> bool;

    // NEW - Account Delegation Interface Functions
    fn create_delegation(
        ref self: TContractState,
        delegate: ContractAddress,
        permissions: u64,
        expiration: u64,
        max_actions: u64,
    ) -> bool;

    fn revoke_delegation(
        ref self: TContractState, delegate: ContractAddress, permissions: u64,
    ) -> bool;

    fn is_delegated(
        self: @TContractState,
        delegator: ContractAddress,
        delegate: ContractAddress,
        permission: u64,
    ) -> bool;

    fn use_delegation(
        ref self: TContractState, delegator: ContractAddress, permission: u64,
    ) -> bool;

    // fn execute_as_delegate(
    //     ref self: TContractState,
    //     delegator: ContractAddress,
    //     permission: u64,
    //     to: ContractAddress,
    //     selector: felt252,
    //     calldata: Array<felt252>
    // ) -> Array<felt252>;

    fn get_delegation_info(
        self: @TContractState, delegator: ContractAddress, permission: u64,
    ) -> DelegationInfo;

    fn create_subscription(
        ref self: TContractState, user_id: u256, amount: u256, plan_type: u32,
    ) -> bool;

    fn get_user_subscription(ref self: TContractState, user_id: u256) -> Subscription;

    fn grant_premium_access(ref self: TContractState, user_id: u256, content_id: felt252) -> bool;

    fn is_in_blacklist(self: @TContractState, user_id: u256, content_id: felt252) -> bool;

    fn get_premium_access_status(self: @TContractState, user_id: u256, content_id: felt252) -> bool;

    fn revoke_access(ref self: TContractState, user_id: u256, content_id: felt252) -> bool;
    fn has_active_subscription(self: @TContractState, user_id: u256) -> bool;

    fn set_cache_ttl(ref self: TContractState, ttl_seconds: u64) -> bool;

    fn verify_access(ref self: TContractState, user_id: u256, content_id: felt252) -> bool;

    fn _determine_access(
        ref self: TContractState, user_id: u256, content_id: felt252, user: User,
    ) -> bool;

    fn _update_access_cache(
        ref self: TContractState, cache_key: (u256, felt252), has_access: bool, current_time: u64,
    );
    fn initialize_access_control(ref self: TContractState, default_cache_ttl: u64) -> bool;

    fn clear_access_cache(ref self: TContractState, user_id: u256, content_id: felt252) -> bool;

    fn purchase_content(
        ref self: TContractState, content_id: felt252, transaction_hash: felt252,
    ) -> u256;
    fn get_purchase_details(ref self: TContractState, purchase_id: u256) -> Purchase;
    fn get_user_purchases(
        ref self: TContractState, user_address: ContractAddress,
    ) -> Array<Purchase>;
    fn verify_purchase(ref self: TContractState, purchase_id: u256) -> bool;
    fn update_purchase_status(
        ref self: TContractState, purchase_id: u256, status: PurchaseStatus,
    ) -> bool;
    fn get_content_purchases(ref self: TContractState, content_id: felt252) -> Array<Purchase>;

    fn get_user_subscription_record(ref self: TContractState, user_id: u256) -> Array<Subscription>;
    fn cancel_subscription(ref self: TContractState, user_id: u256) -> bool;
    fn renew_subscription(ref self: TContractState, user_id: u256) -> bool;
    fn issue_receipt(
        ref self: TContractState,
        purchase_id: u256,
        content_id: felt252,
        buyer: ContractAddress,
        creator: ContractAddress,
        price: u256,
        transaction_hash: felt252,
    ) -> u256;

    fn get_receipt(self: @TContractState, receipt_id: u256) -> Receipt;
    fn is_receipt_valid(self: @TContractState, receipt_id: u256) -> bool;
    fn get_total_sales_by_creator(self: @TContractState, creator: ContractAddress) -> u256;
    fn get_total_sales_for_content(self: @TContractState, content_id: felt252) -> u256;
    fn emergency_pause(ref self: TContractState);
    fn emergency_unpause(ref self: TContractState);
    fn is_paused(self: @TContractState) -> bool;
    // fn get_daily_sales(self: @TContractState, day: u64) -> u256;
// fn get_unique_buyers_count(self: @TContractState) -> u256;
}
