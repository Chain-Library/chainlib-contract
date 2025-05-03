use starknet::ContractAddress;
use crate::base::types::{Permissions, Rank, Role, TokenBoundAccount, User};
use crate::chainlib::ChainLib::ChainLib::{
    Category, ContentMetadata, ContentType, ContentUpdate, DelegationInfo,
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
    fn register_user(
        ref self: TContractState, username: felt252, role: Role, rank: Rank, metadata: felt252,
    ) -> u256;
    fn verify_user(ref self: TContractState, user_id: u256) -> bool;
    fn retrieve_user_profile(ref self: TContractState, user_id: u256) -> User;
    fn is_verified(ref self: TContractState, user_id: u256) -> bool;
    fn getAdmin(self: @TContractState) -> ContractAddress;
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
    fn register_content(
        ref self: TContractState,
        title: felt252,
        description: felt252,
        content_type: ContentType,
        category: Category,
    ) -> felt252;
    fn get_content(ref self: TContractState, content_id: felt252) -> ContentMetadata;

    /// Process the initial payment when a subscriber signs up
    /// @param amount: The payment amount in wei
    /// @param subscriber: The address of the subscriber
    /// @return: Boolean indicating if the payment was successful
    fn process_initial_payment(
        ref self: TContractState, amount: u256, subscriber: ContractAddress,
    ) -> bool;

    /// Process a recurring payment for an existing subscription
    /// @param subscription_id: The unique identifier of the subscription
    /// @return: Boolean indicating if the payment was successful
    fn process_recurring_payment(ref self: TContractState, subscription_id: u256) -> bool;

    /// Verify if a payment has been processed successfully
    /// @param payment_id: The unique identifier of the payment
    /// @return: Boolean indicating if the payment is verified
    fn verify_payment(ref self: TContractState, payment_id: u256) -> bool;

    /// Process a refund for a subscription
    /// @param subscription_id: The unique identifier of the subscription to refund
    /// @return: Boolean indicating if the refund was successful
    fn process_refund(ref self: TContractState, subscription_id: u256) -> bool;


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

    fn update_content(
        ref self: TContractState,
        content_id: felt252,
        new_title: Option<felt252>,
        new_description: Option<felt252>,
        new_content_type: Option<ContentType>,
        new_category: Option<Category>,
    ) -> bool;

    fn get_content_update_history(
        self: @TContractState, content_id: felt252,
    ) -> Array<ContentUpdate>;

    fn get_content_update_count(self: @TContractState, content_id: felt252) -> u64;
}
