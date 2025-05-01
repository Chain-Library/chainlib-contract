use starknet::ContractAddress;
use core::array::Array;
use crate::base::types::{
    TokenBoundAccount, User, Role, Rank, Permissions, AccessRule, VerificationRequirement,
    VerificationType,
};
use crate::chainlib::ChainLib::ChainLib::{Category, ContentType, ContentMetadata};

#[starknet::interface]
pub trait IChainLib<TContractState> {
    // Account Management
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
}
