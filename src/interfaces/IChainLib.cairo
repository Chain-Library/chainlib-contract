use starknet::ContractAddress;
use crate::base::types::{TokenBoundAccount, User, Role, Rank, Permissions};

#[starknet::interface]
pub trait IChainLib<TContractState> {
    // Course Management
    fn create_token_account(
        ref self: TContractState, user_name: felt252, init_param1: felt252, init_param2: felt252,
    ) -> u256;

    fn get_token_bound_account(ref self: TContractState, id: u256) -> TokenBoundAccount;
    fn get_token_bound_account_by_owner(
        ref self: TContractState, address: ContractAddress
    ) -> TokenBoundAccount;

    fn register_user(
        ref self: TContractState, username: felt252, role: Role, rank: Rank, metadata: felt252
    ) -> u256;
    fn verify_user(ref self: TContractState, user_id: u256) -> bool;
    fn retrieve_user_profile(ref self: TContractState, user_id: u256) -> User;
    fn getAdmin(self: @TContractState) -> ContractAddress;
    fn is_verified(ref self: TContractState, user_id: u256) -> bool;

    // Permission system
    fn get_permissions(
        self: @TContractState, account_id: u256, operator: ContractAddress
    ) -> Permissions;
    
    fn set_operator_permissions(
        ref self: TContractState, 
        account_id: u256, 
        operator: ContractAddress, 
        permissions: Permissions
    ) -> bool;
    
    fn revoke_operator(
        ref self: TContractState, 
        account_id: u256, 
        operator: ContractAddress
    ) -> bool;
    
    fn has_permission(
        self: @TContractState, 
        account_id: u256, 
        operator: ContractAddress, 
        permission: u64
    ) -> bool;
    
    fn modify_account_permissions(
        ref self: TContractState, 
        account_id: u256, 
        permissions: Permissions
    ) -> bool;
}

