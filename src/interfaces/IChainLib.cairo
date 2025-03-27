use starknet::ContractAddress;
use crate::base::types::{TokenBoundAccount};

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
    fn test_deployment(ref self: TContractState) -> bool;
}
