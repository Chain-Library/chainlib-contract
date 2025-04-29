use chain_lib::chainlib::AccountDelegation::AccountDelegation::DelegationInfo;
use starknet::ContractAddress;


#[starknet::interface]
pub trait IAccountDelegation<TContractState> {
    fn add_owner(ref self: TContractState, new_owner: ContractAddress);
    fn delegate_permission(
        ref self: TContractState,
        delegate: ContractAddress,
        permission_id: u8,
        expiry: u64,
        max_actions: u64,
    );
    fn revoke_delegation(ref self: TContractState, permission_id: u8, delegate: ContractAddress);
    fn has_delegation(
        self: @TContractState, owner: ContractAddress, caller: ContractAddress, permission_id: u8,
    ) -> bool;
    fn use_delegation(ref self: TContractState, owner: ContractAddress, permission_id: u8);
    fn get_delegation_info(
        self: @TContractState, owner: ContractAddress, permission_id: u8,
    ) -> DelegationInfo;
    fn is_owner(self: @TContractState, address: ContractAddress) -> bool;
    fn is_valid_permission(self: @TContractState, permission_id: u8) -> bool;
}

