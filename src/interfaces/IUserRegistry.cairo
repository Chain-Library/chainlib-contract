
#[starknet::interface]
trait IUserRegistry<TContractState> {
    /// Updates the name of the caller's profile
    fn update_profile(ref self: TContractState, name: felt252);

    /// Deactivates the caller's profile without data loss
    fn deactivate_profile(ref self: TContractState);

    /// Retrieves a profile by its unique ID
    fn get_profile_by_id(self: @TContractState, id: u128) -> Profile;

    /// Retrieves a profile by the associated wallet address
    fn get_profile_by_address(self: @TContractState, address: ContractAddress) -> Profile;
}

