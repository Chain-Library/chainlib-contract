#[starknet::interface]
trait IUserRegistry<TContractState> {
    // Basic user management (existing functions)
    fn create_user(self: @TContractState, user: ContractAddress, name: felt252, email: felt252);

    fn update_user(self: @TContractState, user: ContractAddress, name: felt252, email: felt252);

    fn get_user(self: @TContractState, user: ContractAddress) -> (felt252, felt252, bool);

    fn deactivate_user(self: @TContractState, user: ContractAddress);

    // New functions for enhanced profile management
    fn create_user_profile(
        ref self: TContractState, username: felt252, role: Role, rank: Rank, metadata: felt252,
    ) -> u256;

    fn retrieve_user_profile(self: @TContractState, user_id: u256) -> User;

    fn retrieve_user_profile_by_address(self: @TContractState, address: ContractAddress) -> User;

    fn update_user_profile(
        ref self: TContractState,
        user_id: u256,
        username: felt252,
        role: Role,
        rank: Rank,
        metadata: felt252,
    ) -> bool;

    fn reactivate_user_profile(ref self: TContractState, user_id: u256) -> bool;

    fn is_profile_active(self: @TContractState, user_id: u256) -> bool;

    fn is_verified(self: @TContractState, user_id: u256) -> bool;

    fn get_admin(self: @TContractState) -> ContractAddress;
}
