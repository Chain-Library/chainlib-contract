#[starknet::interface]
trait IUserRegistry {
    fn create_user(self: @ContractState, user: ContractAddress, name: felt252, email: felt252);
    fn update_user(self: @ContractState, user: ContractAddress, name: felt252, email: felt252);
    fn get_user(self: @ContractState, user: ContractAddress) -> (felt252, felt252, bool);
    fn deactivate_user(self: @ContractState, user: ContractAddress);
}

