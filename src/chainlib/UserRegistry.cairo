use starknet::ContractAddress;
use starknet::get_caller_address;
use starknet::syscalls::emit_event;

#[derive(Drop, Serde, Clone, Copy, PartialEq)]
struct UserProfile {
    name: felt252,
    email: felt252,
    is_active: bool,
}

#[starknet::interface]
trait IUserRegistry {
    fn create_user(self: @ContractState, user: ContractAddress, name: felt252, email: felt252);
    fn update_user(self: @ContractState, user: ContractAddress, name: felt252, email: felt252);
    fn get_user(self: @ContractState, user: ContractAddress) -> (felt252, felt252, bool);
    fn deactivate_user(self: @ContractState, user: ContractAddress);
}

#[starknet::contract]
mod UserRegistry {
    use super::*;
    
    struct Storage {
        users: LegacyMap<ContractAddress, UserProfile>,
    }
    
    #[external]
    fn create_user(self: @ContractState, user: ContractAddress, name: felt252, email: felt252) {
        self.users.write(user, UserProfile { name, email, is_active: true });
        emit_event(("UserCreated", user, name, email));
    }
    
    #[external]
    fn update_user(self: @ContractState, user: ContractAddress, name: felt252, email: felt252) {
        assert!(self.users.contains(user), "User not found");
        let mut profile = self.users.read(user);
        profile.name = name;
        profile.email = email;
        self.users.write(user, profile);
        emit_event(("UserUpdated", user, name, email));
    }
    
    #[external]
    fn get_user(self: @ContractState, user: ContractAddress) -> (felt252, felt252, bool) {
        assert!(self.users.contains(user), "User not found");
        let profile = self.users.read(user);
        (profile.name, profile.email, profile.is_active)
    }
    
    #[external]
    fn deactivate_user(self: @ContractState, user: ContractAddress) {
        assert!(self.users.contains(user), "User not found");
        let mut profile = self.users.read(user);
        profile.is_active = false;
        self.users.write(user, profile);
        emit_event(("UserDeactivated", user));
    }
}

