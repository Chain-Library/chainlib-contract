#[starknet::contract]
mod UserRegistry {
    use starknet::ContractAddress;
    use starknet::get_caller_address;
    use starknet::syscalls::emit_event;
    use super::IUserRegistry;

    #[derive(Drop, Serde, Clone, Copy, PartialEq)]
    struct UserProfile {
        name: felt252,
        email: felt252,
        is_active: bool,
    }

    struct Storage {
        users: LegacyMap<ContractAddress, UserProfile>,
    }

    #[abi(embed_v0)]
    impl UserRegistryImpl of IUserRegistry<ContractState> {
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
}
