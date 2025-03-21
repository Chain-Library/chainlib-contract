#[starknet::contract]
mod UserRegistry {
    use starknet::contract_address::ContractAddress;
    use starknet::storage;
    use starknet::syscalls::get_caller_address;
    use core::integer::u128;
    
    #[derive(Drop, Copy, Serde)]
    struct Profile {
        id: u128,
        user_address: ContractAddress,
        name: felt252,
        is_active: bool,
    }

    #[storage]
    struct Storage {
        profiles: Map<u128, Profile>,
        profile_by_address: Map<ContractAddress, u128>, // Maps address to profile ID
        profile_count: u128, // Tracks the total number of profiles
    }

    #[event]
    struct ProfileUpdated {
        user: ContractAddress,
    }

    #[event]
    struct ProfileDeactivated {
        user: ContractAddress,
    }

    #[starknet::interface]
    trait IUserRegistry<TContractState> {
        fn update_profile(ref self: TContractState, name: felt252);
        fn deactivate_profile(ref self: TContractState);
        fn get_profile_by_id(self: @TContractState, id: u128) -> Profile;
        fn get_profile_by_address(self: @TContractState, address: ContractAddress) -> Profile;
    }

    #[external(v0)]
    impl IUserRegistry<ContractState> of IUserRegistry<ContractState> {
        fn update_profile(ref self: ContractState, name: felt252) {
            let caller = get_caller_address();
            let id = self.profile_by_address.get(caller).unwrap_or_else(|| panic!("Profile not found"));

            let mut profile = self.profiles.get(id).unwrap_or_else(|| panic!("Profile not found"));
            assert!(profile.user_address == caller, "Unauthorized");

            profile.name = name;
            self.profiles.insert(id, profile);
            self.emit(ProfileUpdated { user: caller });
        }

        fn deactivate_profile(ref self: ContractState) {
            let caller = get_caller_address();
            let id = self.profile_by_address.get(caller).unwrap_or_else(|| panic!("Profile not found"));

            let mut profile = self.profiles.get(id).unwrap_or_else(|| panic!("Profile not found"));
            assert!(profile.user_address == caller, "Unauthorized");

            profile.is_active = false;
            self.profiles.insert(id, profile);
            self.emit(ProfileDeactivated { user: caller });
        }

        fn get_profile_by_id(self: @ContractState, id: u128) -> Profile {
            return self.profiles.get(id).unwrap_or_else(|| panic!("Profile not found"));
        }

        fn get_profile_by_address(self: @ContractState, address: ContractAddress) -> Profile {
            let id = self.profile_by_address.get(address).unwrap_or_else(|| panic!("Profile not found"));
            return self.profiles.get(id).unwrap_or_else(|| panic!("Profile not found"));
        }
    }
}
