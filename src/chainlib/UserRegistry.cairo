#[starknet::contract]
mod UserRegistry {
    use starknet::{ContractAddress, get_caller_address, get_block_timestamp};
    use super::IUserRegistry;

    #[derive(Drop, Serde, Clone, Copy, PartialEq)]
    struct UserProfile {
        name: felt252,
        email: felt252,
        is_active: bool,
        role: Role,
        rank: Rank,
        metadata: felt252,
        created_at: u64,
        updated_at: u64,
        verified: bool,
    }

    #[derive(Drop, Serde, Copy, PartialEq)]
    enum Role {
        READER,
        WRITER,
        ADMIN,
    }

    #[derive(Drop, Serde, Copy, PartialEq)]
    enum Rank {
        LEVEL1,
        LEVEL2,
        LEVEL3,
    }

    struct Storage {
        users: LegacyMap<ContractAddress, UserProfile>,
        user_ids: LegacyMap<u256, ContractAddress>,
        next_user_id: u256,
        admin: ContractAddress,
        active_users: LegacyMap<ContractAddress, bool>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        UserCreated: UserCreated,
        UserUpdated: UserUpdated,
        UserDeactivated: UserDeactivated,
        UserReactivated: UserReactivated,
        UserVerified: UserVerified,
    }

    #[derive(Drop, starknet::Event)]
    struct UserCreated {
        user_id: u256,
        address: ContractAddress,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct UserUpdated {
        user_id: u256,
        fields: felt252,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct UserDeactivated {
        user_id: u256,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct UserReactivated {
        user_id: u256,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct UserVerified {
        user_id: u256,
        timestamp: u64,
    }

    #[constructor]
    fn constructor(ref self: ContractState, admin: ContractAddress) {
        self.admin.write(admin);
        self.next_user_id.write(1);
    }

    #[abi(embed_v0)]
    impl UserRegistryImpl of IUserRegistry<ContractState> {
        #[external]
        fn create_user(
            ref self: ContractState,
            name: felt252,
            email: felt252,
            role: Role,
            rank: Rank,
            metadata: felt252,
        ) -> u256 {
            let caller = get_caller_address();
            assert(!self.users.contains(caller), "User already exists");

            let user_id = self.next_user_id.read();
            let new_profile = UserProfile {
                name,
                email,
                is_active: true,
                role,
                rank,
                metadata,
                created_at: get_block_timestamp(),
                updated_at: get_block_timestamp(),
                verified: false,
            };

            self.users.write(caller, new_profile);
            self.user_ids.write(user_id, caller);
            self.active_users.write(caller, true);
            self.next_user_id.write(user_id + 1);

            self
                .emit(
                    Event::UserCreated(
                        UserCreated { user_id, address: caller, timestamp: get_block_timestamp() },
                    ),
                );

            user_id
        }

        #[external]
        fn update_user(
            ref self: ContractState,
            user_id: u256,
            name: felt252,
            email: felt252,
            role: Role,
            rank: Rank,
            metadata: felt252,
        ) -> bool {
            let caller = get_caller_address();
            let user_address = self.user_ids.read(user_id);
            let mut profile = self.users.read(user_address);
            let admin = self.admin.read();

            assert(caller == user_address || caller == admin, "Unauthorized");
            assert(self.active_users.read(user_address), "User inactive");

            let mut fields_updated = 0;
            let mut changes_made = false;

            if name != 0 && name != profile.name {
                profile.name = name;
                fields_updated = if fields_updated == 0 {
                    'name'
                } else {
                    'multiple'
                };
                changes_made = true;
            }

            if email != 0 && email != profile.email {
                profile.email = email;
                fields_updated = if fields_updated == 0 {
                    'email'
                } else {
                    'multiple'
                };
                changes_made = true;
            }

            if role != profile.role {
                profile.role = role;
                fields_updated = if fields_updated == 0 {
                    'role'
                } else {
                    'multiple'
                };
                changes_made = true;
            }

            if rank != profile.rank {
                profile.rank = rank;
                fields_updated = if fields_updated == 0 {
                    'rank'
                } else {
                    'multiple'
                };
                changes_made = true;
            }

            if metadata != 0 && metadata != profile.metadata {
                profile.metadata = metadata;
                fields_updated = if fields_updated == 0 {
                    'metadata'
                } else {
                    'multiple'
                };
                changes_made = true;
            }

            if changes_made {
                profile.updated_at = get_block_timestamp();
                self.users.write(user_address, profile);
                self
                    .emit(
                        Event::UserUpdated(
                            UserUpdated {
                                user_id, fields: fields_updated, timestamp: get_block_timestamp(),
                            },
                        ),
                    );
            }

            changes_made
        }

        #[external]
        fn get_user(
            self: @ContractState, user_id: u256,
        ) -> (felt252, felt252, bool, Role, Rank, felt252, bool) {
            let user_address = self.user_ids.read(user_id);
            assert(self.users.contains(user_address), "User not found");
            let profile = self.users.read(user_address);
            (
                profile.name,
                profile.email,
                profile.is_active,
                profile.role,
                profile.rank,
                profile.metadata,
                profile.verified,
            )
        }

        #[external]
        fn get_user_by_address(
            self: @ContractState, address: ContractAddress,
        ) -> (felt252, felt252, bool, Role, Rank, felt252, bool) {
            assert(self.users.contains(address), "User not found");
            let profile = self.users.read(address);
            (
                profile.name,
                profile.email,
                profile.is_active,
                profile.role,
                profile.rank,
                profile.metadata,
                profile.verified,
            )
        }

        #[external]
        fn deactivate_user(ref self: ContractState, user_id: u256) -> bool {
            let caller = get_caller_address();
            let user_address = self.user_ids.read(user_id);
            let admin = self.admin.read();

            assert(caller == user_address || caller == admin, "Unauthorized");
            assert(self.active_users.read(user_address), "Already inactive");

            self.active_users.write(user_address, false);
            let mut profile = self.users.read(user_address);
            profile.is_active = false;
            self.users.write(user_address, profile);

            self
                .emit(
                    Event::UserDeactivated(
                        UserDeactivated { user_id, timestamp: get_block_timestamp() },
                    ),
                );

            true
        }

        #[external]
        fn reactivate_user(ref self: ContractState, user_id: u256) -> bool {
            let caller = get_caller_address();
            let user_address = self.user_ids.read(user_id);
            let admin = self.admin.read();

            assert(caller == user_address || caller == admin, "Unauthorized");
            assert(!self.active_users.read(user_address), "Already active");

            self.active_users.write(user_address, true);
            let mut profile = self.users.read(user_address);
            profile.is_active = true;
            self.users.write(user_address, profile);

            self
                .emit(
                    Event::UserReactivated(
                        UserReactivated { user_id, timestamp: get_block_timestamp() },
                    ),
                );

            true
        }

        #[external]
        fn verify_user(ref self: ContractState, user_id: u256) -> bool {
            let caller = get_caller_address();
            assert(caller == self.admin.read(), "Admin only");

            let user_address = self.user_ids.read(user_id);
            let mut profile = self.users.read(user_address);
            profile.verified = true;
            self.users.write(user_address, profile);

            self
                .emit(
                    Event::UserVerified(UserVerified { user_id, timestamp: get_block_timestamp() }),
                );

            true
        }

        #[external]
        fn is_user_active(self: @ContractState, user_id: u256) -> bool {
            let user_address = self.user_ids.read(user_id);
            self.active_users.read(user_address)
        }

        #[external]
        fn get_admin(self: @ContractState) -> ContractAddress {
            self.admin.read()
        }
    }
}
