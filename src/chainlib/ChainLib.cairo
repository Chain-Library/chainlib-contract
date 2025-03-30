#[starknet::contract]
pub mod ChainLib {
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_block_timestamp, get_caller_address};
    use crate::interfaces::IChainLib::IChainLib;
    use crate::base::types::{TokenBoundAccount, User, Role, Rank};

    #[derive(Copy, Drop, Serde, starknet::Store, PartialEq, Debug)]
    pub enum ContentType {
        #[default]
        Text,
        Video,
        Image,
        // Any other content type
    }

    #[derive(Copy, Drop, Serde, starknet::Store, PartialEq, Debug)]
    pub enum Category {
        Software,
        #[default]
        Education,
        Literature,
        Art
    }

    #[derive(Copy, Drop, Serde, starknet::Store, Debug)]
    pub struct ContentMetadata {
        pub content_id: felt252,
        pub title: felt252,
        pub description: felt252,
        pub content_type: ContentType,
        pub creator: ContractAddress,
        pub category: Category
    }

    #[storage]
    struct Storage {
        // Contract addresses for component management
        admin: ContractAddress,
        current_account_id: u256,
        accounts: Map<u256, TokenBoundAccount>,
        accountsaddr: Map<ContractAddress, TokenBoundAccount>,
        next_course_id: u256,
        user_id: u256,
        users: Map<u256, User>,
        creators_content: Map::<ContractAddress, ContentMetadata>,
        content: Map::<felt252, ContentMetadata>,
        content_tags: Map::<ContentMetadata, Array<felt252>>
    }


    #[constructor]
    fn constructor(ref self: ContractState, admin: ContractAddress) {
        // Store the values in contract state
        self.admin.write(admin);
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        TokenBoundAccountCreated: TokenBoundAccountCreated,
        UserCreated: UserCreated,
    }

    #[derive(Drop, starknet::Event)]
    pub struct TokenBoundAccountCreated {
        pub id: u256,
    }

    #[derive(Drop, starknet::Event)]
    pub struct UserCreated {
        pub id: u256,
    }

    #[abi(embed_v0)]
    impl ChainLibNetImpl of IChainLib<ContractState> {
        /// @notice Creates a new token-bound account.
        /// @dev This function generates a unique ID, initializes the account, and emits an event.
        /// @param self The contract state reference.
        /// @param user_name The unique username associated with the token-bound account.
        /// @param init_param1 An initialization parameter required for the account setup.
        /// @param init_param2 An additional initialization parameter.
        /// @return account_id The unique identifier assigned to the token-bound account.
        fn create_token_account(
            ref self: ContractState, user_name: felt252, init_param1: felt252, init_param2: felt252,
        ) -> u256 {
            // Ensure that the username is not empty.
            assert!(user_name != 0, "User name cannot be empty");

            // Validate initialization parameters.
            assert!(init_param1 != 0, "Initialization parameter 1 cannot be empty");

            // Retrieve the current account ID before incrementing.
            let account_id = self.current_account_id.read();

            // Create a new token-bound account with the provided parameters.
            let new_token_bound_account = TokenBoundAccount {
                id: account_id,
                address: get_caller_address(), // Assign the caller's address.
                user_name: user_name,
                init_param1: init_param1,
                init_param2: init_param2,
                created_at: get_block_timestamp(), // Capture the creation timestamp.
                updated_at: get_block_timestamp() // Set initial updated timestamp.
            };

            // Store the new account in the accounts mapping.
            self.accounts.write(account_id, new_token_bound_account);

            // Increment the account ID counter for the next registration.
            self.current_account_id.write(account_id + 1);

            // Emit an event to notify about the new token-bound account creation.
            self.emit(TokenBoundAccountCreated { id: account_id });

            // Return the assigned account ID.
            account_id
        }


        fn get_token_bound_account(ref self: ContractState, id: u256) -> TokenBoundAccount {
            let token_bound_account = self.accounts.read(id);
            token_bound_account
        }
        fn get_token_bound_account_by_owner(
            ref self: ContractState, address: ContractAddress,
        ) -> TokenBoundAccount {
            let token_bound_account = self.accountsaddr.read(address);
            token_bound_account
        }


        /// @notice Registers a new user in the system.
        /// @dev This function assigns a unique ID to the user, stores their profile, and emits an
        /// event.
        /// @param self The contract state reference.
        /// @param username The unique username of the user.
        /// @param wallet_address The blockchain address of the user.
        /// @param role The role of the user (READER or WRITER).
        /// @param rank The rank/level of the user.
        /// @param metadata Additional metadata associated with the user.
        /// @return user_id The unique identifier assigned to the user.
        fn register_user(
            ref self: ContractState, username: felt252, role: Role, rank: Rank, metadata: felt252,
        ) -> u256 {
            // Ensure that the username is not empty.
            assert!(username != 0, "User name cannot be empty");

            // Retrieve the current user ID before incrementing.
            let user_id = self.user_id.read();

            // Create a new user profile with provided details.
            let new_user = User {
                id: user_id,
                username: username,
                wallet_address: get_caller_address(), // Assign the caller's address.
                role: role,
                rank: rank,
                verified: false, // Default verification status is false.
                metadata: metadata,
            };

            // Store the new user in the users mapping.
            self.users.write(user_id, new_user);

            // Increment the user ID counter for the next registration.
            self.current_account_id.write(user_id + 1);

            // Emit an event to notify about the new user registration.
            self.emit(UserCreated { id: user_id });

            // Return the assigned user ID.
            user_id
        }


        /// @notice Verifies a user in the system.
        /// @dev Only an admin can verify a user.
        /// @param self The contract state reference.
        /// @param user_id The unique identifier of the user to be verified.
        /// @return bool Returns true if the user is successfully verified.
        fn verify_user(ref self: ContractState, user_id: u256) -> bool {
            let caller = get_caller_address();
            // Ensure that only an admin can verify users.
            assert((self.admin.read() == caller), 'Only admin can verify users');
            let mut user = self.users.read(user_id);
            user.verified = true;
            self.users.write(user.id, user);
            true
        }
        /// @notice Retrieves a user's profile from the system.
        /// @dev This function fetches the user profile based on the provided user ID.
        /// @param self The contract state reference.
        /// @param user_id The unique identifier of the user whose profile is being retrieved.
        /// @return User The user profile associated with the given user ID.
        fn retrieve_user_profile(ref self: ContractState, user_id: u256) -> User {
            // Read the user profile from the storage mapping.
            let user = self.users.read(user_id);

            // Return the retrieved user profile.
            user
        }

        fn is_verified(ref self: ContractState, user_id: u256) -> bool {
            let mut user = self.users.read(user_id);
            user.verified
        }


        fn getAdmin(self: @ContractState) -> ContractAddress {
            let admin = self.admin.read();
            admin
        }
    }
}
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

    // We need to expose this for the interface
    #[derive(Drop, Serde, Clone, Copy, PartialEq)]
    struct User {
        name: felt252,
        email: felt252,
        is_active: bool,
        role: Role,
        rank: Rank,
        metadata: felt252,
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

    // Helper function to convert UserProfile to User
    fn profile_to_user(profile: UserProfile) -> User {
        User {
            name: profile.name,
            email: profile.email,
            is_active: profile.is_active,
            role: profile.role,
            rank: profile.rank,
            metadata: profile.metadata,
            verified: profile.verified,
        }
    }

    #[abi(embed_v0)]
    impl UserRegistryImpl of IUserRegistry<ContractState> {
        #[external]
        fn create_user(self: @ContractState, user: ContractAddress, name: felt252, email: felt252) {
            let mut state = self.get_contract_state();
            assert(!state.users.contains(user), "User already exists");

            let user_id = state.next_user_id.read();
            let new_profile = UserProfile {
                name,
                email,
                is_active: true,
                role: Role::READER, // Default role
                rank: Rank::LEVEL1, // Default rank
                metadata: 0, // Default metadata
                created_at: get_block_timestamp(),
                updated_at: get_block_timestamp(),
                verified: false,
            };

            state.users.write(user, new_profile);
            state.user_ids.write(user_id, user);
            state.active_users.write(user, true);
            state.next_user_id.write(user_id + 1);

            state
                .emit(
                    Event::UserCreated(
                        UserCreated { user_id, address: user, timestamp: get_block_timestamp() },
                    ),
                );
        }
        #[external]
        fn update_user(self: @ContractState, user: ContractAddress, name: felt252, email: felt252) {
            let mut state = self.get_contract_state();
            let caller = get_caller_address();
            let admin = state.admin.read();

            assert(caller == user || caller == admin, "Unauthorized");
            assert(state.users.contains(user), "User not found");
            assert(state.active_users.read(user), "User inactive");

            let mut profile = state.users.read(user);
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

            if changes_made {
                profile.updated_at = get_block_timestamp();
                state.users.write(user, profile);

                // Find user_id for the event
                let mut user_id = 0;
                let next_id = state.next_user_id.read();
                let mut i = 1;
                while i < next_id {
                    if state.user_ids.read(i) == user {
                        user_id = i;
                        break;
                    }
                    i += 1;
                }

                state
                    .emit(
                        Event::UserUpdated(
                            UserUpdated {
                                user_id, fields: fields_updated, timestamp: get_block_timestamp(),
                            },
                        ),
                    );
            }
        }

        #[external]
        fn get_user(self: @ContractState, user: ContractAddress) -> (felt252, felt252, bool) {
            assert(self.users.contains(user), "User not found");
            let profile = self.users.read(user);
            (profile.name, profile.email, profile.is_active)
        }

        #[external]
        fn deactivate_user(self: @ContractState, user: ContractAddress) {
            let mut state = self.get_contract_state();
            let caller = get_caller_address();
            let admin = state.admin.read();

            assert(caller == user, caller == admin, "Unauthorized");
            assert(state.users.contains(user), "User not found");
            assert(state.active_users.read(user), "Already inactive");

            state.active_users.write(user, false);
            let mut profile = state.users.read(user);
            profile.is_active = false;
            state.users.write(user, profile);

            // Find user_id for the event
            let mut user_id = 0;
            let next_id = state.next_user_id.read();
            let mut i = 1;
            while i < next_id {
                if state.user_ids.read(i) == user {
                    user_id = i;
                    break;
                }
                i += 1;
            }

            state
                .emit(
                    Event::UserDeactivated(
                        UserDeactivated { user_id, timestamp: get_block_timestamp() },
                    ),
                );
        }

        // New functions for enhanced profile management
        #[external]
        fn create_user_profile(
            ref self: ContractState, username: felt252, role: Role, rank: Rank, metadata: felt252,
        ) -> u256 {
            let caller = get_caller_address();
            assert(!self.users.contains(caller), "User already exists");
            let user_id = self.next_user_id.read();
            let new_profile = UserProfile {
                name: username,
                email: 0, // Empty email
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
        fn retrieve_user_profile(self: @ContractState, user_id: u256) -> User {
            let user_address = self.user_ids.read(user_id);
            assert(self.users.contains(user_address), "User not found");
            let profile = self.users.read(user_address);
            profile_to_user(profile)
        }

        #[external]
        fn retrieve_user_profile_by_address(
            self: @ContractState, address: ContractAddress,
        ) -> User {
            assert(self.users.contains(address), "User not found");
            let profile = self.users.read(address);
            profile_to_user(profile)
        }

        #[external]
        fn update_user_profile(
            ref self: ContractState,
            user_id: u256,
            username: felt252,
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

            if username != 0 && username != profile.name {
                profile.name = username;
                fields_updated = if fields_updated == 0 {
                    'name'
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
        fn reactivate_user_profile(ref self: ContractState, user_id: u256) -> bool {
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
        fn is_profile_active(self: @ContractState, user_id: u256) -> bool {
            let user_address = self.user_ids.read(user_id);
            self.active_users.read(user_address)
        }

        #[external]
        fn is_verified(self: @ContractState, user_id: u256) -> bool {
            let user_address = self.user_ids.read(user_id);
            let profile = self.users.read(user_address);
            profile.verified
        }

        #[external]
        fn get_admin(self: @ContractState) -> ContractAddress {
            self.admin.read()
        }
    }
}
