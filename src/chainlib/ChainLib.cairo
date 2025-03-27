#[starknet::contract]
pub mod ChainLib {
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_block_timestamp, get_caller_address};
    use crate::interfaces::IChainLib::IChainLib;
    use crate::base::types::{TokenBoundAccount, User, Role, Rank};


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
            ref self: ContractState, user_name: felt252, init_param1: felt252, init_param2: felt252
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
            ref self: ContractState, address: ContractAddress
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
            ref self: ContractState, username: felt252, role: Role, rank: Rank, metadata: felt252
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
                metadata: metadata
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
