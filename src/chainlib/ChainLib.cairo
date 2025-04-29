#[starknet::contract]
pub mod ChainLib {
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_block_timestamp, get_caller_address};
    use crate::interfaces::IChainLib::IChainLib;
    use crate::base::types::{TokenBoundAccount, User, Role, Rank, Permissions, permission_flags};

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
        content_tags: Map::<ContentMetadata, Array<felt252>>,
        // Permission system storage
        operator_permissions: Map::<
            (u256, ContractAddress), Permissions
        >, // Maps account_id and operator to permissions
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
        // Permission-related events
        PermissionGranted: PermissionGranted,
        PermissionRevoked: PermissionRevoked,
        PermissionModified: PermissionModified,
    }

    #[derive(Drop, starknet::Event)]
    pub struct TokenBoundAccountCreated {
        pub id: u256,
    }

    #[derive(Drop, starknet::Event)]
    pub struct UserCreated {
        pub id: u256,
    }

    // Permission-related events
    #[derive(Drop, starknet::Event)]
    pub struct PermissionGranted {
        pub account_id: u256,
        pub operator: ContractAddress,
        pub permissions: Permissions,
    }

    #[derive(Drop, starknet::Event)]
    pub struct PermissionRevoked {
        pub account_id: u256,
        pub operator: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct PermissionModified {
        pub account_id: u256,
        pub permissions: Permissions,
    }

    #[abi(embed_v0)]
    impl ChainLibNetImpl of IChainLib<ContractState> {
        fn create_token_account(
            ref self: ContractState, user_name: felt252, init_param1: felt252, init_param2: felt252
        ) -> u256 {
            // Ensure that the username is not empty.
            assert!(user_name != 0, "User name cannot be empty");

            // Validate initialization parameters.
            assert!(init_param1 != 0, "Initialization parameter 1 cannot be empty");

            // Retrieve the current account ID before incrementing.
            let account_id = self.current_account_id.read();
            let caller = get_caller_address();

            // Create default full permissions for the owner
            let owner_permissions = Permissions { value: permission_flags::FULL };

            // Create a new token-bound account with the provided parameters.
            let new_token_bound_account = TokenBoundAccount {
                id: account_id,
                address: caller, // Assign the caller's address.
                user_name: user_name,
                init_param1: init_param1,
                init_param2: init_param2,
                created_at: get_block_timestamp(), // Capture the creation timestamp.
                updated_at: get_block_timestamp(), // Set initial updated timestamp.
                owner_permissions: owner_permissions, // Set owner permissions
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


        fn verify_user(ref self: ContractState, user_id: u256) -> bool {
            let caller = get_caller_address();
            // Ensure that only an admin can verify users.
            assert((self.admin.read() == caller), 'Only admin can verify users');
            let mut user = self.users.read(user_id);
            user.verified = true;
            self.users.write(user.id, user);
            true
        }
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

        // Permission system implementation

        fn get_permissions(
            self: @ContractState, account_id: u256, operator: ContractAddress
        ) -> Permissions {
            let account = self.accounts.read(account_id);

            // If the operator is the owner, return the owner's permissions
            if operator == account.address {
                return account.owner_permissions;
            }

            // Otherwise, return the operator's permissions
            self.operator_permissions.read((account_id, operator))
        }

        fn set_operator_permissions(
            ref self: ContractState,
            account_id: u256,
            operator: ContractAddress,
            permissions: Permissions
        ) -> bool {
            let caller = get_caller_address();
            let account = self.accounts.read(account_id);

            // Ensure that the caller is the account owner or has MANAGE_OPERATORS permission
            let caller_permissions = self.get_permissions(account_id, caller);
            assert(
                account.address == caller
                    || (caller_permissions.value & permission_flags::MANAGE_OPERATORS) != 0,
                'No permission'
            );

            // Store the operator's permissions
            self.operator_permissions.write((account_id, operator), permissions);

            // Emit the permission granted event
            self.emit(PermissionGranted { account_id, operator, permissions });

            true
        }

        fn revoke_operator(
            ref self: ContractState, account_id: u256, operator: ContractAddress
        ) -> bool {
            let caller = get_caller_address();
            let account = self.accounts.read(account_id);

            // Ensure that the caller is the account owner or has MANAGE_OPERATORS permission
            let caller_permissions = self.get_permissions(account_id, caller);
            assert(
                account.address == caller
                    || (caller_permissions.value & permission_flags::MANAGE_OPERATORS) != 0,
                'No permission'
            );

            // Set permissions to NONE
            let none_permissions = Permissions { value: permission_flags::NONE };
            self.operator_permissions.write((account_id, operator), none_permissions);

            // Emit the permission revoked event
            self.emit(PermissionRevoked { account_id, operator });

            true
        }

        fn has_permission(
            self: @ContractState, account_id: u256, operator: ContractAddress, permission: u64
        ) -> bool {
            let permissions = self.get_permissions(account_id, operator);
            (permissions.value & permission) != 0
        }

        fn modify_account_permissions(
            ref self: ContractState, account_id: u256, permissions: Permissions
        ) -> bool {
            let caller = get_caller_address();
            let mut account = self.accounts.read(account_id);

            // Ensure that the caller is the account owner
            assert(account.address == caller, 'Not owner');

            // Update the owner's permissions
            account.owner_permissions = permissions;
            self.accounts.write(account_id, account);

            // Emit the permission modified event
            self.emit(PermissionModified { account_id, permissions });

            true
        }
    }
}
