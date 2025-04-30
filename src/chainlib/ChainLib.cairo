#[starknet::contract]
pub mod ChainLib {
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{
        ContractAddress, get_block_timestamp, get_caller_address, contract_address_const
    };
    use crate::interfaces::IChainLib::IChainLib;
    use crate::base::types::{TokenBoundAccount, User, Role, Rank, Permissions, permission_flags, Purchase, PurchaseStatus};
    use core::array::ArrayTrait;
    use core::traits::Into;

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
        next_content_id: felt252,
        user_by_address: Map<ContractAddress, User>,
        // Permission system storage
        operator_permissions: Map::<
            (u256, ContractAddress), Permissions
        >, // Maps account_id and operator to permissions
        // Purchase related storage
        content_prices: Map::<felt252, u256>, // Maps content_id to price
        next_purchase_id: u256, // Tracking the next available purchase ID
        purchases: Map::<u256, Purchase>, // Store purchases by ID
        user_purchase_count: Map::<ContractAddress, u32>, // Count of purchases per user
        user_purchase_ids: Map::<
            (ContractAddress, u32), u256
        >, // Map of (user, index) to purchase ID
        content_purchase_count: Map::<felt252, u32>, // Count of purchases per content
        content_purchase_ids: Map::<
            (felt252, u32), u256
        >, // Map of (content_id, index) to purchase ID
    }


    #[constructor]
    fn constructor(ref self: ContractState, admin: ContractAddress) {
        // Store the values in contract state
        self.admin.write(admin);
        // Initialize purchase ID counter
        self.next_purchase_id.write(1_u256);
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        TokenBoundAccountCreated: TokenBoundAccountCreated,
        UserCreated: UserCreated,
        ContentRegistered: ContentRegistered,
        // Permission-related events
        PermissionGranted: PermissionGranted,
        PermissionRevoked: PermissionRevoked,
        PermissionModified: PermissionModified,

        ContentPurchased: ContentPurchased,
        PurchaseStatusUpdated: PurchaseStatusUpdated,
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


    #[derive(Drop, starknet::Event)]
    pub struct ContentRegistered {
        pub content_id: felt252,
        pub creator: ContractAddress
    }

    #[derive(Drop, starknet::Event)]
    pub struct ContentPurchased {
        pub purchase_id: u256,
        pub content_id: felt252,
        pub buyer: ContractAddress,
        pub price: u256,
        pub timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct PurchaseStatusUpdated {
        pub purchase_id: u256,
        pub new_status: u8, // Using u8 for status code instead of PurchaseStatus enum
        pub timestamp: u64,
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

            let user_for_address = self.users.read(user_id);
            self.user_by_address.write(user_for_address.wallet_address, user_for_address);

            // Increment the user ID counter for the next registration.
            self.user_id.write(user_id + 1);

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


        /// @notice Registers new content in the system.
        /// @dev Only users with WRITER role can register content.
        /// @param self The contract state reference.
        /// @param title The title of the content (cannot be empty).
        /// @param description The description of the content.
        /// @param content_type The type of content being registered.
        /// @param category The category the content belongs to.
        /// @return felt252 Returns the unique identifier of the registered content.
        fn register_content(
            ref self: ContractState,
            title: felt252,
            description: felt252,
            content_type: ContentType,
            category: Category
        ) -> felt252 {
            assert!(title != 0, "Title cannot be empty");
            assert!(description != 0, "Description cannot be empty");

            let creator = get_caller_address();
            let user = self.user_by_address.read(creator);

            assert!(user.role == Role::WRITER, "Only WRITER can post content");

            let content_id = self.next_content_id.read();

            let content_metadata = ContentMetadata {
                content_id: content_id,
                title: title,
                description: description,
                content_type: content_type,
                creator: creator,
                category: category
            };

            self.content.write(content_id, content_metadata);
            self.creators_content.write(creator, content_metadata);
            self.next_content_id.write(content_id + 1);

            self.emit(ContentRegistered { content_id: content_id, creator: creator });

            content_id
        }


        fn get_content(ref self: ContractState, content_id: felt252) -> ContentMetadata {
            let content_metadata = self.content.read(content_id);

            assert!(content_metadata.content_id == content_id, "Content does not exist");
            content_metadata
        }

        /// @notice Sets the price for a content item (admin only)
        /// @dev This function allows the admin to set or update the price of a content item.
        /// @param self The contract state reference.
        /// @param content_id The unique identifier of the content.
        /// @param price The price to set for the content.
        fn set_content_price(ref self: ContractState, content_id: felt252, price: u256) {
            // Only admin can set content prices
            let caller = get_caller_address();
            assert(self.admin.read() == caller, 'Admin only');

            // Set the price for the content
            self.content_prices.write(content_id, price);
        }

        /// @notice Initiates a purchase for a specific content.
        /// @dev Creates a purchase record with a pending status and emits an event.
        /// @param self The contract state reference.
        /// @param content_id The unique identifier of the content being purchased.
        /// @param transaction_hash The hash of the transaction being used for payment.
        /// @return The unique ID of the newly created purchase.
        fn purchase_content(
            ref self: ContractState, content_id: felt252, transaction_hash: felt252
        ) -> u256 {
            // Validate input parameters
            assert!(content_id != 0, "Content ID cannot be empty");
            assert!(transaction_hash != 0, "Transaction hash cannot be empty");

            // Get the price for the content
            let price = self.content_prices.read(content_id);
            assert!(price > 0, "Content either doesn't exist");

            // Get the buyer's address
            let buyer = get_caller_address();

            // Get the next purchase ID and increment for future use
            let purchase_id = self.next_purchase_id.read();
            self.next_purchase_id.write(purchase_id + 1);

            // Create the purchase record
            let purchase = Purchase {
                id: purchase_id,
                content_id: content_id,
                buyer: buyer,
                price: price,
                status: PurchaseStatus::Pending,
                timestamp: get_block_timestamp(),
                transaction_hash: transaction_hash,
            };

            // Store the purchase in the purchases mapping
            self.purchases.write(purchase_id, purchase);

            // Add the purchase ID to the user's purchase list
            let user_purchase_count = self.user_purchase_count.read(buyer);
            self.user_purchase_ids.write((buyer, user_purchase_count), purchase_id);
            self.user_purchase_count.write(buyer, user_purchase_count + 1);

            // Add the purchase ID to the content's purchase list
            let content_purchase_count = self.content_purchase_count.read(content_id);
            self.content_purchase_ids.write((content_id, content_purchase_count), purchase_id);
            self.content_purchase_count.write(content_id, content_purchase_count + 1);

            // Emit event for the purchase
            let timestamp = get_block_timestamp();
            self.emit(ContentPurchased { purchase_id, content_id, buyer, price, timestamp, });

            // Return the purchase ID
            purchase_id
        }

        /// @notice Retrieves details of a specific purchase.
        /// @dev Fetches purchase information by its ID.
        /// @param self The contract state reference.
        /// @param purchase_id The unique identifier of the purchase.
        /// @return Purchase The purchase details.
        fn get_purchase_details(ref self: ContractState, purchase_id: u256) -> Purchase {
            // Fetch and return the purchase details from storage
            let purchase = self.purchases.read(purchase_id);
            purchase
        }

        /// @notice Retrieves all purchases made by a specific user.
        /// @dev Returns an array of purchase records for the user.
        /// @param self The contract state reference.
        /// @param user_address The address of the user whose purchases are being retrieved.
        /// @return Array<Purchase> An array of purchase records for the user.
        fn get_user_purchases(
            ref self: ContractState, user_address: ContractAddress
        ) -> Array<Purchase> {
            // Initialize an empty array to hold the purchases
            let mut purchases: Array<Purchase> = ArrayTrait::new();

            // Get the number of purchases for this user
            let purchase_count = self.user_purchase_count.read(user_address);

            // Iterate through the purchase IDs and fetch each purchase
            let mut i: u32 = 0;

            while i < purchase_count {
                // Get the purchase ID at the current index
                let purchase_id = self.user_purchase_ids.read((user_address, i));

                // Fetch the purchase details using the ID
                let purchase = self.purchases.read(purchase_id);

                // Add the purchase to the array
                purchases.append(purchase);

                // Move to the next index
                i += 1;
            };

            // Return the array of purchases
            purchases
        }

        /// @notice Verifies if a purchase is valid and completed.
        /// @dev Checks the status of a purchase to confirm it has been completed successfully.
        /// @param self The contract state reference.
        /// @param purchase_id The unique identifier of the purchase to verify.
        /// @return bool True if the purchase is valid and completed, false otherwise.
        fn verify_purchase(ref self: ContractState, purchase_id: u256) -> bool {
            // Get the purchase details
            let purchase = self.purchases.read(purchase_id);

            // A purchase is valid if its status is Completed
            if purchase.status == PurchaseStatus::Completed {
                return true;
            } else {
                return false;
            }
        }

        /// @notice Updates the status of a purchase.
        /// @dev Only admin can update the status to prevent unauthorized changes.
        /// @param self The contract state reference.
        /// @param purchase_id The unique identifier of the purchase.
        /// @param status The new status to set for the purchase.
        /// @return bool True if the status was updated successfully.
        fn update_purchase_status(
            ref self: ContractState, purchase_id: u256, status: PurchaseStatus
        ) -> bool {
            // Only admin can update purchase status
            let caller = get_caller_address();
            assert(self.admin.read() == caller, 'Only admin can update status');

            // Get the current purchase
            let mut purchase = self.purchases.read(purchase_id);

            // Validate that we're not trying to update a purchase that doesn't exist
            assert(purchase.id == purchase_id, 'Purchase does not exist');

            // Update the status
            purchase.status = status;

            // Save the updated purchase
            self.purchases.write(purchase_id, purchase);

            // Emit event for the status update
            let timestamp = get_block_timestamp();

            // Convert PurchaseStatus to u8
            let status_code: u8 = match status {
                PurchaseStatus::Pending => 0_u8,
                PurchaseStatus::Completed => 1_u8,
                PurchaseStatus::Failed => 2_u8,
                PurchaseStatus::Refunded => 3_u8,
            };

            self.emit(PurchaseStatusUpdated { purchase_id, new_status: status_code, timestamp, });

            true
        }
    }
}
