#[starknet::contract]
pub mod ChainLib {
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_block_timestamp, get_caller_address};
    use crate::interfaces::IChainLib::IChainLib;
    use crate::base::types::{TokenBoundAccount, User, Role, Rank, Purchase, PurchaseStatus};
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
        
        // Purchase related storage
        content_prices: Map::<felt252, u256>, // Maps content_id to price
        next_purchase_id: u256, // Tracking the next available purchase ID
        purchases: Map::<u256, Purchase>, // Store purchases by ID
        user_purchase_count: Map::<ContractAddress, u32>, // Count of purchases per user
        user_purchase_ids: Map::<(ContractAddress, u32), u256>, // Map of (user, index) to purchase ID
        content_purchase_count: Map::<felt252, u32>, // Count of purchases per content
        content_purchase_ids: Map::<(felt252, u32), u256>, // Map of (content_id, index) to purchase ID
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

        /// @notice Processes a content purchase transaction.
        /// @dev Creates a purchase record, verifies payment, and emits an event.
        /// @param self The contract state reference.
        /// @param content_id The unique identifier of the content being purchased.
        /// @param transaction_hash The hash of the transaction for verification purposes.
        /// @return purchase_id The unique identifier assigned to the purchase.
        fn purchase_content(
            ref self: ContractState, content_id: felt252, transaction_hash: felt252
        ) -> u256 {
            // Validate input parameters
            assert!(content_id != 0, "Content ID cannot be empty");
            assert!(transaction_hash != 0, "Transaction hash cannot be empty");
            
            // Get the price for the content
            let price = self.content_prices.read(content_id);
            assert!(price > 0, "Content either doesn't exist or is not for sale");
            
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
                status: PurchaseStatus::Pending, // Initial status is pending until payment is verified
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
            self.emit(
                ContentPurchased {
                    purchase_id,
                    content_id,
                    buyer,
                    price,
                    timestamp,
                }
            );
            
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
            
            self.emit(
                PurchaseStatusUpdated {
                    purchase_id,
                    new_status: status_code,
                    timestamp,
                }
            );
            
            true
        }
    }
}
