#[starknet::contract]
pub mod ChainLib {
    use core::array::{Array, ArrayTrait};
    use core::option::OptionTrait;
    use core::traits::Into;
    use starknet::storage::{
        Map, MutableVecTrait, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess, Vec, VecTrait,
    };
    use starknet::{
        ContractAddress, contract_address_const, get_block_timestamp, get_caller_address,
    };
    use crate::base::types::{
        AccessRule, AccessType, Permissions, Purchase, PurchaseStatus, Rank, Role, Status,
        TokenBoundAccount, User, VerificationRequirement, VerificationType, permission_flags,
        Subscription, SubscriptionStatus,
    };
    use crate::interfaces::IChainLib::IChainLib;

    // Define delegation-specific structures and constants

    // New delegation flags - extending the existing permission_flags
    pub mod delegation_flags {
        // Using higher bits to avoid collision with existing permission flags
        const DELEGATE_TRANSFER: u64 = 0x10000;
        const DELEGATE_CONTENT: u64 = 0x20000;
        const DELEGATE_ADMIN: u64 = 0x40000;
        const DELEGATE_USER: u64 = 0x80000;
        // Combined flag for full delegation capabilities
        const FULL_DELEGATION: u64 = 0xF0000;
    }

    #[derive(Copy, Drop, Serde, starknet::Store, Debug)]
    pub struct DelegationInfo {
        pub delegator: ContractAddress, // The account owner who created the delegation
        pub delegate: ContractAddress, // The account that receives delegated permissions
        pub permissions: u64, // Delegated permissions as bit flags
        pub expiration: u64, // Timestamp when delegation expires (0 = no expiration)
        pub max_actions: u64, // Maximum number of actions allowed (0 = unlimited)
        pub action_count: u64, // Current number of actions performed
        pub active: bool // Whether this delegation is active
    }

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
        Art,
    }

    #[derive(Copy, Drop, Serde, starknet::Store, Debug)]
    pub struct ContentMetadata {
        pub content_id: felt252,
        pub title: felt252,
        pub description: felt252,
        pub content_type: ContentType,
        pub creator: ContractAddress,
        pub category: Category,
    }

    // #[derive(Copy, Drop, Serde, starknet::Store, Debug)]
    // pub struct Subscription {
    //     pub id: u256,
    //     pub subscriber: ContractAddress,
    //     pub plan_id: u256,
    //     pub amount: u256,
    //     pub start_date: u64,
    //     pub end_date: u64,
    //     pub is_active: bool,
    //     pub last_payment_date: u64,
    // }

    #[derive(Copy, Drop, Serde, starknet::Store, Debug)]
    pub struct AccessCache {
        pub user_id: u256,
        pub content_id: felt252,
        pub has_access: bool,
        pub timestamp: u64,
        pub expiry: u64,
    }
    #[derive(Copy, Drop, Serde, starknet::Store, Debug)]
    pub struct ContentAccess {
        pub content_id: felt252,
        pub access_type: AccessType,
        pub requires_subscription: bool,
        pub is_premium: bool,
    }

    #[derive(Copy, Drop, Serde, starknet::Store, Debug)]
    pub struct Payment {
        pub id: u256,
        pub subscription_id: u256,
        pub amount: u256,
        pub timestamp: u64,
        pub is_verified: bool,
        pub is_refunded: bool,
    }

    #[storage]
    struct Storage {
        admin: ContractAddress, // Address of the contract admin
        current_account_id: u256, // Counter for token-bound account IDs
        accounts: Map<u256, TokenBoundAccount>, // Maps account ID to TokenBoundAccount
        accountsaddr: Map<ContractAddress, TokenBoundAccount>, // Maps address to TokenBoundAccount
        next_course_id: u256, // Counter for course IDs (unused?)
        user_id: u256, // Counter for user IDs
        users: Map<u256, User>, // Maps user ID to User
        creators_content: Map<
            ContractAddress, ContentMetadata,
        >, // Maps creator address to their content
        content: Map<felt252, ContentMetadata>, // Maps content ID to ContentMetadata
        content_tags: Map<ContentMetadata, Array<felt252>>, // Maps content to associated tags
        subscription_id: u256, // Counter for subscription IDs
        user_subscription_count: Map<ContractAddress, u256>, // Count of subscriptions per user
        user_subscription_by_index: Map<
            (ContractAddress, u256), u256,
        >, // Maps (user, index) to subscription ID
        payment_id: u256, // Counter for payment IDs
        payments: Map<u256, Payment>, // Maps payment ID to Payment
        subscription_payment_count: Map<u256, u256>, // Count of payments per subscription
        subscription_payment_by_index: Map<
            (u256, u256), u256,
        >, // Maps (subscription_id, index) to payment ID
        next_content_id: felt252, // Counter for content IDs
        user_by_address: Map<ContractAddress, User>, // Maps user address to User
        operator_permissions: Map<
            (u256, ContractAddress), Permissions,
        >, // Maps (account_id, operator) to Permissions
        content_access: Map<felt252, ContentAccess>, // Maps content ID to access configuration
        premium_content_access: Map<
            (u256, felt252), bool,
        >, // Maps (user_id, content_id) to premium access status
        access_cache: Map<
            (u256, felt252), AccessCache,
        >, // Maps (user_id, content_id) to cached access status
        access_blacklist: Map<
            (u256, felt252), bool,
        >, // Maps (user_id, content_id) to blacklist status
        cache_ttl: u64, // Cache time-to-live in seconds
        delegations: Map<
            (ContractAddress, u64), DelegationInfo,
        >, // Maps (delegator, permission) to DelegationInfo
        delegation_nonces: Map<ContractAddress, u64>, // Nonce for tracking delegations
        delegation_history: Map<
            (ContractAddress, ContractAddress), u64,
        >, // Tracks delegation history
        content_access_rules_count: Map<felt252, u32>, // Count of access rules per content
        content_access_rules: Map<
            (felt252, u32), AccessRule,
        >, // Maps (content_id, index) to AccessRule
        user_content_permissions: Map<
            (ContractAddress, felt252), Permissions,
        >, // Maps (user, content_id) to Permissions
        content_verification_requirements_count: Map<
            felt252, u32,
        >, // Count of verification requirements per content
        content_verification_requirements: Map<
            (felt252, u32), VerificationRequirement,
        >, // Maps (content_id, index) to VerificationRequirement
        user_verifications: Map<
            (ContractAddress, VerificationType), bool,
        >, // Maps (user, verification_type) to verification status
        user_identity_verifications: Map<
            ContractAddress, bool,
        >, // Identity verification status for users
        user_payment_verifications: Map<
            ContractAddress, bool,
        >, // Payment verification status for users
        user_reputation_verifications: Map<
            ContractAddress, bool,
        >, // Reputation verification status for users
        user_ownership_verifications: Map<
            ContractAddress, bool,
        >, // Ownership verification status for users
        user_custom_verifications: Map<
            ContractAddress, bool,
        >, // Custom verification status for users
        content_prices: Map<felt252, u256>, // Maps content_id to price
        next_purchase_id: u256, // Counter for purchase IDs
        purchases: Map<u256, Purchase>, // Maps purchase ID to Purchase
        purchase_timeout_duration: u64,
        subscriptions: Map<u256, Subscription>, // Maps subscription ID to Subscription
        subscription_counter: Map<ContractAddress, u256>, // Tracks subscription IDs per user
        subscription_count: u64 // Tracks total number of subscriptions
    }


    #[constructor]
    fn constructor(ref self: ContractState, admin: ContractAddress) {
        // Store the values in contract state
        self.admin.write(admin);
        // Initialize purchase ID counter
        self.next_purchase_id.write(1_u256);
        self.purchase_timeout_duration.write(3600);
        // Initialize subscription count
        self.subscription_count.write(0);
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        TokenBoundAccountCreated: TokenBoundAccountCreated,
        UserCreated: UserCreated,
        UserUpdated: UserUpdated,
        PaymentProcessed: PaymentProcessed,
        RecurringPaymentProcessed: RecurringPaymentProcessed,
        PaymentVerified: PaymentVerified,
        RefundProcessed: RefundProcessed,
        ContentRegistered: ContentRegistered,
        // Permission-related events
        PermissionGranted: PermissionGranted,
        PermissionRevoked: PermissionRevoked,
        PermissionModified: PermissionModified,
        UserVerificationStatusChanged: UserVerificationStatusChanged,
        ContentPermissionsGranted: ContentPermissionsGranted,
        AccessVerified: AccessVerified,
        // NEW - Delegation-related events
        DelegationCreated: DelegationCreated,
        DelegationRevoked: DelegationRevoked,
        DelegationUsed: DelegationUsed,
        DelegationExpired: DelegationExpired,
        ContentPurchased: ContentPurchased,
        PurchaseStatusUpdated: PurchaseStatusUpdated,
        SubscriptionCreated: SubscriptionCreated,
        SubscriptionRenewed: SubscriptionRenewed,
        SubscriptionCancelled: SubscriptionCancelled,
    }


    #[derive(Drop, starknet::Event)]
    struct SubscriptionCreated {
        user: ContractAddress,
        subscription_id: u256,
        duration: u64,
        start_time: u64,
        end_time: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct SubscriptionRenewed {
        user: ContractAddress,
        subscription_id: u256,
        new_end_time: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct SubscriptionCancelled {
        user: ContractAddress,
        subscription_id: u256,
    }

    #[derive(Drop, starknet::Event)]
    pub struct TokenBoundAccountCreated {
        pub id: u256,
    }

    #[derive(Drop, starknet::Event)]
    pub struct UserUpdated {
        pub user_id: u256,
    }

    // #[derive(Drop, starknet::Event)]
    // pub struct SubscriptionCreated {
    //     pub user_id: u256,
    //     pub end_date: u64,
    //     pub amount: u256,
    // }

    #[derive(Drop, starknet::Event)]
    pub struct AccessVerified {
        pub user_id: u256,
        pub content_id: felt252,
        pub has_access: bool,
    }

    #[derive(Drop, starknet::Event)]
    pub struct UserCreated {
        pub id: u256,
    }

    #[derive(Drop, starknet::Event)]
    pub struct PaymentProcessed {
        pub payment_id: u256,
        pub subscription_id: u256,
        pub subscriber: ContractAddress,
        pub amount: u256,
        pub timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct RecurringPaymentProcessed {
        pub payment_id: u256,
        pub subscription_id: u256,
        // pub subscriber: ContractAddress,
        // pub amount: u256,
        pub timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct PaymentVerified {
        pub payment_id: u256,
        pub subscription_id: u256,
        pub timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct RefundProcessed {
        pub payment_id: u256,
        pub subscription_id: u256,
        pub amount: u256,
        pub timestamp: u64,
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

    // NEW - Delegation-related events
    #[derive(Drop, starknet::Event)]
    pub struct DelegationCreated {
        pub delegator: ContractAddress,
        pub delegate: ContractAddress,
        pub permissions: u64,
        pub expiration: u64,
        pub max_actions: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct DelegationRevoked {
        pub delegator: ContractAddress,
        pub delegate: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct DelegationUsed {
        pub delegator: ContractAddress,
        pub delegate: ContractAddress,
        pub permission: u64,
        pub remaining_actions: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct DelegationExpired {
        pub delegator: ContractAddress,
        pub delegate: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ContentRegistered {
        pub content_id: felt252,
        pub creator: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct UserVerificationStatusChanged {
        #[key]
        pub user: ContractAddress,
        pub verification_type: VerificationType,
        pub is_verified: bool,
        pub timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ContentPermissionsGranted {
        #[key]
        pub content_id: felt252,
        #[key]
        pub user: ContractAddress,
        pub permissions: Permissions,
        pub timestamp: u64,
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
            ref self: ContractState, user_name: felt252, init_param1: felt252, init_param2: felt252,
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

            // Get the caller's address
            let caller_address = get_caller_address();

            // Create a new token-bound account with the provided parameters.
            let new_token_bound_account = TokenBoundAccount {
                id: account_id,
                address: caller_address, // Assign the caller's address.
                user_name: user_name,
                init_param1: init_param1,
                init_param2: init_param2,
                created_at: get_block_timestamp(), // Capture the creation timestamp.
                updated_at: get_block_timestamp(), // Set initial updated timestamp.
                owner_permissions: owner_permissions // Set owner permissions
            };

            // Store the new account in the accounts mapping
            self.accounts.write(account_id, new_token_bound_account);

            // Store the new account in the accountsaddr mapping
            // Make sure to use the caller's address as the key
            self.accountsaddr.write(caller_address, new_token_bound_account);

            // For debugging, verify that the account was stored correctly
            let stored_account = self.accountsaddr.read(caller_address);
            assert(stored_account.id == account_id, 'Account storage failed');

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
                status: Status::ACTIVE,
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

        fn update_user_profile(
            ref self: ContractState,
            id: u256,
            username: felt252,
            wallet_address: ContractAddress,
            role: Role,
            rank: Rank,
            metadata: felt252,
        ) {
            assert!(username != 0, "User name cannot be empty");
            let zero: ContractAddress = contract_address_const::<0>();
            assert!(wallet_address != zero, "Address cannot be zero");

            let user = self.users.read(id);

            // Ensure that the caller is the user or has permission to update.
            let caller = get_caller_address();
            assert(caller == user.wallet_address, 'Only user can update');

            // Update the user profile with new details.
            let updated_user = User {
                id: user.id,
                username: username,
                wallet_address: wallet_address,
                role: role,
                rank: rank,
                verified: user.verified, // Keep the existing verification status.
                metadata: metadata,
                status: Status::ACTIVE,
            };
            // Store the updated user profile in the users mapping.
            self.users.write(id, updated_user);

            self.emit(UserUpdated { user_id: id });
        }

        fn deactivate_profile(ref self: ContractState, user_id: u256) -> bool {
            let mut user = self.users.read(user_id);
            // Ensure that the caller is the user or has permission to update.
            let caller = get_caller_address();
            assert(caller == user.wallet_address, 'Only user can update');

            // Update the user profile with new details.
            user.status = Status::DEACTIVATED;

            // Store the updated user profile in the users mapping.
            self.users.write(user_id, user);

            true
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
            self: @ContractState, account_id: u256, operator: ContractAddress,
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
            permissions: Permissions,
        ) -> bool {
            let caller = get_caller_address();
            let account = self.accounts.read(account_id);

            // Ensure that the caller is the account owner or has MANAGE_OPERATORS permission
            let caller_permissions = self.get_permissions(account_id, caller);
            assert(
                account.address == caller
                    || (caller_permissions.value & permission_flags::MANAGE_OPERATORS) != 0,
                'No permission',
            );

            // Store the operator's permissions
            self.operator_permissions.write((account_id, operator), permissions);

            // Emit the permission granted event
            self.emit(PermissionGranted { account_id, operator, permissions });

            true
        }

        fn revoke_operator(
            ref self: ContractState, account_id: u256, operator: ContractAddress,
        ) -> bool {
            let caller = get_caller_address();
            let account = self.accounts.read(account_id);

            // Ensure that the caller is the account owner or has MANAGE_OPERATORS permission
            let caller_permissions = self.get_permissions(account_id, caller);
            assert(
                account.address == caller
                    || (caller_permissions.value & permission_flags::MANAGE_OPERATORS) != 0,
                'No permission',
            );

            // Set permissions to NONE
            let none_permissions = Permissions { value: permission_flags::NONE };
            self.operator_permissions.write((account_id, operator), none_permissions);

            // Emit the permission revoked event
            self.emit(PermissionRevoked { account_id, operator });

            true
        }

        fn has_permission(
            self: @ContractState, account_id: u256, operator: ContractAddress, permission: u64,
        ) -> bool {
            let permissions = self.get_permissions(account_id, operator);
            (permissions.value & permission) != 0
        }

        fn modify_account_permissions(
            ref self: ContractState, account_id: u256, permissions: Permissions,
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
            category: Category,
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
                category: category,
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

        /// @notice Processes the initial payment for a new subscription
        /// @param amount The amount to be charged for the initial payment
        /// @param subscriber The address of the subscriber
        /// @return bool Returns true if the payment is processed successfully
        fn process_initial_payment(
            ref self: ContractState, amount: u256, subscriber: ContractAddress,
        ) -> bool {
            // Get the caller's address - this is who is initiating the subscription
            let caller = get_caller_address();

            // Only allow the subscriber themselves to create a subscription
            assert(caller == subscriber, 'Only subscriber can call');

            // Create a new subscription
            let subscription_id = self.subscription_id.read();
            let current_time = get_block_timestamp();

            // Default subscription period is 30 days (in seconds)
            let subscription_period: u64 = 30 * 24 * 60 * 60;

            // let new_subscription = Subscription {
            //     id: subscription_id,
            //     subscriber: subscriber,
            //     plan_id: 1, // Default plan ID
            //     amount: amount,
            //     start_date: current_time,
            //     end_date: current_time + subscription_period,
            //     is_active: true,
            //     last_payment_date: current_time,
            // };

            // // Store the subscription
            // self.subscriptions.write(subscription_id, new_subscription);

            // Create and store the payment record
            let payment_id = self.payment_id.read();
            let new_payment = Payment {
                id: payment_id,
                subscription_id: subscription_id,
                amount: amount,
                timestamp: current_time,
                is_verified: true, // Initial payment is auto-verified
                is_refunded: false,
            };

            self.payments.write(payment_id, new_payment);

            // Update user's subscriptions using a counter-based approach
            // First, get the current count of subscriptions for this user
            let current_count = self.user_subscription_count.read(subscriber);

            // Store the subscription ID at the next index
            self.user_subscription_by_index.write((subscriber, current_count), subscription_id);

            // Increment the count
            self.user_subscription_count.write(subscriber, current_count + 1);

            // Update subscription's payments using a similar approach
            let current_payment_count = self.subscription_payment_count.read(subscription_id);

            // Store the payment ID at the next index
            self
                .subscription_payment_by_index
                .write((subscription_id, current_payment_count), payment_id);

            // Increment the count
            self.subscription_payment_count.write(subscription_id, current_payment_count + 1);

            // Increment IDs for next use
            self.subscription_id.write(subscription_id + 1);
            self.payment_id.write(payment_id + 1);

            // Emit payment processed event
            self
                .emit(
                    PaymentProcessed {
                        payment_id: payment_id,
                        subscription_id: subscription_id,
                        subscriber: subscriber,
                        amount: amount,
                        timestamp: current_time,
                    },
                );

            true
        }

        /// @notice Handles recurring payments for existing subscriptions
        /// @param subscription_id The unique identifier of the subscription
        /// @return bool Returns true if the recurring payment is processed successfully
        fn process_recurring_payment(ref self: ContractState, subscription_id: u256) -> bool {
            // Get the subscription
            let mut subscription = self.subscriptions.read(subscription_id);

            // Verify subscription exists and is active
            assert(subscription.id == subscription_id, 'Subscription not found');
            // assert(subscription.is_active, 'Subscription not active');

            // Check if it's time for a recurring payment
            let current_time = get_block_timestamp();

            // Only process if subscription is due for renewal
            // In a real implementation, you would check if current_time >= subscription.end_date
            // For simplicity, we'll allow any recurring payment after the initial payment
            // assert(current_time > subscription.last_payment_date, 'Payment not due yet');

            // Default subscription period is 30 days (in seconds)
            let subscription_period: u64 = 30 * 24 * 60 * 60;

            // Update subscription details
            // subscription.last_payment_date = current_time;
            // subscription.end_date = current_time + subscription_period;

            // Store updated subscription
            self.subscriptions.write(subscription_id, subscription);

            // Create and store the payment record
            let payment_id = self.payment_id.read();
            let new_payment = Payment {
                id: payment_id,
                subscription_id: subscription_id,
                amount:33,
                timestamp: current_time,
                is_verified: true, // Auto-verify for simplicity
                is_refunded: false,
            };

            self.payments.write(payment_id, new_payment);

            // Update subscription's payments using a similar approach
            let current_payment_count = self.subscription_payment_count.read(subscription_id);

            // Store the payment ID at the next index
            self
                .subscription_payment_by_index
                .write((subscription_id, current_payment_count), payment_id);

            // Increment the count
            self.subscription_payment_count.write(subscription_id, current_payment_count + 1);

            // Increment payment ID for next use
            self.payment_id.write(payment_id + 1);

            // Emit recurring payment processed event
            self
                .emit(
                    RecurringPaymentProcessed {
                        payment_id: payment_id,
                        subscription_id: subscription_id,
                        // subscriber: subscription.subscriber,
                        // amount: subscription.amount,
                        timestamp: current_time,
                    },
                );

            true
        }

        /// @notice Verifies if a payment has been processed correctly
        /// @param payment_id The unique identifier of the payment to verify
        /// @return bool Returns true if the payment is verified successfully
        fn verify_payment(ref self: ContractState, payment_id: u256) -> bool {
            // Only admin should be able to verify payments
            let caller = get_caller_address();
            assert(self.admin.read() == caller, 'Only admin can verify payments');

            // Get the payment
            let mut payment = self.payments.read(payment_id);

            // Verify payment exists and is not already verified
            assert(payment.id == payment_id, 'Payment not found');
            assert(!payment.is_verified, 'Payment already verified');

            // Mark payment as verified
            payment.is_verified = true;
            self.payments.write(payment_id, payment);

            // Get subscription for the event
            // let subscription = self.subscriptions.read(payment.subscription_id);

            // Emit payment verified event
            self
                .emit(
                    PaymentVerified {
                        payment_id: payment_id,
                        subscription_id: payment.subscription_id,
                        timestamp: get_block_timestamp(),
                    },
                );

            true
        }

        /// @notice Processes refunds for cancelled or disputed subscriptions
        /// @param subscription_id The unique identifier of the subscription to refund
        /// @return bool Returns true if the refund is processed successfully
        fn process_refund(ref self: ContractState, subscription_id: u256) -> bool {
            // Only admin should be able to process refunds
            let caller = get_caller_address();
            assert(self.admin.read() == caller, 'Only admin can process refunds');

            // Get the subscription
            let mut subscription = self.subscriptions.read(subscription_id);

            // Verify subscription exists and is active
            assert(subscription.id == subscription_id, 'Subscription not found');
            // assert(subscription.is_active, 'Subscription not active');

            // Get the most recent payment for this subscription
            // In a real implementation, you would find the most recent payment
            // For simplicity, we'll use a placeholder approach
            let sub_payments = self.subscription_payment_count.read(subscription_id);
            assert(sub_payments > 0, 'No payments to refund');

            // Get the last payment (simplified approach)
            let payment_id = self
                .subscription_payment_by_index
                .read((subscription_id, sub_payments - 1));
            let mut payment = self.payments.read(payment_id);

            // Verify payment exists and is not already refunded
            assert(!payment.is_refunded, 'Payment already refunded');

            // Mark payment as refunded
            payment.is_refunded = true;
            self.payments.write(payment_id, payment);

            // Deactivate the subscription
            // subscription.is_active = false;
            self.subscriptions.write(subscription_id, subscription);

            // Emit refund processed event
            self
                .emit(
                    RefundProcessed {
                        payment_id: payment_id,
                        subscription_id: subscription_id,
                        amount: payment.amount,
                        timestamp: get_block_timestamp(),
                    },
                );

            true
        }


        fn set_verification_requirements(
            ref self: ContractState,
            content_id: felt252,
            requirements: Array<VerificationRequirement>,
        ) -> bool {
            let caller = get_caller_address();
            let content = self.content.read(content_id);

            assert(content.creator == caller || self.admin.read() == caller, 'Not authorized');

            // Clear existing requirements
            let current_count = self.content_verification_requirements_count.read(content_id);
            let mut i: u32 = 0;
            while i < current_count {
                let default_req = VerificationRequirement {
                    requirement_type: VerificationType::Identity,
                    valid_until: 0_u64,
                    threshold: 0_u64,
                };
                self.content_verification_requirements.write((content_id, i), default_req);
                i += 1;
            };

            // Store new requirements
            let new_count = requirements.len();
            i = 0;
            while i < new_count {
                let req = requirements.at(i);
                self.content_verification_requirements.write((content_id, i), *req);
                i += 1;
            };

            self.content_verification_requirements_count.write(content_id, new_count);
            true
        }


        fn get_verification_requirements(
            self: @ContractState, content_id: felt252,
        ) -> Array<VerificationRequirement> {
            let count = self.content_verification_requirements_count.read(content_id);
            let mut requirements = ArrayTrait::new();
            let mut i: u32 = 0;

            while i < count {
                let req = self.content_verification_requirements.read((content_id, i));
                requirements.append(req);
                i += 1;
            };

            requirements
        }


        fn set_content_access_rules(
            ref self: ContractState, content_id: felt252, rules: Array<AccessRule>,
        ) -> bool {
            let caller = get_caller_address();
            let content = self.content.read(content_id);

            assert(content.creator == caller || self.admin.read() == caller, 'Not authorized');

            // Clear existing rules
            let current_count = self.content_access_rules_count.read(content_id);
            let mut i: u32 = 0;
            while i < current_count {
                // Create an empty/default AccessRule manually
                let empty_rule = AccessRule {
                    access_type: AccessType::Admin,
                    permission_level: 0,
                    conditions: Option::None,
                    expires_at: 0,
                };
                self.content_access_rules.write((content_id, i), empty_rule);
                i += 1;
            };

            // Store new rules
            let new_count = rules.len();
            i = 0;
            while i < new_count {
                let rule = *rules.at(i);
                self.content_access_rules.write((content_id, i), rule);
                i += 1;
            };

            self.content_access_rules_count.write(content_id, new_count);
            true
        }


        fn get_content_access_rules(
            self: @ContractState, content_id: felt252,
        ) -> Array<AccessRule> {
            let count = self.content_access_rules_count.read(content_id);
            let mut rules = ArrayTrait::new();
            let mut i: u32 = 0;

            while i < count {
                let rule = self.content_access_rules.read((content_id, i));
                rules.append(rule);
                i += 1;
            };

            rules
        }

        fn add_content_access_rule(
            ref self: ContractState, content_id: felt252, rule: AccessRule,
        ) -> bool {
            let caller = get_caller_address();
            let content = self.content.read(content_id);

            assert(content.creator == caller || self.admin.read() == caller, 'Not authorized');

            let count = self.content_access_rules_count.read(content_id);
            self.content_access_rules.write((content_id, count), rule);
            self.content_access_rules_count.write(content_id, count + 1);
            true
        }

        fn check_verification_requirements(
            self: @ContractState, user: ContractAddress, content_id: felt252,
        ) -> bool {
            let requirements = self.get_verification_requirements(content_id);
            let current_time = get_block_timestamp();
            let mut status = true;

            let mut i = 0;
            let len = requirements.len();
            while i < len {
                let req = *requirements.at(i);

                // Skip expired requirements
                if req.valid_until != 0 && req.valid_until < current_time {
                    i += 1;
                    continue;
                }

                // Check verification status based on type
                let is_verified = match req.requirement_type {
                    VerificationType::Identity => self.user_identity_verifications.read(user),
                    VerificationType::Payment => self.user_payment_verifications.read(user),
                    VerificationType::Reputation => self.user_reputation_verifications.read(user),
                    VerificationType::Ownership => self.user_ownership_verifications.read(user),
                    VerificationType::Custom => self.user_custom_verifications.read(user),
                };

                if !is_verified {
                    status = false;
                    break;
                }
                i += 1;
            };
            status
        }

        fn set_user_verification(
            ref self: ContractState,
            user: ContractAddress,
            verification_type: VerificationType,
            is_verified: bool,
        ) -> bool {
            let caller = get_caller_address();
            assert(self.admin.read() == caller, 'Only admin can verify users');

            // Update the appropriate verification map
            match verification_type {
                VerificationType::Identity => {
                    self.user_identity_verifications.write(user, is_verified);
                },
                VerificationType::Payment => {
                    self.user_payment_verifications.write(user, is_verified);
                },
                VerificationType::Reputation => {
                    self.user_reputation_verifications.write(user, is_verified);
                },
                VerificationType::Ownership => {
                    self.user_ownership_verifications.write(user, is_verified);
                },
                VerificationType::Custom => {
                    self.user_custom_verifications.write(user, is_verified);
                },
            }

            self
                .emit(
                    UserVerificationStatusChanged {
                        user, verification_type, is_verified, timestamp: get_block_timestamp(),
                    },
                );
            true
        }

        fn grant_content_permissions(
            ref self: ContractState,
            content_id: felt252,
            user: ContractAddress,
            permissions: Permissions,
        ) -> bool {
            let caller = get_caller_address();
            let content = self.content.read(content_id);

            // Verify caller has permission to grant permissions
            assert(
                content.creator == caller
                    || self.admin.read() == caller
                    || self
                        .has_content_permission(
                            content_id, caller, permission_flags::MANAGE_PERMISSIONS,
                        ),
                'Not authorized for permissions',
            );

            // Grant the permissions
            self.user_content_permissions.write((user, content_id), permissions);

            // Emit event
            self
                .emit(
                    ContentPermissionsGranted {
                        content_id, user, permissions, timestamp: get_block_timestamp(),
                    },
                );
            true
        }
        // NEW - Account Delegation Implementation

        // Creates a delegation for account permissions
        // delegate The address that will receive delegated permissions
        // permissions The permissions to be delegated (using delegation_flags)
        // expiration Timestamp when the delegation expires (0 for no expiration)
        // max_actions Maximum number of actions allowed (0 for unlimited)
        //  bool Returns true if delegation was created successfully
        fn create_delegation(
            ref self: ContractState,
            delegate: ContractAddress,
            permissions: u64,
            expiration: u64,
            max_actions: u64,
        ) -> bool {
            // Ensure the delegate address is valid
            let x: ContractAddress = 0.try_into().unwrap();
            assert(delegate != x, 'Invalid delegate address');

            // Get the delegator (caller)
            let delegator = get_caller_address();

            // Create delegation info
            let delegation_info = DelegationInfo {
                delegator,
                delegate,
                permissions,
                expiration,
                max_actions,
                action_count: 0,
                active: true,
            };

            // Store the delegation
            self.delegations.write((delegator, permissions), delegation_info);

            // Increment nonce for tracking
            let current_nonce = self.delegation_nonces.read(delegate);
            self.delegation_nonces.write(delegate, current_nonce + 1);

            // Track delegation history
            let history_count = self.delegation_history.read((delegator, delegate));
            self.delegation_history.write((delegator, delegate), history_count + 1);

            // Emit delegation created event
            self
                .emit(
                    Event::DelegationCreated(
                        DelegationCreated {
                            delegator, delegate, permissions, expiration, max_actions,
                        },
                    ),
                );

            true
        }

        fn has_content_permission(
            self: @ContractState, content_id: felt252, user: ContractAddress, permission: u64,
        ) -> bool {
            let content = self.content.read(content_id);

            // Creator or admin always allowed
            if user == content.creator || user == self.admin.read() {
                return true;
            }

            // Check user permissions
            let user_permissions = self.user_content_permissions.read((user, content_id));
            (user_permissions.value & permission) != 0
        }
        // Revokes an active delegation
        fn revoke_delegation(
            ref self: ContractState, delegate: ContractAddress, permissions: u64,
        ) -> bool {
            // Get the delegator (caller)
            let delegator = get_caller_address();

            // Get the delegation info
            let mut delegation_info = self.delegations.read((delegator, permissions));

            // Ensure the delegation exists and is active
            assert(delegation_info.active, 'Delegation not active');
            assert(delegation_info.delegate == delegate, 'Delegate mismatch');

            // Deactivate the delegation
            delegation_info.active = false;
            self.delegations.write((delegator, permissions), delegation_info);

            // Emit delegation revoked event
            self.emit(Event::DelegationRevoked(DelegationRevoked { delegator, delegate }));

            true
        }

        // Checks if a delegate has specific permissions from a delegator
        fn is_delegated(
            self: @ContractState,
            delegator: ContractAddress,
            delegate: ContractAddress,
            permission: u64,
        ) -> bool {
            let delegation_info = self.delegations.read((delegator, permission));

            // Verify delegation exists and is active
            if !delegation_info.active || delegation_info.delegate != delegate {
                return false;
            }

            // Check if the delegation has expired
            let current_time = get_block_timestamp();
            if delegation_info.expiration != 0 && delegation_info.expiration < current_time {
                return false;
            }

            // Check if action limit has been reached
            if delegation_info.max_actions != 0
                && delegation_info.action_count >= delegation_info.max_actions {
                return false;
            }

            // Check if the requested permission is included in the granted permissions
            return (delegation_info.permissions & permission) == permission;
        }

        // Uses a delegation to perform an action, updating usage count
        fn use_delegation(
            ref self: ContractState, delegator: ContractAddress, permission: u64,
        ) -> bool {
            let caller = get_caller_address();

            // Check if the caller has the required permission via delegation
            assert(self.is_delegated(delegator, caller, permission), 'Permission denied');

            // Get the delegation info
            let mut delegation_info = self.delegations.read((delegator, permission));

            // Increment action count
            delegation_info.action_count += 1;
            self.delegations.write((delegator, permission), delegation_info);

            // Calculate remaining actions
            let remaining_actions = if delegation_info.max_actions == 0 {
                0 // Unlimited actions
            } else {
                delegation_info.max_actions - delegation_info.action_count
            };

            // Emit delegation used event
            self
                .emit(
                    Event::DelegationUsed(
                        DelegationUsed {
                            delegator, delegate: caller, permission, remaining_actions,
                        },
                    ),
                );

            // Check if the delegation has reached its action limit
            if delegation_info.max_actions != 0
                && delegation_info.action_count >= delegation_info.max_actions {
                // Deactivate the delegation
                delegation_info.active = false;
                self.delegations.write((delegator, permission), delegation_info);

                // Emit delegation expired event
                self.emit(DelegationExpired { delegator, delegate: caller });
            }

            true
        }


        // Get delegation information
        fn get_delegation_info(
            self: @ContractState, delegator: ContractAddress, permission: u64,
        ) -> DelegationInfo {
            self.delegations.read((delegator, permission))
        }

        // Create a new subscription for a specified user with amount as duration
        fn create_subscription(
            ref self: ContractState, user: ContractAddress, amount: u256,
        ) -> u256 {
            let current_time = get_block_timestamp();

            // Validate user address
                  let zero: ContractAddress = contract_address_const::<0>();
            assert!(user != zero, "Address cannot be zero");

            // Validate amount (minimum 30 days in seconds, convert to u64)
            let min_duration: u64 = 30 * 24 * 60 * 60;
            let duration: u64 = amount.try_into().expect('AMOUNT_TOO_LARGE');
            assert(duration >= min_duration, 'DURATION_TOO_SHORT');

            // Increment subscription counter for user
            let user_sub_id = self.subscription_counter.read(user) + 1;
            self.subscription_counter.write(user, user_sub_id);

            // Increment global subscription count
            let global_sub_id = self.subscription_count.read() + 1;
            self.subscription_count.write(global_sub_id);

            // Use global subscription count as unique ID
            let subscription_id: u256 = global_sub_id.into();

            // Create subscription
            let subscription = Subscription {
                id: subscription_id,
                user: user,
                start_time: current_time,
                end_time: current_time + duration,
                duration: duration,
                status: SubscriptionStatus::Active,
            };

            // Store subscription
            self.subscriptions.write(subscription_id, subscription);

            // Emit event
            self
                .emit(
                    Event::SubscriptionCreated(
                        SubscriptionCreated {
                            user: user,
                            subscription_id: subscription_id,
                            duration: duration,
                            start_time: current_time,
                            end_time: current_time + duration,
                        },
                    ),
                );

            // Return subscription ID
            subscription_id
        }

        // Renew a subscription
        fn renew_subscription(ref self: ContractState, subscription_id: u256) -> bool {
            let caller = get_caller_address();
            let current_time = get_block_timestamp();

            // Read subscription
            let mut subscription = self.subscriptions.read(subscription_id);
            assert(subscription.id !=0, 'SUBSCRIPTION_NOT_FOUND');
            assert(subscription.user == caller, 'UNAUTHORIZED');
            assert(subscription.status == SubscriptionStatus::Active, 'SUBSCRIPTION_NOT_ACTIVE');

            // Update end time based on original duration
            subscription.end_time = current_time + subscription.duration;
            self.subscriptions.write(subscription_id, subscription);

            // Emit event
            self
                .emit(
                    Event::SubscriptionRenewed(
                        SubscriptionRenewed {
                            user: caller,
                            subscription_id: subscription_id,
                            new_end_time: subscription.end_time,
                        },
                    ),
                );
            true
        }

        // Cancel a subscription
        fn cancel_subscription(ref self: ContractState, subscription_id: u256) -> bool {
            let caller = get_caller_address();

            // Read subscription
            let mut subscription = self.subscriptions.read(subscription_id);
            assert(subscription.id != 0, 'SUBSCRIPTION_NOT_FOUND');
            assert(subscription.user == caller, 'UNAUTHORIZED');
            assert(subscription.status == SubscriptionStatus::Active, 'SUBSCRIPTION_NOT_ACTIVE');

            // Update status
            subscription.status = SubscriptionStatus::Cancelled;
            self.subscriptions.write(subscription_id, subscription);

            // Emit event
            self
                .emit(
                    Event::SubscriptionCancelled(
                        SubscriptionCancelled { user: caller, subscription_id: subscription_id },
                    ),
                );
            true
        }

        // Get subscription status
        // fn get_subscription_status(self: @ContractState, subscription_id: u256) ->
        // SubscriptionStatus {
        //     let subscription = self.subscriptions.read(subscription_id);
        //     if subscription.id == 0 {
        //         return SubscriptionStatus::Inactive;
        //     }

        //     // Check if subscription has expired
        //     let current_time = get_block_timestamp();
        //     if subscription.status == SubscriptionStatus::Active && current_time >
        //     subscription.end_time {
        //         return SubscriptionStatus::Inactive;
        //     }

        //     subscription.status
        // }

        // Get subscription details
        fn get_subscription(ref self: ContractState, subscription_id: u256) -> Subscription {
            let subscription = self.subscriptions.read(subscription_id);
            assert(subscription.id != 0, 'SUBSCRIPTION_NOT_FOUND');
            subscription
        }

        // Get total subscription count
        fn get_subscription_count(ref self: ContractState) -> u64 {
            self.subscription_count.read()
        }
        fn get_user_subscription(ref self: ContractState, user_id: u256) -> Subscription {
            self.subscriptions.read(user_id)
        }

        fn grant_premium_access(
            ref self: ContractState, user_id: u256, content_id: felt252,
        ) -> bool {
            let caller = get_caller_address();
            let content = self.content.read(content_id);

            // Verify the caller is either the content creator or admin
            assert(
                content.creator == caller || self.admin.read() == caller,
                'Not authorized to grant access',
            );

            // Verify the user exists
            let user = self.users.read(user_id);
            assert(user.id == user_id, 'User does not exist');

            // Grant premium access
            self.premium_content_access.write((user_id, content_id), true);

            // Invalidate any existing cache entry
            let cache_key = (user_id, content_id);
            let cache_exists = self.access_cache.read(cache_key).timestamp != 0;
            if cache_exists {
                let mut cache_entry = self.access_cache.read(cache_key);
                cache_entry.has_access = true;
                cache_entry.timestamp = get_block_timestamp();
                cache_entry.expiry = get_block_timestamp() + self.cache_ttl.read();
                self.access_cache.write(cache_key, cache_entry);
            }

            // Remove from blacklist if present
            if self.access_blacklist.read((user_id, content_id)) {
                self.access_blacklist.write((user_id, content_id), false);
            }

            true
        }
        fn is_in_blacklist(self: @ContractState, user_id: u256, content_id: felt252) -> bool {
            self.access_blacklist.read((user_id, content_id))
        }
        fn get_premium_access_status(
            self: @ContractState, user_id: u256, content_id: felt252,
        ) -> bool {
            self.premium_content_access.read((user_id, content_id))
        }

        fn revoke_access(ref self: ContractState, user_id: u256, content_id: felt252) -> bool {
            let caller = get_caller_address();
            let content = self.content.read(content_id);

            // Verify the caller is either the content creator or admin
            assert(
                content.creator == caller || self.admin.read() == caller,
                'Not authorized to revoke access',
            );

            // Add to blacklist
            self.access_blacklist.write((user_id, content_id), true);

            // Remove premium access if it exists
            if self.premium_content_access.read((user_id, content_id)) {
                self.premium_content_access.write((user_id, content_id), false);
            }

            // Invalidate any existing cache entry
            let cache_key = (user_id, content_id);
            let cache_exists = self.access_cache.read(cache_key).timestamp != 0;
            if cache_exists {
                let mut cache_entry = self.access_cache.read(cache_key);
                cache_entry.has_access = false;
                cache_entry.timestamp = get_block_timestamp();
                cache_entry.expiry = get_block_timestamp() + self.cache_ttl.read();
                self.access_cache.write(cache_key, cache_entry);
            }

            true
        }

        fn has_active_subscription(self: @ContractState, user_id: u256) -> bool {
            let subscription = self.subscriptions.read(user_id);

            if subscription.status == SubscriptionStatus::Inactive {
                return false;
            }

            let current_time = get_block_timestamp();
            return true;
        }

        fn set_cache_ttl(ref self: ContractState, ttl_seconds: u64) -> bool {
            let caller = get_caller_address();

            // Only admin can set cache TTL
            assert(self.admin.read() == caller, 'Only admin can set cache TTL');

            self.cache_ttl.write(ttl_seconds);
            true
        }

        fn verify_access(ref self: ContractState, user_id: u256, content_id: felt252) -> bool {
            let current_time = get_block_timestamp();
            let cache_key = (user_id, content_id);

            // Check if the user is blacklisted for this content
            if self.access_blacklist.read(cache_key) {
                self._update_access_cache(cache_key, false, current_time);
                return false;
            }

            // Check cache first
            let cached_access = self.access_cache.read(cache_key);

            // Cache miss or expired, perform full verification
            let user = self.users.read(user_id);
            assert(user.id == user_id, 'User does not exist');

            let content = self.content.read(content_id);
            assert(content.content_id == content_id, 'Content does not exist');

            // Determine access with early returns for special cases
            let has_access = self._determine_access(user_id, content_id, user);

            // Update cache with result
            self._update_access_cache(cache_key, has_access, current_time);

            has_access
        }

        // Helper function to determine access
        fn _determine_access(
            ref self: ContractState, user_id: u256, content_id: felt252, user: User,
        ) -> bool {
            let content = self.get_content(content_id);
            // Admin check - admins have access to everything
            if user.wallet_address == self.admin.read() {
                return true;
            }

            // Creator check - creators have access to their own content
            if content.creator == user.wallet_address {
                return true;
            }

            // Access type check - standard content is accessible to all
            let access_config = self.content_access.read(content_id);
            if access_config.access_type == AccessType::View {
                return true;
            }

            // Check subscription if required
            if access_config.requires_subscription && !self.has_active_subscription(user_id) {
                return false;
            }

            // Check premium access if required
            if access_config.is_premium
                && !self.premium_content_access.read((user_id, content_id)) {
                return false;
            }

            // If we've passed all checks, user has access
            return true;
        }

        // Helper function to update cache and emit event
        fn _update_access_cache(
            ref self: ContractState,
            cache_key: (u256, felt252),
            has_access: bool,
            current_time: u64,
        ) {
            let (user_id, content_id) = cache_key;

            // Update cache
            let cache_entry = AccessCache {
                user_id: user_id,
                content_id: content_id,
                has_access: has_access,
                timestamp: current_time,
                expiry: current_time + self.cache_ttl.read(),
            };
            self.access_cache.write(cache_key, cache_entry);

            // Emit event
            self
                .emit(
                    AccessVerified {
                        user_id: user_id, content_id: content_id, has_access: has_access,
                    },
                );
        }

        fn initialize_access_control(ref self: ContractState, default_cache_ttl: u64) -> bool {
            let caller = get_caller_address();

            // Only admin can initialize access control
            assert(self.admin.read() == caller, 'Only admin can initialize');

            self.cache_ttl.write(default_cache_ttl);

            true
        }

        fn clear_access_cache(ref self: ContractState, user_id: u256, content_id: felt252) -> bool {
            let caller = get_caller_address();

            // Only admin can clear cache entries
            assert(self.admin.read() == caller, 'Only admin can clear cache');

            // Create an empty cache entry with zero timestamp (effectively clearing it)
            let empty_cache = AccessCache {
                user_id: 0, content_id: 0, has_access: false, timestamp: 0, expiry: 0,
            };

            self.access_cache.write((user_id, content_id), empty_cache);

            true
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
            ref self: ContractState, content_id: felt252, transaction_hash: felt252,
        ) -> u256 {
            assert!(content_id != 0, "Content ID cannot be empty");
            assert!(transaction_hash != 0, "Transaction hash cannot be empty");

            let price = self.content_prices.read(content_id);
            assert!(price > 0, "Content either doesn't exist or has no price");

            let buyer = get_caller_address();
            let current_time = get_block_timestamp();

            let purchase_id = self.next_purchase_id.read();
            self.next_purchase_id.write(purchase_id + 1);

            let purchase = Purchase {
                id: purchase_id,
                content_id: content_id,
                buyer: buyer,
                price: price,
                status: PurchaseStatus::Pending,
                timestamp: current_time,
                transaction_hash: transaction_hash,
                timeout_expiry: current_time + self.purchase_timeout_duration.read(),
            };

            self.purchases.write(purchase_id, purchase);

            let timestamp = get_block_timestamp();
            self.emit(ContentPurchased { purchase_id, content_id, buyer, price, timestamp });

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
            ref self: ContractState, user_address: ContractAddress,
        ) -> Array<Purchase> {
            // Initialize an empty array to hold the purchases
            let mut purchases: Array<Purchase> = ArrayTrait::new();

            // Iterate through all purchase IDs up to next_purchase_id
            let total_purchases = self.next_purchase_id.read();
            let mut i: u256 = 1; // Start from 1 as purchase IDs begin at 1

            while i < total_purchases {
                let purchase = self.purchases.read(i);
                if purchase.buyer == user_address {
                    purchases.append(purchase);
                }
                i += 1;
            };

            // Return the array of purchases
            purchases
        }

        /// @notice Retrieves all purchases for a specific content item.
        /// @dev Iterates through the purchases mapping to find purchases for the given content_id.
        /// @param self The contract state reference.
        /// @param content_id The unique identifier of the content.
        /// @return Array<Purchase> An array of purchase records for the content.
        fn get_content_purchases(ref self: ContractState, content_id: felt252) -> Array<Purchase> {
            // Initialize an empty array to hold the purchases
            let mut purchases: Array<Purchase> = ArrayTrait::new();

            // Iterate through all purchase IDs up to next_purchase_id
            let total_purchases = self.next_purchase_id.read();
            let mut i: u256 = 1; // Start from 1 as purchase IDs begin at 1

            while i < total_purchases {
                let purchase = self.purchases.read(i);
                if purchase.content_id == content_id {
                    purchases.append(purchase);
                }
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
            ref self: ContractState, purchase_id: u256, status: PurchaseStatus,
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

            self.emit(PurchaseStatusUpdated { purchase_id, new_status: status_code, timestamp });

            true
        }
    }
}
