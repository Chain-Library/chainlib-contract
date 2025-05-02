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

    use crate::base::types::{TokenBoundAccount, User, Role, Rank, Permissions, permission_flags};

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

    #[derive(Copy, Drop, Serde, starknet::Store, Debug)]
    pub struct Subscription {
        pub id: u256,
        pub subscriber: ContractAddress,
        pub plan_id: u256,
        pub amount: u256,
        pub start_date: u64,
        pub end_date: u64,
        pub is_active: bool,
        pub last_payment_date: u64
    }

    #[derive(Copy, Drop, Serde, starknet::Store, Debug)]
    pub struct Payment {
        pub id: u256,
        pub subscription_id: u256,
        pub amount: u256,
        pub timestamp: u64,
        pub is_verified: bool,
        pub is_refunded: bool
    }

    #[derive(Copy, Drop, Serde, starknet::Store, Debug)]
    pub struct ContentUpdate {
        pub content_id: felt252,
        pub updater: ContractAddress,
        pub timestamp: u64,
        pub old_title: felt252,
        pub old_description: felt252,
        pub old_content_type: ContentType,
        pub old_category: Category
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
        // Subscription related storage
        subscription_id: u256,
        subscriptions: Map::<u256, Subscription>,
        // Instead of storing arrays directly, we'll use a counter-based approach
        user_subscription_count: Map::<ContractAddress, u256>,
        user_subscription_by_index: Map::<(ContractAddress, u256), u256>,
        payment_id: u256,
        payments: Map::<u256, Payment>,
        // Similar counter-based approach for subscription payments
        subscription_payment_count: Map::<u256, u256>,
        subscription_payment_by_index: Map::<(u256, u256), u256>,
        next_content_id: felt252,
        user_by_address: Map<ContractAddress, User>,
        // Permission system storage
        operator_permissions: Map::<
            (u256, ContractAddress), Permissions
        >, // Maps account_id and operator to permissions
        // NEW - Delegation system storage
        delegations: Map::<
            (ContractAddress, u64), DelegationInfo
        >, // Maps (delegator, permission) to delegation info
        delegation_nonces: Map::<ContractAddress, u64>, // Track delegations for each address
        delegation_history: Map::<
            (ContractAddress, ContractAddress), u64
        >, // Track history between delegator and delegate
        content_updates: Map<felt252, Array<ContentUpdate>>,
        content_update_count: Map<felt252, u64>,
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
        PaymentProcessed: PaymentProcessed,
        RecurringPaymentProcessed: RecurringPaymentProcessed,
        PaymentVerified: PaymentVerified,
        RefundProcessed: RefundProcessed,
        ContentRegistered: ContentRegistered,
        // Permission-related events
        PermissionGranted: PermissionGranted,
        PermissionRevoked: PermissionRevoked,
        PermissionModified: PermissionModified,
        // NEW - Delegation-related events
        DelegationCreated: DelegationCreated,
        DelegationRevoked: DelegationRevoked,
        DelegationUsed: DelegationUsed,
        DelegationExpired: DelegationExpired,
        ContentUpdated: ContentUpdated,
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
        pub subscriber: ContractAddress,
        pub amount: u256,
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
        pub creator: ContractAddress
    }

    #[derive(Drop, starknet::Event)]
    pub struct ContentUpdated {
        pub content_id: felt252,
        pub updater: ContractAddress,
        pub timestamp: u64,
        pub old_title: felt252,
        pub new_title: felt252,
        pub old_description: felt252,
        pub new_description: felt252,
        pub old_content_type: ContentType,
        pub new_content_type: ContentType,
        pub old_category: Category,
        pub new_category: Category
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
                owner_permissions: owner_permissions, // Set owner permissions
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

        /// @notice Processes the initial payment for a new subscription
        /// @param amount The amount to be charged for the initial payment
        /// @param subscriber The address of the subscriber
        /// @return bool Returns true if the payment is processed successfully
        fn process_initial_payment(
            ref self: ContractState, amount: u256, subscriber: ContractAddress
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

            let new_subscription = Subscription {
                id: subscription_id,
                subscriber: subscriber,
                plan_id: 1, // Default plan ID
                amount: amount,
                start_date: current_time,
                end_date: current_time + subscription_period,
                is_active: true,
                last_payment_date: current_time
            };

            // Store the subscription
            self.subscriptions.write(subscription_id, new_subscription);

            // Create and store the payment record
            let payment_id = self.payment_id.read();
            let new_payment = Payment {
                id: payment_id,
                subscription_id: subscription_id,
                amount: amount,
                timestamp: current_time,
                is_verified: true, // Initial payment is auto-verified
                is_refunded: false
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
                        timestamp: current_time
                    }
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
            assert(subscription.is_active, 'Subscription not active');

            // Check if it's time for a recurring payment
            let current_time = get_block_timestamp();

            // Only process if subscription is due for renewal
            // In a real implementation, you would check if current_time >= subscription.end_date
            // For simplicity, we'll allow any recurring payment after the initial payment
            assert(current_time > subscription.last_payment_date, 'Payment not due yet');

            // Default subscription period is 30 days (in seconds)
            let subscription_period: u64 = 30 * 24 * 60 * 60;

            // Update subscription details
            subscription.last_payment_date = current_time;
            subscription.end_date = current_time + subscription_period;

            // Store updated subscription
            self.subscriptions.write(subscription_id, subscription);

            // Create and store the payment record
            let payment_id = self.payment_id.read();
            let new_payment = Payment {
                id: payment_id,
                subscription_id: subscription_id,
                amount: subscription.amount,
                timestamp: current_time,
                is_verified: true, // Auto-verify for simplicity
                is_refunded: false
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
                        subscriber: subscription.subscriber,
                        amount: subscription.amount,
                        timestamp: current_time
                    }
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
                        timestamp: get_block_timestamp()
                    }
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
            assert(subscription.is_active, 'Subscription not active');

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
            subscription.is_active = false;
            self.subscriptions.write(subscription_id, subscription);

            // Emit refund processed event
            self
                .emit(
                    RefundProcessed {
                        payment_id: payment_id,
                        subscription_id: subscription_id,
                        amount: payment.amount,
                        timestamp: get_block_timestamp()
                    }
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
            max_actions: u64
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
                        }
                    )
                );

            true
        }

        // Revokes an active delegation
        fn revoke_delegation(
            ref self: ContractState, delegate: ContractAddress, permissions: u64
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
            self.emit(Event::DelegationRevoked(DelegationRevoked { delegator, delegate, }));

            true
        }

        // Checks if a delegate has specific permissions from a delegator
        fn is_delegated(
            self: @ContractState,
            delegator: ContractAddress,
            delegate: ContractAddress,
            permission: u64
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
            ref self: ContractState, delegator: ContractAddress, permission: u64
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
                        }
                    )
                );

            // Check if the delegation has reached its action limit
            if delegation_info.max_actions != 0
                && delegation_info.action_count >= delegation_info.max_actions {
                // Deactivate the delegation
                delegation_info.active = false;
                self.delegations.write((delegator, permission), delegation_info);

                // Emit delegation expired event
                self.emit(DelegationExpired { delegator, delegate: caller, });
            }

            true
        }


        // Get delegation information
        fn get_delegation_info(
            self: @ContractState, delegator: ContractAddress, permission: u64
        ) -> DelegationInfo {
            self.delegations.read((delegator, permission))
        }

        fn update_content(
            ref self: ContractState,
            content_id: felt252,
            new_title: Option<felt252>,
            new_description: Option<felt252>,
            new_content_type: Option<ContentType>,
            new_category: Option<Category>
        ) -> bool {
            let caller = get_caller_address();
            let content = self.content.read(content_id);
            
            // Verify ownership or permissions
            let has_permission = self.has_permission(
                content.creator.into(),
                caller,
                permission_flags::CONTENT_UPDATE
            );
            assert(has_permission, 'Unauthorized: caller does not have update permission');

            // Store old values for history
            let old_title = content.title;
            let old_description = content.description;
            let old_content_type = content.content_type;
            let old_category = content.category;

            // Update only the fields that are provided
            if new_title.is_some() {
                content.title = new_title.unwrap();
            }
            if new_description.is_some() {
                content.description = new_description.unwrap();
            }
            if new_content_type.is_some() {
                content.content_type = new_content_type.unwrap();
            }
            if new_category.is_some() {
                content.category = new_category.unwrap();
            }

            // Store the update in history
            let update = ContentUpdate {
                content_id,
                updater: caller,
                timestamp: get_block_timestamp(),
                old_title,
                old_description,
                old_content_type,
                old_category
            };

            let mut updates = self.content_updates.read(content_id);
            updates.append(update);
            self.content_updates.write(content_id, updates);

            // Increment update count
            let count = self.content_update_count.read(content_id);
            self.content_update_count.write(content_id, count + 1);

            // Emit event
            self.emit(Event::ContentUpdated(ContentUpdated {
                content_id,
                updater: caller,
                timestamp: get_block_timestamp(),
                old_title,
                new_title: content.title,
                old_description,
                new_description: content.description,
                old_content_type,
                new_content_type: content.content_type,
                old_category,
                new_category: content.category
            }));

            true
        }

        fn get_content_update_history(
            self: @ContractState,
            content_id: felt252
        ) -> Array<ContentUpdate> {
            self.content_updates.read(content_id)
        }

        fn get_content_update_count(
            self: @ContractState,
            content_id: felt252
        ) -> u64 {
            self.content_update_count.read(content_id)
        }
    }
}
