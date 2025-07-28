#[starknet::contract]
pub mod ChainLib {
    use core::array::{Array, ArrayTrait};
    use core::num::traits::Zero;
    use core::option::OptionTrait;
    use core::traits::Into;
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
    use starknet::storage::{
        Map, MutableVecTrait, StorageMapReadAccess, StorageMapWriteAccess, StoragePathEntry,
        StoragePointerReadAccess, StoragePointerWriteAccess, Vec, VecTrait,
    };
    use starknet::{
        ContractAddress, contract_address_const, get_block_timestamp, get_caller_address,
        get_contract_address,
    };
    use crate::base::errors::{payment_errors, permission_errors};
    use crate::base::types::{
        AccessRule, AccessType, Payout, PayoutSchedule, PayoutStatus, Permissions, Purchase,
        PurchaseStatus, Rank, Receipt, ReceiptStatus, Refund, RefundRequestReason, RefundStatus,
        Role, Status, TokenBoundAccount, User, VerificationRequirement, VerificationType,
        permission_flags,
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

    const GRACE_PERIOD: u64 = 7 * 24 * 60 * 60;
    const PRORATION_PRECISION: u256 = 1_000_000_000_000_000_000;

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

    #[derive(Copy, Drop, Serde, starknet::Store, PartialEq, Debug)]
    pub enum SubscriptionStatus {
        Active,
        #[default]
        Inactive,
        Cancelled,
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

    #[derive(Drop, Serde, starknet::Store, Clone)]
    pub struct Subscription {
        pub id: u256,
        pub subscriber: ContractAddress,
        pub plan_id: u256,
        pub amount: u256,
        pub start_date: u64,
        pub end_date: u64,
        pub is_active: bool,
        pub last_payment_date: u64,
        pub subscription_type: PlanType,
        pub status: SubscriptionStatus,
        pub grace_period_end: u64,
    }

    #[derive(Drop, Serde, starknet::Store, Clone, PartialEq)]
    pub enum PlanType {
        #[default]
        MONTHLY,
        YEARLY,
        TRIAL,
    }

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

    #[derive(Copy, Drop, Serde, starknet::Store, Debug)]
    pub struct AccessToken {
        pub token_id: u256,
        pub user_id: u256,
        pub content_id: felt252,
        pub expiry: u64,
        pub is_active: bool,
    }

    #[derive(Copy, Drop, Serde, starknet::Store, Debug)]
    pub struct SubscriptionPlan {
        pub plan_id: u256,
        pub content_id: felt252,
        pub duration: u64,
        pub price: u256,
        pub is_active: bool,
    }

    #[derive(Copy, Drop, Serde, starknet::Store, Debug)]
    pub struct ContentLicense {
        pub content_id: felt252,
        pub license_type: u8 // 0: One-time, 1: Subscription, 2: Time-limited
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
        subscriptions: Map<u256, Subscription>, // Maps subscription ID to Subscription
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
        subscription_record: Map<u256, Vec<Subscription>>, // subcription id to subscription record
        subscription_count: Map<
            u256, u256,
        >, // subscriber count to number of times the subscription record has been updated
        //  RECEIPTS
        receipt_counter: u256,
        receipt: Map<u256, Receipt>,
        creator_sales: Map<ContractAddress, u256>,
        total_sales_for_content: Map<felt252, u256>,
        token_address: ContractAddress,
        access_tokens: Map<u256, AccessToken>,
        next_token_id: u256,
        user_content_tokens: Map<(u256, felt252), u256>,
        subscription_plans: Map<u256, SubscriptionPlan>,
        next_plan_id: u256,
        content_licenses: Map<felt252, ContentLicense>,

        platform_fee: u256, //basis points; 1000 = 10%
        platform_fee_recipient: ContractAddress,
        payout_schedule: PayoutSchedule,
        payout_history: Map<
            ContractAddress, Vec<Payout>,
        >, // map a creator's address to a Vec of his payouts
        user_refunds: Map<ContractAddress, Vec<Refund>>,
        refund_window: u64,
    }

    const REFUND_WINDOW: u64 = 86400;
    const PLATFORM_FEE: u256 = 900; //9%
    const PAYOUT_SCHEDULE_INTERVAL: u64 = 86400 * 7;

    #[constructor]
    fn constructor(
        ref self: ContractState,
        admin: ContractAddress,
        token_address: ContractAddress,
        platform_fee: u256,
        // platform_fee_recipient: ContractAddress,
        payout_schedule_interval: u64,
        refund_window: u64,
    ) {
        // Store the values in contract state
        self.admin.write(admin);
        self.token_address.write(token_address);
        // Initialize purchase ID counter
        self.next_purchase_id.write(1_u256);
        self.next_content_id.write(0_felt252);
        self.purchase_timeout_duration.write(3600);
        self.next_token_id.write(1_u256);
        self.next_plan_id.write(1_u256);
        self.platform_fee_recipient.write(get_contract_address());
        // self.platform_fee.write(PLATFORM_FEE);
        self.platform_fee.write(platform_fee);
        let payout_schedule = PayoutSchedule {
            // interval: PAYOUT_SCHEDULE_INTERVAL,
            interval: payout_schedule_interval,
            start_time: get_block_timestamp(),
            last_execution: 0,
        };
        self.payout_schedule.write(payout_schedule);
        // self.refund_window.write(REFUND_WINDOW);
        self.refund_window.write(refund_window);
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
        SubscriptionCreated: SubscriptionCreated,
        // NEW - Delegation-related events
        DelegationCreated: DelegationCreated,
        DelegationRevoked: DelegationRevoked,
        DelegationUsed: DelegationUsed,
        DelegationExpired: DelegationExpired,
        ContentPurchased: ContentPurchased,
        PurchaseStatusUpdated: PurchaseStatusUpdated,
        SubscriptionCancelled: SubscriptionCancelled,
        SubscriptionRenewed: SubscriptionRenewed,
        ReceiptGenerated: ReceiptGenerated,
        AccessTokenGenerated: AccessTokenGenerated,
        AccessTokenRevoked: AccessTokenRevoked,
        SubscriptionPlanCreated: SubscriptionPlanCreated,
        SubscriptionUpgraded: SubscriptionUpgraded,
        ContentLicenseSet: ContentLicenseSet,
    }

    #[derive(Drop, starknet::Event)]
    pub struct AccessTokenGenerated {
        pub token_id: u256,
        pub user_id: u256,
        pub content_id: felt252,
        pub expiry: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct AccessTokenRevoked {
        pub token_id: u256,
        pub user_id: u256,
        pub content_id: felt252,
    }

    #[derive(Drop, starknet::Event)]
    pub struct SubscriptionPlanCreated {
        pub plan_id: u256,
        pub content_id: felt252,
        pub duration: u64,
        pub price: u256,
    }

    #[derive(Drop, starknet::Event)]
    pub struct SubscriptionUpgraded {
        pub subscription_id: u256,
        pub user_id: u256,
        pub new_plan_id: u256,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ContentLicenseSet {
        pub content_id: felt252,
        pub license_type: u8,

        PayoutExecuted: PayoutExecuted,
        PayoutScheduleSet: PayoutScheduleSet,
        RefundRequested: RefundRequested,
        RefundApproved: RefundApproved,
        RefundDeclined: RefundDeclined,
        RefundPaid: RefundPaid,
        PlatformFeeChanged: PlatformFeeChanged,
        RefundWindowChanged: RefundWindowChanged,
        RefundTimedOut: RefundTimedOut,
    }

    #[derive(Drop, starknet::Event)]
    pub struct TokenBoundAccountCreated {
        pub id: u256,
    }

    #[derive(Drop, starknet::Event)]
    pub struct UserUpdated {
        pub user_id: u256,
    }

    #[derive(Drop, starknet::Event)]
    pub struct SubscriptionCreated {
        pub user_id: u256,
        pub end_date: u64,
        pub amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct SubscriptionRenewed {
        user: ContractAddress,
        subscription_id: u256,
        new_end_time: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct ReceiptGenerated {
        receipt_id: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct SubscriptionCancelled {
        user: ContractAddress,
        subscription_id: u256,
    }
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

    // Payout and Refunds
    #[derive(Drop, starknet::Event)]
    pub struct PayoutExecuted {
        pub recipients: Array<ContractAddress>,
        pub timestamp: u64,
        pub amount_paid: u256,
    }

    #[derive(Drop, starknet::Event)]
    pub struct PayoutScheduleSet {
        pub start_time: u64,
        pub setter: ContractAddress,
        pub interval: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct RefundRequested {
        pub user: ContractAddress,
        pub content_id: felt252,
        pub purchase_id: u256,
        pub reason: RefundRequestReason,
    }

    #[derive(Drop, starknet::Event)]
    pub struct RefundApproved {
        pub approver: ContractAddress,
        pub user_id: u256,
        pub content_id: felt252,
        pub refund_id: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct RefundDeclined {
        pub decliner: ContractAddress,
        pub user_id: u256,
        pub content_id: felt252,
        pub refund_id: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct RefundTimedOut {
        pub user_id: u256,
        pub content_id: felt252,
        pub refund_id: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct RefundPaid {
        pub refund_id: u64,
        pub content_id: felt252,
        pub purchase_id: u256,
        pub executor: ContractAddress,
        pub user_id: u256,
    }

    #[derive(Drop, starknet::Event)]
    pub struct PlatformFeeChanged {
        pub new_fee: u256,
        pub timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct RefundWindowChanged {
        pub new_window: u64,
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
            let user_address = user.wallet_address;
            self.users.write(user.id, user.clone());
            self.user_by_address.write(user_address, user.clone());
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

            self._process_payment(amount);

            // Create a new subscription
            let subscription_id = self.subscription_id.read();
            let subscription_plan: Subscription = self.subscriptions.read(subscription_id);

            let current_time = get_block_timestamp();

            // Default subscription period is 30 days (in seconds)
            let subscription_period: u64 = 30 * 24 * 60 * 60;
            let end_date = current_time + subscription_period;

            let new_subscription = Subscription {
                id: subscription_id,
                subscriber: subscriber,
                plan_id: 1, // Default plan ID
                amount: amount,
                start_date: current_time,
                end_date: current_time + subscription_period,
                is_active: true,
                last_payment_date: current_time,
                subscription_type: subscription_plan.subscription_type,
                status: subscription_plan.status,
                grace_period_end: end_date + GRACE_PERIOD,
            };

            // Store the subscription
            self.subscriptions.write(subscription_id, new_subscription.clone());

            self.subscription_record.entry(subscription_id).append().write(new_subscription);

            let current_count = self.subscription_count.read(subscription_id);
            self.subscription_count.write(subscription_id, current_count + 1);

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
            assert(subscription.id.clone() == subscription_id, 'Subscription not found');
            assert(subscription.is_active, 'Subscription not active');

            // Check if it's time for a recurring payment
            let current_time = get_block_timestamp();

            // Only process if subscription is due for renewal
            // In a real implementation, you would check if current_time >= subscription.end_date
            // For simplicity, we'll allow any recurring payment after the initial payment
            assert(current_time > subscription.last_payment_date, 'Payment not due yet');

            // Process the payment
            self._process_payment(subscription.amount);

            // Default subscription period is 30 days (in seconds)
            let subscription_period: u64 = 30 * 24 * 60 * 60;

            // Save required fields before mutating subscription
            let subscription_amount = subscription.amount;
            let subscription_subscriber = subscription.subscriber;

            // Update subscription details
            subscription.last_payment_date = current_time;
            subscription.end_date = current_time + subscription_period;

            // Create and store the payment record
            let payment_id = self.payment_id.read();
            let new_payment = Payment {
                id: payment_id,
                subscription_id: subscription_id,
                amount: subscription_amount,
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
                        subscriber: subscription_subscriber,
                        amount: subscription_amount,
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

            // process the refund
            self._process_refund(payment.amount, get_caller_address());

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
            }

            // Store new requirements
            let new_count = requirements.len();
            i = 0;
            while i < new_count {
                let req = requirements.at(i);
                self.content_verification_requirements.write((content_id, i), *req);
                i += 1;
            }

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
            }

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
            }

            // Store new rules
            let new_count = rules.len();
            i = 0;
            while i < new_count {
                let rule = *rules.at(i);
                self.content_access_rules.write((content_id, i), rule);
                i += 1;
            }

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
            }

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
            }
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


        fn create_subscription(
            ref self: ContractState, user_id: u256, amount: u256, plan_type: u32,
        ) -> bool {
            let caller = get_caller_address();

            // Verify the user exists
            let user = self.users.read(user_id);
            assert(user.id == user_id, 'User does not exist');

            // let current_time = get_block_timestamp();

            // Create a new subscription
            let subscription_id = self.subscription_id.read() + 1;
            let current_time = get_block_timestamp();

            // Default subscription period is 30 days (in seconds)
            let subscription_period: u64 = 30 * 24 * 60 * 60;
            let end_date = current_time + subscription_period;

            let planTypeResult: Result<PlanType, felt252> = match plan_type {
                0 => Ok(PlanType::MONTHLY),
                1 => Ok(PlanType::YEARLY),
                2 => Ok(PlanType::TRIAL),
                _ => Err('Invalid plan option'),
            };
            let subscription_type = match planTypeResult {
                Result::Ok(pt) => pt,
                Result::Err(_) => {
                    assert(false, 'Invalid plan option');
                    // This line will never be reached, but is required for type checking
                    PlanType::MONTHLY
                },
            };

            let new_subscription = Subscription {
                id: subscription_id,
                subscriber: caller,
                plan_id: 1, // Default plan ID
                amount: amount,
                start_date: current_time,
                end_date: end_date,
                is_active: true,
                last_payment_date: current_time,
                subscription_type: subscription_type,
                status: SubscriptionStatus::Active,
                grace_period_end: GRACE_PERIOD,
            };

            self.subscriptions.write(user_id, new_subscription.clone());

            // read from the subscription
            self.subscription_record.entry(user_id).push(new_subscription);

            let current_count = self.subscription_count.read(user_id);
            self.subscription_count.write(user_id, current_count + 1);

            // Emit event
            self.emit(SubscriptionCreated { user_id: user_id, end_date: end_date, amount: amount });

            true
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

        fn get_user_subscription_record(
            ref self: ContractState, user_id: u256,
        ) -> Array<Subscription> {
            let count = self.subscription_count.entry(user_id).read();
            let mut subscriptions = ArrayTrait::new();

            let mut i = 0;
            while i < count.try_into().unwrap() {
                let subscription = self.subscription_record.entry(user_id).at(i).read();
                subscriptions.append(subscription);
                i += 1;
            }

            subscriptions
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

            if !subscription.is_active {
                return false;
            }

            let current_time = get_block_timestamp();
            return current_time <= subscription.end_date;
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
            // assert!(content_id != 0, "Content ID cannot be empty");
            // I commented the above line out because in other parts of the project, it is
            // explicitly stated that first content id should be 0
            assert!(transaction_hash != 0, "Transaction hash cannot be empty");

            let price = self.content_prices.read(content_id);
            assert!(price > 0, "Content either doesn't exist or has no price");

            // process the purchase
            self._process_payment(price);

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
            }

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
            }

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
            // assert()
            let content = self.content.read(purchase.content_id);
            let total_content_sales = self.total_sales_for_content.read(purchase.content_id)
                + purchase.price;

            let platform_fee_percentage = self.platform_fee.read();
            let platform_fee_recipient = self.platform_fee_recipient.read();

            let actual_platform_fee = (platform_fee_percentage * purchase.price) / 10000;
            let creators_fraction = purchase.price - actual_platform_fee;

            let total_creator_sales = self.creator_sales.read(content.creator) + creators_fraction;
            self.creator_sales.write(content.creator, total_creator_sales);

            self._single_payout(platform_fee_recipient, actual_platform_fee);

            let mut all_payouts = self.payout_history.entry(content.creator);

            let creator_payout_history_id = self.payout_history.entry(content.creator).len();
            let mut creator_payout = Payout {
                id: creator_payout_history_id,
                purchase_id,
                recipient: content.creator,
                amount: creators_fraction,
                timestamp: get_block_timestamp(),
                status: PayoutStatus::PENDING,
            };

            for i in 0..all_payouts.len() {
                let current_payout = all_payouts.at(i).read();
                if current_payout.purchase_id == purchase_id {
                    creator_payout.id = current_payout.id;
                    creator_payout.amount = current_payout.amount;
                    if purchase.status == PurchaseStatus::Completed {
                        creator_payout.timestamp = current_payout.timestamp;
                    } else {
                        creator_payout.timestamp = get_block_timestamp();
                    }
                    creator_payout.status = current_payout.status;
                    // I left out the timestamp so that the time starts counting from when true is
                // returned from this function. In other words, when the verify purchase returns
                // true, the content time in the hands of the user starts counting. This is for
                // the refund window calculation.
                }
            }

            if creator_payout.id >= all_payouts.len() {
                self.payout_history.entry(content.creator).push(creator_payout);
            } else {
                self
                    .payout_history
                    .entry(content.creator)
                    .at(creator_payout.id)
                    .write(creator_payout);
            }

            self.total_sales_for_content.write(purchase.content_id, total_content_sales);
            self
                .issue_receipt(
                    purchase_id,
                    purchase.content_id,
                    purchase.buyer,
                    content.creator,
                    purchase.price,
                    purchase.transaction_hash,
                );
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

        fn cancel_subscription(ref self: ContractState, user_id: u256) -> bool {
            let caller = get_caller_address();
            let user = self.users.read(user_id);
            assert(user.id == user_id, 'User does not exist');

            let subscription = self.subscriptions.read(user_id);
            let updated_subscription = Subscription {
                id: subscription.id,
                subscriber: subscription.subscriber,
                plan_id: subscription.plan_id,
                amount: subscription.amount,
                start_date: subscription.start_date,
                end_date: subscription.end_date,
                is_active: false,
                last_payment_date: subscription.last_payment_date,
                subscription_type: subscription.subscription_type,
                status: SubscriptionStatus::Cancelled,
                grace_period_end: subscription.grace_period_end,
            };

            self.subscriptions.write(user_id, updated_subscription.clone());
            self.subscription_record.entry(user_id).append().write(updated_subscription);
            self.subscription_count.write(user_id, self.subscription_count.read(user_id) + 1);

            let plan = self.subscription_plans.read(subscription.plan_id);
            let token_id = self.user_content_tokens.read((user_id, plan.content_id));
            if token_id != 0 {
                let mut token = self.access_tokens.read(token_id);
                token.is_active = false;
                self.access_tokens.write(token_id, token);
                self.emit(AccessTokenRevoked { token_id, user_id, content_id: plan.content_id });
            }

            self.emit(SubscriptionCancelled { user: caller, subscription_id: user_id });
            true
        }

        fn renew_subscription(ref self: ContractState, user_id: u256) -> bool {
            let caller = get_caller_address();

            // Verify the user exists
            let user = self.users.read(user_id);
            assert(user.id == user_id, 'User does not exist');

            // let subscription_id = self.subscription_id.read();
            let subscription_plan: Subscription = self.subscriptions.read(user_id);

            let current_time = get_block_timestamp();

            // Default subscription period is 30 days (in seconds)
            let subscription_period: u64 = 30 * 24 * 60 * 60;
            let end_date = current_time + subscription_period;

            // update user_id subscription to renew the previous subscription
            let update_subscription = Subscription {
                id: subscription_plan.id,
                subscriber: subscription_plan.subscriber,
                plan_id: subscription_plan.plan_id,
                amount: subscription_plan.amount,
                start_date: subscription_plan.start_date,
                end_date: end_date,
                is_active: true,
                last_payment_date: subscription_plan.last_payment_date,
                subscription_type: subscription_plan.subscription_type,
                status: SubscriptionStatus::Active,
                grace_period_end: GRACE_PERIOD,
            };

            // Store the subscription
            self.subscriptions.write(user_id, update_subscription.clone());

            self.subscription_record.entry(user_id).append().write(update_subscription);

            let current_count = self.subscription_count.read(user_id);

            self
                .emit(
                    SubscriptionRenewed {
                        user: caller, subscription_id: user_id, new_end_time: end_date,
                    },
                );

            true
        }

        fn issue_receipt(
            ref self: ContractState,
            purchase_id: u256,
            content_id: felt252,
            buyer: ContractAddress,
            creator: ContractAddress,
            price: u256,
            transaction_hash: felt252,
        ) -> u256 {
            let receipt_id = self.receipt_counter.read() + 1;
            let issued_at = starknet::get_block_timestamp();

            let receipt = Receipt {
                id: receipt_id,
                purchase_id,
                content_id,
                buyer,
                creator,
                price,
                status: ReceiptStatus::Valid,
                issued_at,
                transaction_hash,
            };
            self.receipt_counter.write(receipt_id);
            self.receipt.write(receipt_id, receipt);

            self.emit(ReceiptGenerated { receipt_id });

            receipt_id
        }

        fn get_receipt(self: @ContractState, receipt_id: u256) -> Receipt {
            let receipt = self.receipt.read(receipt_id);
            receipt
        }

        fn is_receipt_valid(self: @ContractState, receipt_id: u256) -> bool {
            let receipt = self.receipt.read(receipt_id);

            match receipt.status {
                ReceiptStatus::Valid => true,
                ReceiptStatus::Invalid => false,
            }
        }

        fn get_total_sales_by_creator(self: @ContractState, creator: ContractAddress) -> u256 {
            let total_sales = self.creator_sales.read(creator);
            total_sales
        }

        fn get_total_sales_for_content(self: @ContractState, content_id: felt252) -> u256 {
            let total_content_sales = self.total_sales_for_content.read(content_id);
            total_content_sales
        }

        fn create_subscription_plan(
            ref self: ContractState, content_id: felt252, duration: u64, price: u256,
        ) -> u256 {
            let caller = get_caller_address();
            assert(self.admin.read() == caller, 'Only admin can create plans');
            assert!(content_id != 0, "Invalid content ID");
            assert!(duration > 0, "Invalid duration");
            assert!(price > 0, "Invalid price");

            let plan_id = self.next_plan_id.read();
            let new_plan = SubscriptionPlan {
                plan_id, content_id, duration, price, is_active: true,
            };

            self.subscription_plans.write(plan_id, new_plan);
            self.next_plan_id.write(plan_id + 1);

            self.emit(SubscriptionPlanCreated { plan_id, content_id, duration, price });

            plan_id
        }
        fn get_subscription_plan(ref self: ContractState, plan_id: u256) -> SubscriptionPlan {
            let plan = self.subscription_plans.read(plan_id);
            assert!(plan.plan_id == plan_id, "Plan does not exist");
            plan
        }

        fn purchase_one_time_access(
            ref self: ContractState, user_id: u256, content_id: felt252,
        ) -> u256 {
            let caller = get_caller_address();
            let user = self.users.read(user_id);
            assert!(user.id == user_id, "User does not exist");
            assert!(caller == user.wallet_address, "Only user can purchase");

            let license = self.content_licenses.read(content_id);
            assert!(license.license_type == 0, "Content not available for one-time purchase");

            let price = self.content_prices.read(content_id);
            assert!(price > 0, "Content has no price");

            self._process_payment(price);

            let current_time = get_block_timestamp();
            let token_id = self
                ._generate_access_token(
                    user_id, content_id, current_time + 30 * 24 * 60 * 60,
                ); // 30 days access

            let purchase_id = self.next_purchase_id.read();
            let purchase = Purchase {
                id: purchase_id,
                content_id,
                buyer: caller,
                price,
                status: PurchaseStatus::Completed,
                timestamp: current_time,
                transaction_hash: 0,
                timeout_expiry: current_time + self.purchase_timeout_duration.read(),
            };

            self.purchases.write(purchase_id, purchase);
            self.next_purchase_id.write(purchase_id + 1);

            self
                .emit(
                    ContentPurchased {
                        purchase_id, content_id, buyer: caller, price, timestamp: current_time,
                    },
                );

            token_id
        }

        fn subscribe(ref self: ContractState, user_id: u256, plan_id: u256) -> u256 {
            let caller = get_caller_address();
            let user = self.users.read(user_id);
            assert!(user.id == user_id, "User does not exist");
            assert!(caller == user.wallet_address, "Only user can subscribe");

            let plan = self.subscription_plans.read(plan_id);
            assert!(plan.plan_id == plan_id, "Plan does not exist");
            assert!(plan.is_active, "Plan not active");

            self._process_payment(plan.price);

            let current_time = get_block_timestamp();
            let subscription_id = self.subscription_id.read();
            let new_subscription = Subscription {
                id: subscription_id,
                subscriber: caller,
                plan_id,
                amount: plan.price,
                start_date: current_time,
                end_date: current_time + plan.duration,
                is_active: true,
                last_payment_date: current_time,
                subscription_type: PlanType::MONTHLY,
                status: SubscriptionStatus::Active,
                grace_period_end: current_time + plan.duration + GRACE_PERIOD,
            };

            self.subscriptions.write(subscription_id, new_subscription.clone());
            self.subscription_record.entry(subscription_id).append().write(new_subscription);
            self
                .subscription_count
                .write(subscription_id, self.subscription_count.read(subscription_id) + 1);

            let payment_id = self.payment_id.read();
            let new_payment = Payment {
                id: payment_id,
                subscription_id,
                amount: plan.price,
                timestamp: current_time,
                is_verified: true,
                is_refunded: false,
            };

            self.payments.write(payment_id, new_payment);
            let payment_count = self.subscription_payment_count.read(subscription_id);
            self.subscription_payment_count.write(subscription_id, payment_count + 1);
            self.subscription_id.write(subscription_id + 1);
            let token_id = self
                ._generate_access_token(user_id, plan.content_id, current_time + plan.duration);

            self
                .emit(
                    SubscriptionCreated {
                        user_id, end_date: current_time + plan.duration, amount: plan.price,
                    },
                );

            subscription_id
        }

        fn has_access(ref self: ContractState, user_id: u256, content_id: felt252) -> bool {
            let token_id = self.user_content_tokens.read((user_id, content_id));
            let token = self.access_tokens.read(token_id);
            let current_time = get_block_timestamp();

            token.is_active
                && token.user_id == user_id
                && token.content_id == content_id
                && token.expiry > current_time
        }

        fn set_content_license(
            ref self: ContractState, content_id: felt252, license_type: u8,
        ) -> bool {
            let caller = get_caller_address();
            assert!(self.admin.read() == caller, "Only admin can set license");
            assert!(license_type <= 2, "Invalid license type");

            let license = ContentLicense { content_id, license_type };

            self.content_licenses.write(content_id, license);
            self.emit(ContentLicenseSet { content_id, license_type });

            true
        }

        fn upgrade_subscription(
            ref self: ContractState, subscription_id: u256, new_plan_id: u256,
        ) -> bool {
            let caller = get_caller_address();
            let subscription = self.subscriptions.read(subscription_id);
            assert!(subscription.id == subscription_id, "Subscription does not exist");
            assert!(subscription.is_active, "Subscription not active");
            assert!(caller == subscription.subscriber, "Not subscription owner");

            let old_plan = self.subscription_plans.read(subscription.plan_id);
            let new_plan = self.subscription_plans.read(new_plan_id);
            assert!(new_plan.plan_id == new_plan_id, "New plan does not exist");
            assert!(new_plan.is_active, "New plan not active");

            // Get user_id from subscriber address
            let user = self.user_by_address.read(subscription.subscriber);
            assert!(user.id != 0, "User not found for subscriber");
            let user_id = user.id;

            let current_time = get_block_timestamp();
            let remaining_time = if subscription.end_date > current_time {
                subscription.end_date - current_time
            } else {
                0
            };

            let remaining_value = (old_plan.price * remaining_time.into())
                / old_plan.duration.into();
            let proration_credit = (remaining_value * PRORATION_PRECISION) / PRORATION_PRECISION;
            let amount_due = if new_plan.price > proration_credit {
                new_plan.price - proration_credit
            } else {
                0
            };

            if amount_due > 0 {
                self._process_payment(amount_due);
            }

            let updated_subscription = Subscription {
                id: subscription.id,
                subscriber: subscription.subscriber,
                plan_id: new_plan_id,
                amount: new_plan.price,
                start_date: subscription.start_date,
                end_date: current_time + new_plan.duration,
                is_active: true,
                last_payment_date: current_time,
                subscription_type: subscription.subscription_type,
                status: SubscriptionStatus::Active,
                grace_period_end: current_time + new_plan.duration + GRACE_PERIOD,
            };

            self.subscriptions.write(subscription_id, updated_subscription.clone());
            self.subscription_record.entry(subscription_id).append().write(updated_subscription);
            self
                .subscription_count
                .write(subscription_id, self.subscription_count.read(subscription_id) + 1);

            let token_id = self.user_content_tokens.read((user_id, old_plan.content_id));
            self
                .access_tokens
                .entry(token_id)
                .write(
                    AccessToken {
                        token_id: token_id,
                        user_id: user_id,
                        content_id: new_plan.content_id,
                        expiry: current_time + new_plan.duration,
                        is_active: true,
                    },
                );

            self.emit(SubscriptionUpgraded { subscription_id, user_id, new_plan_id });

            true
        }

        fn get_content_license(ref self: ContractState, content_id: felt252) -> ContentLicense {
            self.content_licenses.read(content_id)

        fn batch_payout_creators(ref self: ContractState) {
            let caller = get_caller_address();
            assert(self.admin.read() == caller, 'Only admin can execute payout');

            let payout_schedule = self.payout_schedule.read();
            let (last_execution, interval) = (
                payout_schedule.last_execution, payout_schedule.interval,
            );
            let current_time = get_block_timestamp();
            assert(current_time >= (last_execution + interval), 'Payout period not reached');

            let current_user_count = self.user_id.read();
            let mut creators_array: Array<User> = array![];
            let mut amount_paid_out: u256 = 0;
            for i in 0..current_user_count {
                if self.users.read(i).role == Role::WRITER {
                    creators_array.append(self.users.read(i));
                }
            }
            let mut recipients_array: Array<ContractAddress> = array![];

            for i in 0..creators_array.len() {
                let current_creator = creators_array.at(i);
                let current_creator_address = *current_creator.wallet_address;
                recipients_array.append(current_creator_address);

                let current_creator_payout_history_vec = self
                    .payout_history
                    .entry(current_creator_address);
                let mut pending_payouts: Array<Payout> = array![];
                let mut amt_to_be_paid_creator = 0_u256;

                for i in 0..current_creator_payout_history_vec.len() {
                    let mut payout = current_creator_payout_history_vec.at(i).read();
                    if payout.status == PayoutStatus::PENDING {
                        pending_payouts.append(payout);
                        amt_to_be_paid_creator += payout.amount;
                        payout.status == PayoutStatus::PAID;
                    }
                    current_creator_payout_history_vec.at(i).write(payout);
                }

                let transfer = self._single_payout(current_creator_address, amt_to_be_paid_creator);
                assert(transfer, 'Transfer failed');
                amount_paid_out += amt_to_be_paid_creator;
                self.creator_sales.write(current_creator_address, 0);
            }

            self
                .emit(
                    PayoutExecuted {
                        recipients: recipients_array,
                        timestamp: get_block_timestamp(),
                        amount_paid: amount_paid_out,
                    },
                );
        }

        fn set_payout_schedule(ref self: ContractState, interval: u64) {
            let caller = get_caller_address();
            assert(self.admin.read() == caller, 'Only admin can verify payments');
            let current_payout_schedule = self.payout_schedule.read();
            let mut last_execution_date = get_block_timestamp();
            if current_payout_schedule != Default::default() {
                last_execution_date = current_payout_schedule.last_execution;
            }
            let new_schedule = PayoutSchedule {
                interval, start_time: last_execution_date, last_execution: 0,
            };
            self.payout_schedule.write(new_schedule);
            self
                .emit(
                    PayoutScheduleSet { start_time: last_execution_date, setter: caller, interval },
                );
        }

        fn get_payout_schedule(
            self: @ContractState,
        ) -> (u64, u64) { // interval and last execution time
            let payout_schedule = self.payout_schedule.read();
            (payout_schedule.interval, payout_schedule.last_execution)
        }

        fn request_refund(
            ref self: ContractState, purchase_id: u256, refund_reason: RefundRequestReason,
        ) {
            let caller = get_caller_address();
            // let user = self.user_by_address.read(caller);
            let user_refunds_vec = self.user_refunds.entry(caller);
            let refund_id = user_refunds_vec.len();
            let refund_request = Refund {
                refund_id,
                purchase_id,
                reason: refund_reason,
                user: caller,
                status: RefundStatus::PENDING,
                request_timestamp: get_block_timestamp(),
                refund_amount: Option::None,
            };
            self.user_refunds.entry(caller).push(refund_request);
            let content_id = self.purchases.read(purchase_id).content_id;
            let purchased_at = self.purchases.read(purchase_id).timestamp;
            assert(
                (get_block_timestamp() - purchased_at) < self.refund_window.read(),
                'Refund window already closed',
            );
            self
                .emit(
                    RefundRequested {
                        user: caller, content_id, purchase_id, reason: refund_reason,
                    },
                );
        }

        // The refund_percentage will only be used if the reason is OTHER
        fn approve_refund(
            ref self: ContractState, refund_id: u64, user_id: u256, refund_percentage: Option<u256>,
        ) {
            let caller = get_caller_address();
            // Ensure that only an admin can verify users.
            assert((self.admin.read() == caller), 'Only admin can approve refunds');
            let user = self.users.read(user_id);
            let user_address = user.wallet_address;
            let mut refund = self.user_refunds.entry(user_address).at(refund_id).read();
            assert(refund.status != RefundStatus::TIMED_OUT, 'Request already timed out');
            assert(refund.status == RefundStatus::PENDING, 'Request already processed');

            let refund_reason = refund.reason;
            let mut refund_percent = self._get_refund_percentage(refund_reason);
            if refund_percent == 0 {
                assert(refund_percentage.is_some(), 'Custom percentage for other');
                refund_percent = refund_percentage.unwrap();
            }
            // We'll take the refund percent later in the contract from the creator payout

            let request_timestamp = refund.request_timestamp;
            let time_since_request = get_block_timestamp() - request_timestamp;
            if time_since_request >= self.refund_window.read() {
                refund.status = RefundStatus::TIMED_OUT;
                let purchase_id = refund.purchase_id;
                let purchase = self.purchases.read(purchase_id);
                let content_id = purchase.content_id;
                // let content = self.content.read(content_id);
                self.user_refunds.entry(user_address).at(refund_id).write(refund);
                self.emit(RefundTimedOut { user_id, content_id, refund_id })
            } else {
                refund.status = RefundStatus::APPROVED;
                // This should affect the creator payout for that purchase

                let purchase_id = refund.purchase_id;
                let purchase = self.purchases.read(purchase_id);
                let content_id = purchase.content_id;
                let content = self.content.read(content_id);
                let content_creator = content.creator;

                let creator_payout_vec = self.payout_history.entry(content_creator);
                let mut dummy_payout_array = array![];
                // Dummy array that will help retrieve the payout we need to edit
                for i in 0..creator_payout_vec.len() {
                    let specific_payout = creator_payout_vec.at(i).read();
                    if specific_payout.purchase_id == purchase_id {
                        dummy_payout_array.append(specific_payout);
                    }
                }
                // Retrieve the payout, the length will be one, but we can assert too
                assert(dummy_payout_array.len() == 1, 'Double Payout-purchase entry');
                let mut specific_payout = *dummy_payout_array.at(0);

                let refund_amount = refund_percent * specific_payout.amount / 100;
                specific_payout.amount -= refund_amount;
                if refund_amount == specific_payout.amount {
                    specific_payout.status = PayoutStatus::CANCELLED;
                }
                refund.refund_amount = Option::Some(refund_amount);

                self
                    .payout_history
                    .entry(content_creator)
                    .at(specific_payout.id)
                    .write(specific_payout);
                self.user_refunds.entry(user_address).at(refund_id).write(refund);
                self.emit(RefundApproved { approver: caller, user_id, content_id, refund_id });
            }
        }

        fn decline_refund(ref self: ContractState, refund_id: u64, user_id: u256) {
            let caller = get_caller_address();
            // Ensure that only an admin can verify users.
            assert((self.admin.read() == caller), 'Only admin can approve refunds');
            let user = self.users.read(user_id);
            let user_address = user.wallet_address;
            let mut refund = self.user_refunds.entry(user_address).at(refund_id).read();
            let purchase = refund.purchase_id;
            let content_id = self.purchases.read(purchase).content_id;
            assert(refund.status == RefundStatus::PENDING, 'Request already processed');
            let request_timestamp = refund.request_timestamp;
            let time_since_request = get_block_timestamp() - request_timestamp;
            if time_since_request >= self.refund_window.read() {
                refund.status = RefundStatus::TIMED_OUT;
                let purchase_id = refund.purchase_id;
                let purchase = self.purchases.read(purchase_id);
                let content_id = purchase.content_id;
                // let content = self.content.read(content_id);
                self.user_refunds.entry(user_address).at(refund_id).write(refund);
                self.emit(RefundTimedOut { user_id, content_id, refund_id })
            } else {
                refund.status = RefundStatus::DECLINED;
                self.emit(RefundDeclined { decliner: caller, user_id, content_id, refund_id });
                self.user_refunds.entry(user_address).at(refund_id).write(refund);
            }
        }

        fn refund_user(ref self: ContractState, refund_id: u64, user_id: u256) {
            let caller = get_caller_address();
            // Ensure that only an admin can verify users.
            assert((self.admin.read() == caller), 'Only admin can approve refunds');
            let user = self.users.read(user_id);
            let user_address = user.wallet_address;
            let mut refund = self.user_refunds.entry(user_address).at(refund_id).read();
            assert(refund.status == RefundStatus::APPROVED, 'Refund request declined');
            refund.status = RefundStatus::PAID;
            self.user_refunds.entry(user_address).at(refund_id).write(refund);
            let purchase_id = refund.purchase_id;
            let content_id = self.purchases.read(purchase_id).content_id;
            assert(refund.refund_amount.is_some(), 'Refund amount is none');
            let refund_amount = refund.refund_amount.unwrap();

            self._process_refund(refund_amount, user_address);

            self
                .emit(
                    RefundPaid {
                        refund_id, content_id, purchase_id: purchase_id, executor: caller, user_id,
                    },
                );
        }

        fn get_user_refunds(self: @ContractState, user_id: u256) -> Array<Refund> {
            let user = self.users.read(user_id);
            let user_address = user.wallet_address;
            let user_refunds_vec = self.user_refunds.entry(user_address);
            let mut user_refunds_arr = array![];

            for i in 0..user_refunds_vec.len() {
                let current_refund = user_refunds_vec.at(i).read();
                user_refunds_arr.append(current_refund);
            }

            user_refunds_arr
        }

        fn get_all_pending_refunds(self: @ContractState) -> Array<Refund> {
            let caller = get_caller_address();
            // Ensure that only an admin can verify users.
            assert((self.admin.read() == caller), 'Only admin can approve refunds');

            let current_user_id = self.user_id.read();
            let mut all_pending_refunds_arr = array![];
            let mut all_users_array = array![];

            for i in 0..current_user_id {
                let current_user = self.users.read(i);
                all_users_array.append(current_user);
            }

            for i in 0..all_users_array.len() {
                let current_user = all_users_array.at(i);
                let current_user_address = current_user.wallet_address;
                let current_user_refunds_vec = self.user_refunds.entry(*current_user_address);

                for i in 0..current_user_refunds_vec.len() {
                    let current_user_refund = current_user_refunds_vec.at(i).read();
                    if current_user_refund.status == RefundStatus::PENDING {
                        all_pending_refunds_arr.append(current_user_refund);
                    }
                }
            }

            all_pending_refunds_arr
        }

        fn set_platform_fee(ref self: ContractState, platform_fee: u256) {
            let caller = get_caller_address();
            // Ensure that only an admin can verify users.
            assert((self.admin.read() == caller), 'Only admin can execute refunds');
            self.platform_fee.write(platform_fee);
            self
                .emit(
                    PlatformFeeChanged { new_fee: platform_fee, timestamp: get_block_timestamp() },
                );
        }

        fn set_refund_window(ref self: ContractState, window: u64) {
            let caller = get_caller_address();
            // Ensure that only an admin can verify users.
            assert((self.admin.read() == caller), 'Only admin can execute refunds');
            self.refund_window.write(window);
            self.emit(RefundWindowChanged { new_window: window, timestamp: get_block_timestamp() });
        }
    }

    #[generate_trait]
    impl internal of InternalTraits {
        /// @notice Processes a payment for a subscription or content purchase.
        /// @dev Checks the token allowance and balance before transferring tokens.
        /// @param self The contract state reference.
        /// @param amount The amount of tokens to transfer.
        /// @require The caller must have sufficient token allowance and balance.
        fn _process_payment(ref self: ContractState, amount: u256) {
            let strk_token = IERC20Dispatcher { contract_address: self.token_address.read() };
            let caller = get_caller_address();
            let contract_address = get_contract_address();
            self._check_token_allowance(caller, amount);
            self._check_token_balance(caller, amount);
            strk_token.transfer_from(caller, contract_address, amount);
        }

        /// @notice Checks if the caller has sufficient token allowance.
        /// @dev Asserts that the caller has enough allowance to transfer the specified amount.
        /// @param self The contract state reference.
        /// @param spender The address of the spender (usually the contract itself).
        /// @param amount The amount of tokens to check allowance for.
        /// @require The caller must have sufficient token allowance.
        fn _check_token_allowance(ref self: ContractState, spender: ContractAddress, amount: u256) {
            let token = IERC20Dispatcher { contract_address: self.token_address.read() };
            let allowance = token.allowance(spender, starknet::get_contract_address());
            assert(allowance >= amount, payment_errors::INSUFFICIENT_ALLOWANCE);
        }

        /// @notice Checks if the caller has sufficient token balance.
        /// @dev Asserts that the caller has enough balance to transfer the specified amount.
        /// @param self The contract state reference.
        /// @param caller The address of the caller (usually the user).
        /// @param amount The amount of tokens to check balance for.
        /// @require The caller must have sufficient token balance.
        fn _check_token_balance(ref self: ContractState, caller: ContractAddress, amount: u256) {
            let token = IERC20Dispatcher { contract_address: self.token_address.read() };
            let balance = token.balance_of(caller);
            assert(balance >= amount, payment_errors::INSUFFICIENT_BALANCE);
        }

        fn _single_payout(
            ref self: ContractState, recipient_address: ContractAddress, amount: u256,
        ) -> bool {
            assert(!recipient_address.is_zero(), permission_errors::ZERO_ADDRESS);
            let token_dispatcher = IERC20Dispatcher { contract_address: self.token_address.read() };
            let contract_address = get_contract_address();
            self._check_token_balance(contract_address, amount);
            let transfer = token_dispatcher.transfer(recipient_address, amount);
            transfer
        }

        fn _process_refund(ref self: ContractState, amount: u256, refund_address: ContractAddress) {
            let token = IERC20Dispatcher { contract_address: self.token_address.read() };
            let contract_address = get_contract_address();
            self._check_token_balance(contract_address, amount);
            token.transfer(refund_address, amount);
        }

        fn _generate_access_token(
            ref self: ContractState, user_id: u256, content_id: felt252, expiry: u64,
        ) -> u256 {
            let token_id = self.next_token_id.read();
            let new_token = AccessToken { token_id, user_id, content_id, expiry, is_active: true };

            self.access_tokens.write(token_id, new_token);
            self.user_content_tokens.write((user_id, content_id), token_id);
            self.next_token_id.write(token_id + 1);

            self.emit(AccessTokenGenerated { token_id, user_id, content_id, expiry });

            token_id
        fn _get_refund_percentage(
            ref self: ContractState, refund_reason: RefundRequestReason,
        ) -> u256 {
            match refund_reason {
                RefundRequestReason::CONTENT_NOT_RECEIVED => 100,
                RefundRequestReason::DUPLICATE_PURCHASE => 80,
                RefundRequestReason::UNABLE_TO_ACCESS => 100,
                RefundRequestReason::MISREPRESENTED_CONTENT => 65,
                RefundRequestReason::OTHER => 0,
            }
        }
    }
}
