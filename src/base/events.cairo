use starknet::{
    ContractAddress
};
use crate::base::types::{Permissions,VerificationType,RefundRequestReason,ContentUpdateType};
#[derive(Drop, starknet::Event)]
pub struct TokenBoundAccountCreated {
    pub id: u256,
}


#[derive(Drop, starknet::Event)]
pub struct EmergencyPaused {
    pub paused_by: ContractAddress,
    pub timestamp: u64,
}

#[derive(Drop, starknet::Event)]
pub struct EmergencyUnpause {
    pub unpaused_by: ContractAddress,
    pub timestamp: u64,
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
pub struct SubscriptionRenewed {
    pub user: ContractAddress,
    pub subscription_id: u256,
    pub new_end_time: u64,
}

#[derive(Drop, starknet::Event)]
pub struct ReceiptGenerated {
    pub receipt_id: u256,
}

#[derive(Drop, starknet::Event)]
pub struct SubscriptionCancelled {
    pub user: ContractAddress,
    pub subscription_id: u256,
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

#[derive(Drop, starknet::Event)]
pub struct ContentUpdated {
    pub content_id: felt252,
    pub updater: ContractAddress,
    pub version: u64,
    pub update_type: ContentUpdateType,
    pub timestamp: u64,
}

#[derive(Drop, starknet::Event)]
pub struct ContentUpdateHistoryRecorded {
    pub content_id: felt252,
    pub version: u64,
    pub updater: ContractAddress,
    pub update_type: ContentUpdateType,
    pub timestamp: u64,
}
