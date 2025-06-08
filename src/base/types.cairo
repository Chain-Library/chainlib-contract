use starknet::ContractAddress;

#[derive(Drop, Serde, starknet::Store, Copy)]
pub struct TokenBoundAccount {
    pub id: u256,
    pub address: ContractAddress,
    pub user_name: felt252,
    pub init_param1: felt252,
    pub init_param2: felt252,
    pub created_at: u64,
    pub updated_at: u64,
    pub owner_permissions: Permissions // Owner's permissions
}

#[derive(Drop, Serde, starknet::Store, Clone)]
pub struct User {
    pub id: u256,
    pub username: felt252,
    pub wallet_address: ContractAddress,
    pub role: Role,
    pub rank: Rank,
    pub verified: bool,
    pub metadata: felt252,
    pub status: Status,
}

#[derive(Drop, Serde, starknet::Store, Clone, PartialEq)]
pub enum Status {
    #[default]
    ACTIVE,
    DEACTIVATED,
}

// Permission flags using bit flags for flexibility
#[derive(Drop, Copy, Serde, starknet::Store, Default, PartialEq)]
pub struct Permissions {
    pub value: u64 // Using u64 to store permission bits
}

// Permission constants
pub mod permission_flags {
    // Basic permissions
    pub const NONE: u64 = 0x0;
    pub const FULL: u64 = 0xFFFFFFFFFFFFFFFF;

    // Specific permissions - using powers of 2 for bit flags
    pub const READ: u64 = 0x1; // Can read account data
    pub const WRITE: u64 = 0x2; // Can update account data
    pub const TRANSFER: u64 = 0x4; // Can transfer tokens
    pub const MANAGE_PERMISSIONS: u64 = 0x8; // Can update permissions
    pub const EXECUTE: u64 = 0x10; // Can execute transactions
    pub const MANAGE_OPERATORS: u64 = 0x20; // Can add/remove operators
    pub const UPGRADE: u64 = 0x40; // Can upgrade the account
    pub const DELETE: u64 = 0x80; // Can delete the account
}

#[derive(Drop, Serde, starknet::Store, Clone, PartialEq)]
pub enum Role {
    #[default]
    NIL,
    READER,
    WRITER,
}


#[derive(Drop, Serde, starknet::Store, Clone, PartialEq)]
pub enum Rank {
    #[default]
    BEGINNER,
    INTERMEDIATE,
    EXPERT,
}

#[derive(Drop, starknet::Store, Serde, Debug, Copy)]
pub struct AccessRule {
    pub access_type: AccessType,
    pub permission_level: u64,
    pub conditions: Option<felt252>,
    pub expires_at: u64,
}

#[derive(Copy, Drop, Serde, starknet::Store, PartialEq, Debug)]
pub enum AccessType {
    #[default]
    View,
    Edit,
    Share,
    Manage,
    Admin,
}

#[derive(Drop, starknet::Store, Serde, Debug, Copy)]
pub struct VerificationRequirement {
    pub requirement_type: VerificationType,
    pub threshold: u64,
    pub valid_until: u64,
}

#[derive(Copy, Drop, Serde, starknet::Store, PartialEq, Debug)]
pub enum VerificationType {
    #[default]
    Identity,
    Payment,
    Reputation,
    Ownership,
    Custom,
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

// New delegation flags - add to your permission_flags module
pub mod delegation_flags {
    // Using higher bits to avoid collision with existing permission flags
    pub const DELEGATE_TRANSFER: u64 = 0x10000;
    pub const DELEGATE_CONTENT: u64 = 0x20000;
    pub const DELEGATE_ADMIN: u64 = 0x40000;
    pub const DELEGATE_USER: u64 = 0x80000;
    // Combined flag for full delegation capabilities
    pub const FULL_DELEGATION: u64 = 0xF0000;
}
#[derive(Copy, Drop, Serde, starknet::Store, Clone, PartialEq, Debug)]
pub enum PurchaseStatus {
    #[default]
    Pending,
    Completed,
    Failed,
    Refunded,
}

#[derive(Drop, Serde, starknet::Store, Debug)]
pub struct Purchase {
    pub id: u256,
    pub content_id: felt252,
    pub buyer: ContractAddress,
    pub price: u256,
    pub status: PurchaseStatus,
    pub timestamp: u64,
    pub transaction_hash: felt252,
    pub timeout_expiry: u64,
}


#[derive(Copy, Drop, Serde, PartialEq, starknet::Store, Debug)]
pub struct Subscription {
    pub id: u256, // Subscription ID
    pub user: ContractAddress,
    pub start_time: u64,
    pub end_time: u64,
    pub duration: u64,
    pub status: SubscriptionStatus,
}
#[derive(Copy, Drop, Serde, starknet::Store, Clone, PartialEq, Debug)]
pub enum SubscriptionStatus {
    #[default]
    Active,
    Inactive,
    Cancelled,
}
