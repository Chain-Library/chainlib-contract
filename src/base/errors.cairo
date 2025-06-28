// Error constants for permission system
pub mod permission_errors {
    pub const NO_PERMISSION: felt252 = 'You do not have permission';
    pub const NOT_ACCOUNT_OWNER: felt252 = 'Not the account owner';
    pub const PERMISSION_NOT_FOUND: felt252 = 'Permission not found';
    pub const INVALID_PERMISSION: felt252 = 'Invalid permission value';
    pub const ZERO_ADDRESS: felt252 = 'Zero address';
}

pub mod payment_errors {
    pub const INSUFFICIENT_ALLOWANCE: felt252 = 'Insufficient token allowance';
    pub const INSUFFICIENT_BALANCE: felt252 = 'Insufficient token balance';
}
