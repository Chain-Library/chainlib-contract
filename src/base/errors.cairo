pub mod Error {
    pub const NOT_AUTHORIZED: felt252 = 'NotAuthorized';
    pub const DELEGATION_EXPIRED: felt252 = 'DelegationExpired';
    pub const ACTION_LIMIT_REACHED: felt252 = 'ActionLimitReached';
    pub const DELEGATION_NOT_ACTIVE: felt252 = 'DelegationNotActive';
    pub const INVALID_DELEGATION: felt252 = 'InvalidDelegate';
    pub const INVALID_EXPIRY: felt252 = 'InvalidExpiry';
    pub const INVALID_PERMISSION: felt252 = 'InvalidPermission';
}
