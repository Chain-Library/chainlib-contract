// Error constants for permission system
pub mod permission_errors {
    pub const NO_PERMISSION: felt252 = 'You do not have permission';
    pub const NOT_ACCOUNT_OWNER: felt252 = 'Not the account owner';
    pub const PERMISSION_NOT_FOUND: felt252 = 'Permission not found';
    pub const INVALID_PERMISSION: felt252 = 'Invalid permission value';
    pub const ZERO_ADDRESS: felt252 = 'Zero address';
}

// Error constants for payment safety system
pub mod payment_safety_errors {
    // Transaction validation errors
    pub const INVALID_AMOUNT: felt252 = 'Invalid payment amount';
    pub const AMOUNT_TOO_LARGE: felt252 = 'Amount exceeds limit';
    pub const AMOUNT_TOO_SMALL: felt252 = 'Amount below minimum';
    pub const INVALID_RECIPIENT: felt252 = 'Invalid recipient address';
    pub const INSUFFICIENT_BALANCE: felt252 = 'Insufficient balance';

    // Rate limiting errors
    pub const RATE_LIMIT_EXCEEDED: felt252 = 'Rate limit exceeded';
    pub const DAILY_LIMIT_EXCEEDED: felt252 = 'Daily limit exceeded';
    pub const WITHDRAWAL_COOLDOWN: felt252 = 'Withdrawal cooldown active';
    pub const TOO_MANY_TRANSACTIONS: felt252 = 'Too many transactions';

    // Fraud detection errors
    pub const SUSPICIOUS_ACTIVITY: felt252 = 'Suspicious activity detected';
    pub const TRANSACTION_BLOCKED: felt252 = 'Transaction blocked';
    pub const USER_FLAGGED: felt252 = 'User flagged for review';
    pub const PATTERN_ANOMALY: felt252 = 'Pattern anomaly detected';

    // Emergency system errors
    pub const SYSTEM_PAUSED: felt252 = 'System is paused';
    pub const EMERGENCY_MODE: felt252 = 'Emergency mode active';
    pub const FUNCTION_DISABLED: felt252 = 'Function disabled';
    pub const MAINTENANCE_MODE: felt252 = 'Maintenance mode active';

    // Recovery mechanism errors
    pub const RECOVERY_IN_PROGRESS: felt252 = 'Recovery in progress';
    pub const INVALID_RECOVERY_KEY: felt252 = 'Invalid recovery key';
    pub const RECOVERY_EXPIRED: felt252 = 'Recovery period expired';
    pub const RECOVERY_NOT_INITIATED: felt252 = 'Recovery not initiated';
}
