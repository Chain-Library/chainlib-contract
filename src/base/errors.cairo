pub mod Error {
    pub const NOT_AUTHORIZED: felt252 = 'NotAuthorized';
    pub const DELEGATION_EXPIRED: felt252 = 'DelegationExpired';
    pub const ACTION_LIMIT_REACHED: felt252 = 'ActionLimitReached';
    pub const DELEGATION_NOT_ACTIVE: felt252 = 'DelegationNotActive';
    pub const INVALID_DELEGATION: felt252 = 'InvalidDelegate';
    pub const INVALID_EXPIRY: felt252 = 'InvalidExpiry';
    pub const INVALID_PERMISSION: felt252 = 'InvalidPermission';
}
// // Errors
// #[derive(Drop, PartialEq)]
// pub enum Error {
//     NotAuthorized,
//     DelegationExpired,
//     ActionLimitReached,
//     DelegationNotActive,
//     InvalidDelegate,
//     InvalidExpiry,
//     InvalidPermission,
// }

// impl ImplError of ErrorImpl {
//      fn into_felt252(self) -> felt252 {
//         match self {
//             Error::NotAuthorized => 0,
//             Error::DelegationExpired => 1,
//             Error::ActionLimitReached => 2,
//             Error::DelegationNotActive => 3,
//             Error::InvalidDelegate => 4,
//             Error::InvalidExpiry => 5,
//             Error::InvalidPermission => 6,
//         }
//     }
// }


