//  use chain_lib::chainlib::AccountDelegation::AccountDelegation::{ Event};

use starknet::ContractAddress;


// Event emitted when delegation is created
#[derive(Drop, starknet::Event)]
pub struct DelegationCreated {
    pub owner: ContractAddress,
    pub delegate: ContractAddress,
    pub permission_id: u8,
    pub expiry: u64,
    pub max_actions: u64,
}

// Event emitted when delegation is revoked
#[derive(Drop, starknet::Event)]
pub struct DelegationRevoked {
    pub owner: ContractAddress,
    pub delegate: ContractAddress,
    pub permission_id: u8,
}

// Event emitted when delegation is used
#[derive(Drop, starknet::Event)]
pub struct DelegationUsed {
    pub owner: ContractAddress,
    pub delegate: ContractAddress,
    pub permission_id: u8,
    pub action_count: u64,
}

// Event emitted when delegation expires
#[derive(Drop, starknet::Event)]
pub struct DelegationExpire {
    pub owner: ContractAddress,
    pub delegate: ContractAddress,
    pub permission_id: u8,
}
