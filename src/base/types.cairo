use starknet::ContractAddress;
#[derive(Drop, Serde, starknet::Store)]
pub struct TokenBoundAccount {
    pub id: u256,
    pub address: ContractAddress,
    pub user_name: felt252,
    pub init_param1: felt252,
    pub init_param2: felt252,
    pub created_at: u64,
    pub updated_at: u64,
}
#[derive(Drop, Serde, starknet::Store)]
pub struct User {
    pub id: u256,
    pub username: felt252,
    pub wallet_address: ContractAddress,
    pub role: Role,
    pub rank: Rank,
    pub verified: bool,
    pub metadata: felt252,
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

#[derive(Copy, Drop, Serde, starknet::Store, Clone, PartialEq, Debug)]
pub enum PurchaseStatus {
    #[default]
    Pending,
    Completed,
    Failed,
    Refunded
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
}
