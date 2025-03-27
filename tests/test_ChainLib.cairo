// Import the contract modules
use chain_lib::chainlib::ChainLib;

use chain_lib::interfaces::IChainLib::{IChainLib, IChainLibDispatcher, IChainLibDispatcherTrait};
use snforge_std::{CheatSpan, ContractClassTrait, DeclareResultTrait, cheat_caller_address, declare};
use starknet::ContractAddress;
use starknet::class_hash::ClassHash;
use starknet::contract_address::contract_address_const;
use starknet::testing::{set_caller_address, set_contract_address};
use chain_lib::base::types::{Role, Rank};


fn setup() -> (ContractAddress, ContractAddress) {
    let declare_result = declare("ChainLib");
    assert(declare_result.is_ok(), 'Contract declaration failed');
    let admin_address: ContractAddress = contract_address_const::<'admin'>();

    let contract_class = declare_result.unwrap().contract_class();
    let mut calldata = array![admin_address.into()];

    let deploy_result = contract_class.deploy(@calldata);
    assert(deploy_result.is_ok(), 'Contract deployment failed');

    let (contract_address, _) = deploy_result.unwrap();

    (contract_address, admin_address)
}

#[test]
fn test_initial_data() {
    let (contract_address, admin_address) = setup();

    let dispatcher = IChainLibDispatcher { contract_address };

    // Ensure dispatcher methods exist
    let admin = dispatcher.getAdmin();

    assert(admin == admin_address, 'deployment failed');
}


#[test]
fn test_create_token_bount_account() {
    let (contract_address, _) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Test input values
    let user_name: felt252 = 'John';
    let init_param1: felt252 = 'John@yahoo.com';
    let init_param2: felt252 = 'john is a boy';

    // Call account
    let account_id = dispatcher.create_token_account(user_name, init_param1, init_param2);

    // Validate that the account ID is correctly incremented
    assert(account_id == 0, 'account_id should start from 0');

    // Retrieve the account to verify it was stored correctly
    let token_bound_account = dispatcher.get_token_bound_account(account_id);
    assert(token_bound_account.user_name == user_name, 'namemismatch');
    assert(token_bound_account.init_param1 == init_param1, 'init_param1 mismatch');
    assert(token_bound_account.init_param2 == init_param2, 'init_param2 mismatch');
}


#[test]
fn test_create_user() {
    let (contract_address, _) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Test input values
    let username: felt252 = 'John';
    let role: Role = Role::READER;
    let rank: Rank = Rank::BEGINNER;
    let metadata: felt252 = 'john is a boy';

    // Call create_user
    let account_id = dispatcher.register_user(username, role.clone(), rank.clone(), metadata);

    // Validate that the claim ID is correctly incremented
    assert(account_id == 0, 'account_id should start from 0');

    // Retrieve the user to verify it was stored correctly
    let user = dispatcher.retrieve_user_profile(account_id);
    assert(user.username == username, 'username mismatch');
    assert(user.role == role, 'role mismatch');
    assert(user.rank == rank, 'rank mismatch');
    assert(user.metadata == metadata, 'metadata mismatch');
    assert(!user.verified, 'already verified');
}

#[test]
fn test_verify_user() {
    let (contract_address, admin_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Test input values
    let username: felt252 = 'John';
    let role: Role = Role::READER;
    let rank: Rank = Rank::BEGINNER;
    let metadata: felt252 = 'john is a boy';

    // Call register user
    let account_id = dispatcher.register_user(username, role.clone(), rank.clone(), metadata);
    // Retrieve the user to verify it was stored correctly
    let user = dispatcher.retrieve_user_profile(account_id);
    assert(!user.verified, 'already verified');

    cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);
    let verify = dispatcher.verify_user(user.id);
    assert(verify, 'Verification Falied');

    let verified_user = dispatcher.is_verified(account_id);
    assert(verified_user, 'Not Verified');
}

#[test]
#[should_panic(expected: 'Only admin can verify users')]
fn test_verify_user_not_admin() {
    let (contract_address, _) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Test input values
    let username: felt252 = 'John';
    let role: Role = Role::READER;
    let rank: Rank = Rank::BEGINNER;
    let metadata: felt252 = 'john is a boy';

    // Call register
    let account_id = dispatcher.register_user(username, role.clone(), rank.clone(), metadata);
    // Retrieve the user to verify it was stored correctly
    let user = dispatcher.retrieve_user_profile(account_id);
    assert(!user.verified, 'already verified');

    let verify = dispatcher.verify_user(user.id);
    assert(verify, 'Verification Falied');

    let verified_user = dispatcher.retrieve_user_profile(account_id);
    assert(verified_user.verified, 'Not Verified');
}
