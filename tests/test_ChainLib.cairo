
// Import the contract modules
use chain_lib::chainlib::ChainLib;

use chain_lib::interfaces::IChainLib::{IChainLib, IChainLibDispatcher, IChainLibDispatcherTrait};
use snforge_std::{CheatSpan, ContractClassTrait, DeclareResultTrait, cheat_caller_address, declare};
use starknet::ContractAddress;
use starknet::class_hash::ClassHash;
use starknet::contract_address::contract_address_const;
use starknet::testing::{set_caller_address, set_contract_address};


fn setup() -> ContractAddress {
    let declare_result = declare("ChainLib");
    assert(declare_result.is_ok(), 'Contract declaration failed');

    let contract_class = declare_result.unwrap().contract_class();
    let mut calldata = array![];

    let deploy_result = contract_class.deploy(@calldata);
    assert(deploy_result.is_ok(), 'Contract deployment failed');

    let (contract_address, _) = deploy_result.unwrap();

    (contract_address)
}

#[test]
fn test_initial_data() {
    let contract_address = setup();


    let dispatcher = IChainLibDispatcher { contract_address };

    // Ensure dispatcher methods exist
    let deployed = dispatcher.test_deployment();

    assert(deployed == true, 'deployment failed');
}


#[test]
fn test_create_token_bount_account() {
    let contract_address = setup();
    let dispatcher = IChainLibDispatcher { contract_address };
    
    // Test input values
    let user_name: felt252 = 'John';
    let init_param1: felt252 = 'John@yahoo.com';
    let init_param2: felt252 = 'john is a boy';
    


    // Call create_claim
    let account_id = dispatcher
        .create_token_account(user_name, init_param1, init_param2);

    // Validate that the claim ID is correctly incremented
    assert(account_id == 0, 'account_id should start from 0');

    // Retrieve the claim to verify it was stored correctly
    let token_bound_account = dispatcher.get_token_bound_account(account_id);
    assert(token_bound_account.user_name == user_name, 'namemismatch');
    assert(token_bound_account.init_param1 == init_param1, 'init_param1 mismatch');
    assert(token_bound_account.init_param2 == init_param2, 'init_param2 mismatch');
    
}
