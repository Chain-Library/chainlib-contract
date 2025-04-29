use chain_lib::interfaces::IChainLib::{IChainLib, IChainLibDispatcher, IChainLibDispatcherTrait};
use chain_lib::interfaces::ISubscription::{
    ISubscription, ISubscriptionDispatcher, ISubscriptionDispatcherTrait
};
use snforge_std::{
    CheatSpan, ContractClassTrait, DeclareResultTrait, cheat_caller_address, declare, spy_events,
    EventSpyAssertionsTrait
};
use starknet::{ContractAddress, get_block_timestamp};
use starknet::class_hash::ClassHash;
use starknet::contract_address::contract_address_const;
use starknet::testing::{set_caller_address, set_contract_address};
use chain_lib::base::types::{Role, Rank};
use chain_lib::chainlib::ChainLib::ChainLib::{Event, PaymentProcessed};


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

// Helper function to create a token-bound account for testing
fn create_test_account(dispatcher: IChainLibDispatcher) -> (u256, ContractAddress) {
    // Test input values for token-bound account
    let user_name: felt252 = 'Mark';
    let init_param1: felt252 = 'Mark@yahoo.com';
    let init_param2: felt252 = 'Mark is a boy';

    // Call account creation
    let account_id = dispatcher.create_token_account(user_name, init_param1, init_param2);

    // Get the caller's address (which will be the account owner)
    let account = dispatcher.get_token_bound_account(account_id);

    (account_id, account.address)
}

#[test]
fn test_initial_payment() {
    // Setup the contract
    let (contract_address, _) = setup();

    // Create dispatchers for both interfaces
    let chain_lib_dispatcher = IChainLibDispatcher { contract_address };
    let subscription_dispatcher = ISubscriptionDispatcher { contract_address };

    // Create a specific subscriber address and use it consistently
    let subscriber_address: ContractAddress = contract_address_const::<'subscriber'>();

    // Set the caller to the subscriber for the entire test
    cheat_caller_address(contract_address, subscriber_address, CheatSpan::Indefinite);

    // Create a token-bound account
    let user_name: felt252 = 'Mark';
    let init_param1: felt252 = 'Mark@yahoo.com';
    let init_param2: felt252 = 'Mark is a boy';
    let account_id = chain_lib_dispatcher.create_token_account(user_name, init_param1, init_param2);

    // Process an initial payment (caller is already set to subscriber)
    let amount: u256 = 100000000000000000; // 0.1 ETH in wei
    let result = subscription_dispatcher.process_initial_payment(amount, subscriber_address);

    // Verify the payment was processed successfully
    assert(result == true, 'Initial payment failed');
}

#[test]
#[should_panic(expected: 'Only subscriber can call')]
fn test_initial_payment_invalid_subscriber() {
    // Setup the contract
    let (contract_address, _) = setup();

    // Create subscription dispatcher
    let subscription_dispatcher = ISubscriptionDispatcher { contract_address };

    // Create an invalid subscriber address
    let invalid_subscriber: ContractAddress = contract_address_const::<'invalid'>();

    // Try to process payment for invalid subscriber (should fail)
    let amount: u256 = 100000000000000000; // 0.1 ETH in wei
    subscription_dispatcher.process_initial_payment(amount, invalid_subscriber);
}

#[test]
#[should_panic(expected: 'Only subscriber can call')]
fn test_initial_payment_unauthorized() {
    // Setup the contract
    let (contract_address, _) = setup();

    // Create dispatchers
    let chain_lib_dispatcher = IChainLibDispatcher { contract_address };
    let subscription_dispatcher = ISubscriptionDispatcher { contract_address };

    // Create a token-bound account
    let (_, subscriber_address) = create_test_account(chain_lib_dispatcher);

    // Create another address that is neither the subscriber nor admin
    let unauthorized_address: ContractAddress = contract_address_const::<'unauthorized'>();
    cheat_caller_address(contract_address, unauthorized_address, CheatSpan::Indefinite);

    // Try to process payment (should fail due to unauthorized caller)
    let amount: u256 = 100000000000000000; // 0.1 ETH in wei
    subscription_dispatcher.process_initial_payment(amount, subscriber_address);
}

#[test]
fn test_token_bound_account_creation() {
    // Setup the contract
    let (contract_address, _) = setup();

    // Create dispatcher
    let chain_lib_dispatcher = IChainLibDispatcher { contract_address };

    // Create a specific subscriber address
    let subscriber_address: ContractAddress = contract_address_const::<'subscriber'>();

    // Set the caller to the subscriber
    cheat_caller_address(contract_address, subscriber_address, CheatSpan::Indefinite);

    // Create a token-bound account
    let user_name: felt252 = 'Mark';
    let init_param1: felt252 = 'Mark@yahoo.com';
    let init_param2: felt252 = 'Mark is a boy';
    let account_id = chain_lib_dispatcher.create_token_account(user_name, init_param1, init_param2);

    // Verify the account was created with the correct address
    let account = chain_lib_dispatcher.get_token_bound_account(account_id);
    assert(account.address == subscriber_address, 'Account address mismatch');

    // Verify we can retrieve the account by address
    let account_by_addr = chain_lib_dispatcher.get_token_bound_account_by_owner(subscriber_address);
    assert(account_by_addr.id == account_id, 'Account not found by address');
}

#[test]
fn test_initial_payment_comprehensive() {
    // Setup the contract
    let (contract_address, _) = setup();

    // Create dispatchers
    let chain_lib_dispatcher = IChainLibDispatcher { contract_address };
    let subscription_dispatcher = ISubscriptionDispatcher { contract_address };

    // Create a specific subscriber address
    let subscriber_address: ContractAddress = contract_address_const::<'subscriber'>();

    // Set the caller to the subscriber
    cheat_caller_address(contract_address, subscriber_address, CheatSpan::Indefinite);

    // Create a token-bound account
    let user_name: felt252 = 'Mark';
    let init_param1: felt252 = 'Mark@yahoo.com';
    let init_param2: felt252 = 'Mark is a boy';
    let account_id = chain_lib_dispatcher.create_token_account(user_name, init_param1, init_param2);

    // Verify the account was created with the correct address
    let account = chain_lib_dispatcher.get_token_bound_account(account_id);
    assert(account.address == subscriber_address, 'Account address mismatch');

    // Verify we can retrieve the account by address
    let account_by_addr = chain_lib_dispatcher.get_token_bound_account_by_owner(subscriber_address);
    assert(account_by_addr.id == account_id, 'Account not found by address');

    // Process an initial payment (caller is already set to subscriber)
    let amount: u256 = 100000000000000000; // 0.1 ETH in wei
    let result = subscription_dispatcher.process_initial_payment(amount, subscriber_address);

    // Verify the payment was processed successfully
    assert(result == true, 'Initial payment failed');
}

#[test]
fn test_initial_payment_event() {
    // Setup the contract
    let (contract_address, _) = setup();

    // Create dispatchers for both interfaces
    let chain_lib_dispatcher = IChainLibDispatcher { contract_address };
    let subscription_dispatcher = ISubscriptionDispatcher { contract_address };
    
    let mut spy = spy_events();
    
    // Create a specific subscriber address and use it consistently
    let subscriber_address: ContractAddress = contract_address_const::<'subscriber'>();

    // Set the caller to the subscriber for the entire test
    cheat_caller_address(contract_address, subscriber_address, CheatSpan::Indefinite);

    // Create a token-bound account
    let user_name: felt252 = 'Mark';
    let init_param1: felt252 = 'Mark@yahoo.com';
    let init_param2: felt252 = 'Mark is a boy';
    let account_id = chain_lib_dispatcher.create_token_account(user_name, init_param1, init_param2);

    // Process an initial payment (caller is already set to subscriber)
    let amount: u256 = 100000000000000000; // 0.1 ETH in wei
    let result = subscription_dispatcher.process_initial_payment(amount, subscriber_address);

    // Verify the payment was processed successfully
    assert(result == true, 'Initial payment failed');

    // Define the variables needed for the event
    // Since this is the first payment and subscription in the test, 
    // and the contract initializes IDs at 0, the first payment and subscription will have ID 0
    let payment_id: u256 = 0;
    let subscription_id: u256 = 0;

    let expected_event = Event::PaymentProcessed(
        PaymentProcessed {
            payment_id, subscription_id, amount, subscriber: subscriber_address, timestamp: get_block_timestamp() }
    );

    spy.assert_emitted(@array![(contract_address, expected_event)]);
}
