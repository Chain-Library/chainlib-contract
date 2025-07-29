use chain_lib::base::types::{Rank, Role};
use chain_lib::chainlib::ChainLib::ChainLib::{
    Event, PaymentProcessed, PaymentVerified, RecurringPaymentProcessed, RefundProcessed,
};
use chain_lib::interfaces::IChainLib::{IChainLib, IChainLibDispatcher, IChainLibDispatcherTrait};
use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
use snforge_std::{
    CheatSpan, ContractClassTrait, DeclareResultTrait, EventSpyAssertionsTrait,
    cheat_caller_address, declare, spy_events, start_cheat_caller_address,
    stop_cheat_caller_address,
};
use starknet::class_hash::ClassHash;
use starknet::contract_address::contract_address_const;
use starknet::testing::{set_caller_address, set_contract_address};
use starknet::{ContractAddress, get_block_timestamp};
use crate::test_utils::{setup, setup_content_with_price, token_faucet_and_allowance};
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

// ********* INITIAL PAYMENT TESTS *********
// Test that the initial payment is processed successfully
#[test]
fn test_initial_payment() {
    // Setup the contract
    let (contract_address, admin_address, erc20_address) = setup();

    // Create dispatchers for both interfaces
    let chain_lib_dispatcher = IChainLibDispatcher { contract_address };
    let subscription_dispatcher = IChainLibDispatcher { contract_address };

    // Create a specific subscriber address and use it consistently
    let subscriber_address: ContractAddress = contract_address_const::<'subscriber'>();

    token_faucet_and_allowance(
        chain_lib_dispatcher, subscriber_address, erc20_address, 1000000000000000000,
    );

    // Set the caller to the subscriber for the entire test
    cheat_caller_address(contract_address, subscriber_address, CheatSpan::Indefinite);

    // Create a token-bound account
    let user_name: felt252 = 'Mark';
    let init_param1: felt252 = 'Mark@yahoo.com';
    let init_param2: felt252 = 'Mark is a boy';
    chain_lib_dispatcher.create_token_account(user_name, init_param1, init_param2);

    // Process an initial payment (caller is already set to subscriber)
    let amount: u256 = 100000000000000000; // 0.1 STRK in wei
    let result = subscription_dispatcher.process_initial_payment(amount, subscriber_address);

    // Verify the payment was processed successfully
    assert(result == true, 'Initial payment failed');
}


#[test]
#[should_panic(expected: 'Insufficient token allowance')]
fn test_initial_payment_should_panic_if_no_allowance() {
    // Setup the contract
    let (contract_address, admin_address, erc20_address) = setup();

    // Create dispatchers for both interfaces
    let chain_lib_dispatcher = IChainLibDispatcher { contract_address };
    let subscription_dispatcher = IChainLibDispatcher { contract_address };

    // Create a specific subscriber address and use it consistently
    let subscriber_address: ContractAddress = contract_address_const::<'subscriber'>();

    let token_dispatcher = IERC20Dispatcher { contract_address: erc20_address };
    // Transfer tokens from admin to user
    start_cheat_caller_address(erc20_address, admin_address);
    token_dispatcher.transfer(subscriber_address, 100000000000000000);
    stop_cheat_caller_address(erc20_address);

    // Set the caller to the subscriber for the entire test
    cheat_caller_address(contract_address, subscriber_address, CheatSpan::Indefinite);

    // Create a token-bound account
    let user_name: felt252 = 'Mark';
    let init_param1: felt252 = 'Mark@yahoo.com';
    let init_param2: felt252 = 'Mark is a boy';
    chain_lib_dispatcher.create_token_account(user_name, init_param1, init_param2);

    // Process an initial payment (caller is already set to subscriber)
    let amount: u256 = 100000000000000000; // 0.1 STRK in wei
    let result = subscription_dispatcher.process_initial_payment(amount, subscriber_address);

    // Verify the payment was processed successfully
    assert(result == true, 'Initial payment failed');
}


#[test]
#[should_panic(expected: 'Insufficient token balance')]
fn test_initial_payment_should_panic_if_insufficient_balance() {
    // Setup the contract
    let (contract_address, admin_address, erc20_address) = setup();

    // Create dispatchers for both interfaces
    let chain_lib_dispatcher = IChainLibDispatcher { contract_address };
    let subscription_dispatcher = IChainLibDispatcher { contract_address };

    // Create a specific subscriber address and use it consistently
    let subscriber_address: ContractAddress = contract_address_const::<'subscriber'>();

    let token_dispatcher = IERC20Dispatcher { contract_address: erc20_address };
    // Transfer tokens from admin to user
    start_cheat_caller_address(erc20_address, admin_address);
    token_dispatcher.transfer(subscriber_address, 1000000000);
    stop_cheat_caller_address(erc20_address);

    // Set user as caller to approve the contract
    start_cheat_caller_address(erc20_address, subscriber_address);
    token_dispatcher.approve(subscription_dispatcher.contract_address, 100000000000000000);
    stop_cheat_caller_address(erc20_address);

    // Set the caller to the subscriber for the entire test
    cheat_caller_address(contract_address, subscriber_address, CheatSpan::Indefinite);

    // Create a token-bound account
    let user_name: felt252 = 'Mark';
    let init_param1: felt252 = 'Mark@yahoo.com';
    let init_param2: felt252 = 'Mark is a boy';
    chain_lib_dispatcher.create_token_account(user_name, init_param1, init_param2);

    // Process an initial payment (caller is already set to subscriber)
    let amount: u256 = 100000000000000000; // 0.1 STRK in wei
    let result = subscription_dispatcher.process_initial_payment(amount, subscriber_address);

    // Verify the payment was processed successfully
    assert(result == true, 'Initial payment failed');
}


// Test that the initial payment fails if the caller is not the subscriber
#[test]
#[should_panic(expected: 'Only subscriber can call')]
fn test_initial_payment_invalid_subscriber() {
    // Setup the contract
    let (contract_address, admin_address, erc20_address) = setup();

    // Create subscription dispatcher
    let subscription_dispatcher = IChainLibDispatcher { contract_address };

    // Create an invalid subscriber address
    let invalid_subscriber: ContractAddress = contract_address_const::<'invalid'>();

    // Try to process payment for invalid subscriber (should fail)
    let amount: u256 = 100000000000000000; // 0.1 STRK in wei
    subscription_dispatcher.process_initial_payment(amount, invalid_subscriber);
}

// Test that the initial payment fails if the caller is not the subscriber
#[test]
#[should_panic(expected: 'Only subscriber can call')]
fn test_initial_payment_unauthorized() {
    // Setup the contract
    let (contract_address, admin_address, erc20_address) = setup();

    // Create dispatchers
    let chain_lib_dispatcher = IChainLibDispatcher { contract_address };
    let subscription_dispatcher = IChainLibDispatcher { contract_address };

    // Create a token-bound account
    let (_, subscriber_address) = create_test_account(chain_lib_dispatcher);

    // Create another address that is neither the subscriber nor admin
    let unauthorized_address: ContractAddress = contract_address_const::<'unauthorized'>();
    cheat_caller_address(contract_address, unauthorized_address, CheatSpan::Indefinite);

    // Try to process payment (should fail due to unauthorized caller)
    let amount: u256 = 100000000000000000; // 0.1 STRK in wei
    subscription_dispatcher.process_initial_payment(amount, subscriber_address);
}

// Test that the token-bound account is created successfully
#[test]
fn test_token_bound_account_creation() {
    // Setup the contract
    let (contract_address, admin_address, erc20_address) = setup();

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

// Test that the initial payment event is emitted
#[test]
fn test_initial_payment_event() {
    // Setup the contract
    let (contract_address, admin_address, erc20_address) = setup();

    // Create dispatchers for both interfaces
    let chain_lib_dispatcher = IChainLibDispatcher { contract_address };
    let subscription_dispatcher = IChainLibDispatcher { contract_address };

    let mut spy = spy_events();

    // Create a specific subscriber address and use it consistently
    let subscriber_address: ContractAddress = contract_address_const::<'subscriber'>();
    token_faucet_and_allowance(
        chain_lib_dispatcher, subscriber_address, erc20_address, 1000000000000000000,
    );
    // Set the caller to the subscriber for the entire test
    cheat_caller_address(contract_address, subscriber_address, CheatSpan::Indefinite);

    // Create a token-bound account
    let user_name: felt252 = 'Mark';
    let init_param1: felt252 = 'Mark@yahoo.com';
    let init_param2: felt252 = 'Mark is a boy';
    chain_lib_dispatcher.create_token_account(user_name, init_param1, init_param2);

    // Process an initial payment (caller is already set to subscriber)
    let amount: u256 = 100000000000000000; // 0.1 STRK in wei
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
            payment_id,
            subscription_id,
            amount,
            subscriber: subscriber_address,
            timestamp: get_block_timestamp(),
        },
    );

    spy.assert_emitted(@array![(contract_address, expected_event)]);
}


// ********* PROCESS RECURRING PAYMENT TESTS *********
// Test that the recurring payment is processed successfully
#[test]
fn test_process_recurring_payment() {
    // Setup the contract
    let (contract_address, admin_address, erc20_address) = setup();

    // Create dispatchers for both interfaces
    let chain_lib_dispatcher = IChainLibDispatcher { contract_address };
    let subscription_dispatcher = IChainLibDispatcher { contract_address };

    // Create a specific subscriber address and use it consistently
    let subscriber_address: ContractAddress = contract_address_const::<'subscriber'>();

    token_faucet_and_allowance(
        chain_lib_dispatcher, subscriber_address, erc20_address, 1000000000000000000,
    );

    // Set the caller to the subscriber for the entire test
    cheat_caller_address(contract_address, subscriber_address, CheatSpan::Indefinite);

    // Create a token-bound account
    let user_name: felt252 = 'Mark';
    let init_param1: felt252 = 'Mark@yahoo.com';
    let init_param2: felt252 = 'Mark is a boy';
    chain_lib_dispatcher.create_token_account(user_name, init_param1, init_param2);

    // Process an initial payment (caller is already set to subscriber)
    let amount: u256 = 100000000000000000; // 0.1 STRK in wei
    let result = subscription_dispatcher.process_initial_payment(amount, subscriber_address);

    // Verify the payment was processed successfully
    assert(result == true, 'Initial payment failed');

    // Now process a recurring payment
    // Since this is the first subscription, its ID is 0
    let subscription_id: u256 = 0;

    // Advance the block timestamp to simulate time passing (1 day in seconds)
    let one_day_in_seconds: u64 = 24 * 60 * 60;
    let initial_timestamp = get_block_timestamp();
    let new_timestamp = initial_timestamp + one_day_in_seconds;
    snforge_std::cheat_block_timestamp(contract_address, new_timestamp, CheatSpan::Indefinite);

    // Process the recurring payment
    let recurring_result = subscription_dispatcher.process_recurring_payment(subscription_id);

    // Verify the recurring payment was processed successfully
    assert(recurring_result == true, 'Recurring payment failed');
}


#[test]
#[should_panic(expected: 'Contract is paused')]
fn test_process_recurring_payment_should_panic_if_contract_paused() {
    // Setup the contract
    let (contract_address, admin_address, erc20_address) = setup();

    // Create dispatchers for both interfaces
    let chain_lib_dispatcher = IChainLibDispatcher { contract_address };
    let subscription_dispatcher = IChainLibDispatcher { contract_address };

    // Create a specific subscriber address and use it consistently
    let subscriber_address: ContractAddress = contract_address_const::<'subscriber'>();

    token_faucet_and_allowance(
        chain_lib_dispatcher, subscriber_address, erc20_address, 1000000000000000000,
    );

    // Set the caller to the subscriber for the entire test
    cheat_caller_address(contract_address, subscriber_address, CheatSpan::Indefinite);

    // Create a token-bound account
    let user_name: felt252 = 'Mark';
    let init_param1: felt252 = 'Mark@yahoo.com';
    let init_param2: felt252 = 'Mark is a boy';
    chain_lib_dispatcher.create_token_account(user_name, init_param1, init_param2);

    // Process an initial payment (caller is already set to subscriber)
    let amount: u256 = 100000000000000000; // 0.1 STRK in wei
    let result = subscription_dispatcher.process_initial_payment(amount, subscriber_address);

    // Verify the payment was processed successfully
    assert(result == true, 'Initial payment failed');

    // Now process a recurring payment
    // Since this is the first subscription, its ID is 0
    let subscription_id: u256 = 0;

    // Advance the block timestamp to simulate time passing (1 day in seconds)
    let one_day_in_seconds: u64 = 24 * 60 * 60;
    let initial_timestamp = get_block_timestamp();
    let new_timestamp = initial_timestamp + one_day_in_seconds;
    snforge_std::cheat_block_timestamp(contract_address, new_timestamp, CheatSpan::Indefinite);

    start_cheat_caller_address(contract_address, admin_address);
    subscription_dispatcher.emergency_pause();
    stop_cheat_caller_address(contract_address);

    // Process the recurring payment
    subscription_dispatcher.process_recurring_payment(subscription_id);
}

#[test]
#[should_panic(expected: 'Insufficient token allowance')]
fn test_process_recurring_payment_should_panic_if_insufficient_allowance() {
    // Setup the contract
    let (contract_address, admin_address, erc20_address) = setup();

    // Create dispatchers for both interfaces
    let chain_lib_dispatcher = IChainLibDispatcher { contract_address };
    let subscription_dispatcher = IChainLibDispatcher { contract_address };

    // Create a specific subscriber address and use it consistently
    let subscriber_address: ContractAddress = contract_address_const::<'subscriber'>();

    let token_dispatcher = IERC20Dispatcher { contract_address: erc20_address };
    // Transfer tokens from admin to user
    start_cheat_caller_address(erc20_address, admin_address);
    token_dispatcher.transfer(subscriber_address, 1000000000);
    stop_cheat_caller_address(erc20_address);

    // Set the caller to the subscriber for the entire test
    cheat_caller_address(contract_address, subscriber_address, CheatSpan::Indefinite);

    // Create a token-bound account
    let user_name: felt252 = 'Mark';
    let init_param1: felt252 = 'Mark@yahoo.com';
    let init_param2: felt252 = 'Mark is a boy';
    chain_lib_dispatcher.create_token_account(user_name, init_param1, init_param2);

    // Process an initial payment (caller is already set to subscriber)
    let amount: u256 = 100000000000000000; // 0.1 STRK in wei
    let result = subscription_dispatcher.process_initial_payment(amount, subscriber_address);
}


#[test]
#[should_panic(expected: 'Insufficient token balance')]
fn test_process_recurring_payment_should_panic_if_insufficient_balance() {
    // Setup the contract
    let (contract_address, admin_address, erc20_address) = setup();

    // Create dispatchers for both interfaces
    let chain_lib_dispatcher = IChainLibDispatcher { contract_address };
    let subscription_dispatcher = IChainLibDispatcher { contract_address };

    // Create a specific subscriber address and use it consistently
    let subscriber_address: ContractAddress = contract_address_const::<'subscriber'>();

    let token_dispatcher = IERC20Dispatcher { contract_address: erc20_address };
    // Transfer tokens from admin to user
    start_cheat_caller_address(erc20_address, admin_address);
    token_dispatcher.transfer(subscriber_address, 1000000000);
    stop_cheat_caller_address(erc20_address);

    // Set user as caller to approve the contract
    start_cheat_caller_address(erc20_address, subscriber_address);
    token_dispatcher.approve(subscription_dispatcher.contract_address, 100000000000000000);
    stop_cheat_caller_address(erc20_address);

    // Set the caller to the subscriber for the entire test
    cheat_caller_address(contract_address, subscriber_address, CheatSpan::Indefinite);

    // Create a token-bound account
    let user_name: felt252 = 'Mark';
    let init_param1: felt252 = 'Mark@yahoo.com';
    let init_param2: felt252 = 'Mark is a boy';
    chain_lib_dispatcher.create_token_account(user_name, init_param1, init_param2);

    // Process an initial payment (caller is already set to subscriber)
    let amount: u256 = 100000000000000000; // 0.1 STRK in wei
    let result = subscription_dispatcher.process_initial_payment(amount, subscriber_address);
}

// test should panic if payment not due yet
#[test]
#[should_panic(expected: 'Payment not due yet')]
fn test_process_recurring_payment_not_due() {
    // Setup the contract
    let (contract_address, admin_address, erc20_address) = setup();

    // Create dispatchers for both interfaces
    let chain_lib_dispatcher = IChainLibDispatcher { contract_address };
    let subscription_dispatcher = IChainLibDispatcher { contract_address };

    // Create a specific subscriber address and use it consistently
    let subscriber_address: ContractAddress = contract_address_const::<'subscriber'>();

    token_faucet_and_allowance(
        chain_lib_dispatcher, subscriber_address, erc20_address, 1000000000000000000,
    );

    // Set the caller to the subscriber for the entire test
    cheat_caller_address(contract_address, subscriber_address, CheatSpan::Indefinite);

    // Create a token-bound account
    let user_name: felt252 = 'Mark';
    let init_param1: felt252 = 'Mark@yahoo.com';
    let init_param2: felt252 = 'Mark is a boy';
    chain_lib_dispatcher.create_token_account(user_name, init_param1, init_param2);

    // Process an initial payment (caller is already set to subscriber)
    let amount: u256 = 100000000000000000; // 0.1 STRK in wei
    let result = subscription_dispatcher.process_initial_payment(amount, subscriber_address);

    // Verify the payment was processed successfully
    assert(result == true, 'Initial payment failed');

    // Now process a recurring payment
    // Since this is the first subscription, its ID is 0
    let subscription_id: u256 = 0;

    // Process the recurring payment - this should fail because payment is not due yet
    subscription_dispatcher.process_recurring_payment(subscription_id);
}

// Test that the function panics when subscription is not found
#[test]
#[should_panic(expected: 'Subscription not found')]
fn test_process_recurring_payment_not_found() {
    // Setup the contract
    let (contract_address, admin_address, erc20_address) = setup();

    // Create dispatchers for both interfaces
    let subscription_dispatcher = IChainLibDispatcher { contract_address };

    // Create a specific subscriber address and use it consistently
    let subscriber_address: ContractAddress = contract_address_const::<'subscriber'>();

    // Set the caller to the subscriber for the entire test
    cheat_caller_address(contract_address, subscriber_address, CheatSpan::Indefinite);

    // Try to process a recurring payment for a non-existent subscription ID
    // This should panic with "Subscription not found"
    let non_existent_subscription_id: u256 = 999;
    subscription_dispatcher.process_recurring_payment(non_existent_subscription_id);
}

// test for recurring payment events
#[test]
fn test_process_recurring_payment_event() {
    // Setup the contract
    let (contract_address, admin_address, erc20_address) = setup();

    // Create dispatchers for both interfaces
    let chain_lib_dispatcher = IChainLibDispatcher { contract_address };
    let subscription_dispatcher = IChainLibDispatcher { contract_address };

    let mut spy = spy_events();

    // Create a specific subscriber address and use it consistently
    let subscriber_address: ContractAddress = contract_address_const::<'subscriber'>();

    // Set the caller to the subscriber for the entire test
    cheat_caller_address(contract_address, subscriber_address, CheatSpan::Indefinite);

    token_faucet_and_allowance(
        chain_lib_dispatcher, subscriber_address, erc20_address, 1000000000000000000,
    );

    // Create a token-bound account
    let user_name: felt252 = 'Mark';
    let init_param1: felt252 = 'Mark@yahoo.com';
    let init_param2: felt252 = 'Mark is a boy';
    chain_lib_dispatcher.create_token_account(user_name, init_param1, init_param2);

    // Process an initial payment (caller is already set to subscriber)
    let amount: u256 = 100000000000000000; // 0.1 ETH in wei
    let result = subscription_dispatcher.process_initial_payment(amount, subscriber_address);

    // Verify the payment was processed successfully
    assert(result == true, 'Initial payment failed');

    // Now process a recurring payment
    // Since this is the first subscription, its ID is 0
    let subscription_id: u256 = 0;

    // Advance the block timestamp to simulate time passing (1 day in seconds)
    let one_day_in_seconds: u64 = 24 * 60 * 60;
    let initial_timestamp = get_block_timestamp();
    let new_timestamp = initial_timestamp + one_day_in_seconds;
    snforge_std::cheat_block_timestamp(contract_address, new_timestamp, CheatSpan::Indefinite);

    // Process the recurring payment
    let recurring_result = subscription_dispatcher.process_recurring_payment(subscription_id);

    // Verify the recurring payment was processed successfully
    assert(recurring_result == true, 'Recurring payment failed');

    // The payment ID for the recurring payment should be 1 (since the initial payment used ID 0)
    let payment_id: u256 = 1;

    let expected_event = Event::RecurringPaymentProcessed(
        RecurringPaymentProcessed {
            payment_id,
            subscription_id,
            amount,
            subscriber: subscriber_address,
            timestamp: new_timestamp,
        },
    );

    spy.assert_emitted(@array![(contract_address, expected_event)]);
}

// ********* VERIFY PAYMENT TESTS *********
// Test that only admin can verify payments
#[test]
#[should_panic(expected: 'Only admin can verify payments')]
fn test_verify_payment_admin_only() {
    // Setup the contract
    let (contract_address, admin_address, erc20_address) = setup();

    // Create dispatchers for both interfaces
    let chain_lib_dispatcher = IChainLibDispatcher { contract_address };
    let subscription_dispatcher = IChainLibDispatcher { contract_address };

    // Create a specific subscriber address and use it consistently
    let subscriber_address: ContractAddress = contract_address_const::<'subscriber'>();

    // Set the caller to the subscriber for creating a subscription
    cheat_caller_address(contract_address, subscriber_address, CheatSpan::Indefinite);
    token_faucet_and_allowance(
        chain_lib_dispatcher, subscriber_address, erc20_address, 1000000000000000000,
    );

    // Create a token-bound account
    let user_name: felt252 = 'Mark';
    let init_param1: felt252 = 'Mark@yahoo.com';
    let init_param2: felt252 = 'Mark is a boy';
    chain_lib_dispatcher.create_token_account(user_name, init_param1, init_param2);

    // Process an initial payment (caller is already set to subscriber)
    let amount: u256 = 100000000000000000; // 0.1 STRK in wei
    let result = subscription_dispatcher.process_initial_payment(amount, subscriber_address);

    // Verify the payment was processed successfully
    assert(result == true, 'Initial payment failed');

    // The payment ID for the initial payment should be 0
    let payment_id: u256 = 0;

    // Try to verify the payment as a non-admin (should panic)
    // We're still using the subscriber address as the caller
    subscription_dispatcher.verify_payment(payment_id);

    // This line should not be reached because the function should panic
    assert(false, 'Should have panicked');
}

#[test]
#[should_panic(expected: '')]
fn test_verify_payment_should_panic_if_contract_paused() {
    // Setup the contract
    let (contract_address, admin_address, erc20_address) = setup();

    // Create dispatchers for both interfaces
    let chain_lib_dispatcher = IChainLibDispatcher { contract_address };
    let subscription_dispatcher = IChainLibDispatcher { contract_address };

    // Create a specific subscriber address and use it consistently
    let subscriber_address: ContractAddress = contract_address_const::<'subscriber'>();

    // Set the caller to the subscriber for creating a subscription
    cheat_caller_address(contract_address, subscriber_address, CheatSpan::Indefinite);
    token_faucet_and_allowance(
        chain_lib_dispatcher, subscriber_address, erc20_address, 1000000000000000000,
    );

    // Create a token-bound account
    let user_name: felt252 = 'Mark';
    let init_param1: felt252 = 'Mark@yahoo.com';
    let init_param2: felt252 = 'Mark is a boy';
    chain_lib_dispatcher.create_token_account(user_name, init_param1, init_param2);

    // Process an initial payment (caller is already set to subscriber)
    let amount: u256 = 100000000000000000; // 0.1 STRK in wei
    let result = subscription_dispatcher.process_initial_payment(amount, subscriber_address);

    // Verify the payment was processed successfully
    assert(result == true, 'Initial payment failed');

    // The payment ID for the initial payment should be 0
    let payment_id: u256 = 0;

    start_cheat_caller_address(contract_address, admin_address);
    subscription_dispatcher.emergency_pause();

    subscription_dispatcher.verify_payment(payment_id);

    stop_cheat_caller_address(contract_address);
}

// Test that the function panics when payment is not found
#[test]
#[should_panic(expected: 'Payment not found')]
fn test_verify_payment_not_found() {
    // Setup the contract
    let (contract_address, admin_address, erc20_address) = setup();

    // Create dispatchers for both interfaces
    let _chain_lib_dispatcher = IChainLibDispatcher { contract_address };
    let subscription_dispatcher = IChainLibDispatcher { contract_address };

    // Switch to admin before verifying the payment
    cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);

    // Try to verify a payment that doesn't exist
    let non_existent_payment_id: u256 = 999;
    subscription_dispatcher.verify_payment(non_existent_payment_id);

    // This line should not be reached because the function should panic
    assert(false, 'Should have panicked');
}

// Test that the function verifies a payment successfully
#[test]
#[should_panic(expected: 'Payment already verified')]
fn test_verify_payment_success() {
    // Setup the contract
    let (contract_address, admin_address, erc20_address) = setup();

    // Create dispatchers for both interfaces
    let chain_lib_dispatcher = IChainLibDispatcher { contract_address };
    let subscription_dispatcher = IChainLibDispatcher { contract_address };

    // Create a specific subscriber address and use it consistently
    let subscriber_address: ContractAddress = contract_address_const::<'subscriber'>();

    token_faucet_and_allowance(
        chain_lib_dispatcher, subscriber_address, erc20_address, 1000000000000000000,
    );
    // Set the caller to the subscriber for creating a subscription
    cheat_caller_address(contract_address, subscriber_address, CheatSpan::Indefinite);

    // Create a token-bound account
    let user_name: felt252 = 'Mark';
    let init_param1: felt252 = 'Mark@yahoo.com';
    let init_param2: felt252 = 'Mark is a boy';
    chain_lib_dispatcher.create_token_account(user_name, init_param1, init_param2);

    // Process an initial payment (caller is already set to subscriber)
    let amount: u256 = 100000000000000000; // 0.1 STRK in wei
    let result = subscription_dispatcher.process_initial_payment(amount, subscriber_address);

    // Verify the payment was processed successfully
    assert(result == true, 'Initial payment failed');

    // Switch to admin for the rest of the test
    cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);

    // The payment ID for the initial payment should be 0
    let payment_id: u256 = 0;

    // Try to verify the payment - this should fail because initial payments are auto-verified
    // This will panic with 'Payment already verified'
    subscription_dispatcher.verify_payment(payment_id);
}

// Test that the PaymentVerified event is emitted when processing an initial payment
#[test]
fn test_verify_payment_event() {
    // Setup the contract
    let (contract_address, admin_address, erc20_address) = setup();

    // Create dispatchers for both interfaces
    let chain_lib_dispatcher = IChainLibDispatcher { contract_address };
    let subscription_dispatcher = IChainLibDispatcher { contract_address };

    // Set up event spy to capture verification event
    let mut spy = spy_events();

    // Create a specific subscriber address and use it consistently
    let subscriber_address: ContractAddress = contract_address_const::<'subscriber'>();

    token_faucet_and_allowance(
        chain_lib_dispatcher, subscriber_address, erc20_address, 1000000000000000000,
    );

    // Set the caller to the subscriber for creating a subscription
    cheat_caller_address(contract_address, subscriber_address, CheatSpan::Indefinite);

    // Create a token-bound account
    let user_name: felt252 = 'Mark';
    let init_param1: felt252 = 'Mark@yahoo.com';
    let init_param2: felt252 = 'Mark is a boy';
    chain_lib_dispatcher.create_token_account(user_name, init_param1, init_param2);

    // Process an initial payment (caller is already set to subscriber)
    let amount: u256 = 100000000000000000; // 0.1 STRK in wei
    let result = subscription_dispatcher.process_initial_payment(amount, subscriber_address);

    // Verify the payment was processed successfully
    assert(result == true, 'Initial payment failed');

    // The payment ID for the initial payment should be 0
    let payment_id: u256 = 0;

    // The subscription ID for the first subscription should be 0
    let subscription_id: u256 = 0;

    // Check that the PaymentProcessed event was emitted
    // This is a different event than PaymentVerified, but we can test that it was emitted
    // since we can't test PaymentVerified directly (payments are auto-verified)
    let timestamp = get_block_timestamp();

    let expected_event = Event::PaymentProcessed(
        PaymentProcessed {
            payment_id, subscription_id, subscriber: subscriber_address, amount, timestamp,
        },
    );

    spy.assert_emitted(@array![(contract_address, expected_event)]);
}

// ********* PROCESS REFUND TESTS *********
#[test]
#[should_panic(expected: 'Only admin can process refunds')]
fn test_process_refund_admin_only() {
    // Setup the contract
    let (contract_address, admin_address, erc20_address) = setup();

    // Create dispatchers for both interfaces
    let chain_lib_dispatcher = IChainLibDispatcher { contract_address };
    let subscription_dispatcher = IChainLibDispatcher { contract_address };

    // Create a specific subscriber address and use it consistently
    let subscriber_address: ContractAddress = contract_address_const::<'subscriber'>();

    token_faucet_and_allowance(
        chain_lib_dispatcher, subscriber_address, erc20_address, 1000000000000000000,
    );

    // Set the caller to the subscriber for creating a subscription
    cheat_caller_address(contract_address, subscriber_address, CheatSpan::Indefinite);

    // Create a token-bound account
    let user_name: felt252 = 'Mark';
    let init_param1: felt252 = 'Mark@yahoo.com';
    let init_param2: felt252 = 'Mark is a boy';
    chain_lib_dispatcher.create_token_account(user_name, init_param1, init_param2);

    // Process an initial payment (caller is already set to subscriber)
    let amount: u256 = 100000000000000000; // 0.1 STRK in wei
    let result = subscription_dispatcher.process_initial_payment(amount, subscriber_address);

    // Verify the payment was processed successfully
    assert(result == true, 'Initial payment failed');

    // Since this is the first subscription, its ID is 0
    let subscription_id: u256 = 0;

    // Try to process a refund as a non-admin (should panic)
    // We're still using the subscriber address as the caller
    subscription_dispatcher.process_refund(subscription_id);

    // This line should not be reached because the function should panic
    assert(false, 'Should have panicked');
}

#[test]
#[should_panic(expected: 'Contract is paused')]
fn test_process_refund_should_panic_if_contract_paused() {
    // Setup the contract
    let (contract_address, admin_address, erc20_address) = setup();

    // Create dispatchers for both interfaces
    let chain_lib_dispatcher = IChainLibDispatcher { contract_address };
    let subscription_dispatcher = IChainLibDispatcher { contract_address };

    // Create a specific subscriber address and use it consistently
    let subscriber_address: ContractAddress = contract_address_const::<'subscriber'>();

    token_faucet_and_allowance(
        chain_lib_dispatcher, subscriber_address, erc20_address, 1000000000000000000,
    );

    // Set the caller to the subscriber for creating a subscription
    cheat_caller_address(contract_address, subscriber_address, CheatSpan::Indefinite);

    // Create a token-bound account
    let user_name: felt252 = 'Mark';
    let init_param1: felt252 = 'Mark@yahoo.com';
    let init_param2: felt252 = 'Mark is a boy';
    chain_lib_dispatcher.create_token_account(user_name, init_param1, init_param2);

    // Process an initial payment (caller is already set to subscriber)
    let amount: u256 = 100000000000000000; // 0.1 STRK in wei
    let result = subscription_dispatcher.process_initial_payment(amount, subscriber_address);

    // Verify the payment was processed successfully
    assert(result == true, 'Initial payment failed');

    // Since this is the first subscription, its ID is 0
    let subscription_id: u256 = 0;

    start_cheat_caller_address(contract_address, admin_address);
    subscription_dispatcher.emergency_pause();

    subscription_dispatcher.process_refund(subscription_id);
    stop_cheat_caller_address(contract_address);
}
// Test that the function panics when subscription is not found
#[test]
#[should_panic(expected: 'Subscription not found')]
fn test_process_refund_subscription_not_found() {
    // Setup the contract
    let (contract_address, admin_address, erc20_address) = setup();

    // Create dispatchers for both interfaces
    let _chain_lib_dispatcher = IChainLibDispatcher { contract_address };
    let subscription_dispatcher = IChainLibDispatcher { contract_address };

    // Switch to admin before processing the refund
    cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);

    // Try to refund a subscription that doesn't exist
    let non_existent_subscription_id: u256 = 999;
    subscription_dispatcher.process_refund(non_existent_subscription_id);

    // This line should not be reached because the function should panic
    assert(false, 'Should have panicked');
}

// Test that the function successfully processes a refund
#[test]
fn test_process_refund_success() {
    // Setup the contract
    let (contract_address, admin_address, erc20_address) = setup();

    // Create dispatchers for both interfaces
    let chain_lib_dispatcher = IChainLibDispatcher { contract_address };
    let subscription_dispatcher = IChainLibDispatcher { contract_address };

    // Create a specific subscriber address and use it consistently
    let subscriber_address: ContractAddress = contract_address_const::<'subscriber'>();
    token_faucet_and_allowance(
        chain_lib_dispatcher, subscriber_address, erc20_address, 1000000000000000000,
    );

    // Set the caller to the subscriber for creating a subscription
    cheat_caller_address(contract_address, subscriber_address, CheatSpan::Indefinite);

    // Create a token-bound account
    let user_name: felt252 = 'Mark';
    let init_param1: felt252 = 'Mark@yahoo.com';
    let init_param2: felt252 = 'Mark is a boy';
    chain_lib_dispatcher.create_token_account(user_name, init_param1, init_param2);

    // Process an initial payment (caller is already set to subscriber)
    let amount: u256 = 100000000000000000; // 0.1 STRK in wei
    let result = subscription_dispatcher.process_initial_payment(amount, subscriber_address);

    // Verify the payment was processed successfully
    assert(result == true, 'Initial payment failed');

    // Since this is the first subscription, its ID is 0
    let subscription_id: u256 = 0;

    // Switch to admin for the rest of the test
    cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);

    // Process a refund
    let refund_result = subscription_dispatcher.process_refund(subscription_id);

    // Verify the refund was processed successfully
    assert(refund_result == true, 'Refund processing failed');
}

// Test that the function panics when trying to refund an already refunded payment
#[test]
#[should_panic(expected: 'Subscription not active')]
fn test_process_refund_already_refunded() {
    // Setup the contract
    let (contract_address, admin_address, erc20_address) = setup();

    // Create dispatchers for both interfaces
    let chain_lib_dispatcher = IChainLibDispatcher { contract_address };
    let subscription_dispatcher = IChainLibDispatcher { contract_address };

    // Create a specific subscriber address and use it consistently
    let subscriber_address: ContractAddress = contract_address_const::<'subscriber'>();
    token_faucet_and_allowance(
        chain_lib_dispatcher, subscriber_address, erc20_address, 1000000000000000000,
    );
    // Set the caller to the subscriber for creating a subscription
    cheat_caller_address(contract_address, subscriber_address, CheatSpan::Indefinite);

    // Create a token-bound account
    let user_name: felt252 = 'Mark';
    let init_param1: felt252 = 'Mark@yahoo.com';
    let init_param2: felt252 = 'Mark is a boy';
    chain_lib_dispatcher.create_token_account(user_name, init_param1, init_param2);

    // Process an initial payment (caller is already set to subscriber)
    let amount: u256 = 100000000000000000; // 0.1 STRK in wei
    let result = subscription_dispatcher.process_initial_payment(amount, subscriber_address);

    // Verify the payment was processed successfully
    assert(result == true, 'Initial payment failed');

    // Since this is the first subscription, its ID is 0
    let subscription_id: u256 = 0;

    // Switch to admin for the rest of the test
    cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);

    // Process a refund
    let refund_result = subscription_dispatcher.process_refund(subscription_id);

    // Verify the refund was processed successfully
    assert(refund_result == true, 'First refund processing failed');

    // Try to process another refund for the same subscription
    // This should fail because the subscription is no longer active
    subscription_dispatcher.process_refund(subscription_id);

    // This line should not be reached because the function should panic
    assert(false, 'Should have panicked');
}

// Test that the RefundProcessed event is emitted when processing a refund
#[test]
fn test_process_refund_event() {
    // Setup the contract
    let (contract_address, admin_address, erc20_address) = setup();

    // Create dispatchers for both interfaces
    let chain_lib_dispatcher = IChainLibDispatcher { contract_address };
    let subscription_dispatcher = IChainLibDispatcher { contract_address };

    // Create a specific subscriber address and use it consistently
    let subscriber_address: ContractAddress = contract_address_const::<'subscriber'>();

    // Set the caller to the subscriber for creating a subscription
    cheat_caller_address(contract_address, subscriber_address, CheatSpan::Indefinite);

    // Create a token-bound account
    let user_name: felt252 = 'Mark';
    let init_param1: felt252 = 'Mark@yahoo.com';
    let init_param2: felt252 = 'Mark is a boy';
    chain_lib_dispatcher.create_token_account(user_name, init_param1, init_param2);

    token_faucet_and_allowance(
        chain_lib_dispatcher, subscriber_address, erc20_address, 1000000000000000000,
    );

    // Process an initial payment (caller is already set to subscriber)
    let amount: u256 = 100000000000000000; // 0.1 STRK in wei
    let result = subscription_dispatcher.process_initial_payment(amount, subscriber_address);

    // Verify the payment was processed successfully
    assert(result == true, 'Initial payment failed');

    // Since this is the first subscription, its ID is 0
    let subscription_id: u256 = 0;

    // The payment ID for the initial payment should be 0
    let payment_id: u256 = 0;

    // Set up event spy to capture refund event
    let mut spy = spy_events();

    // Switch to admin for the rest of the test
    cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);

    // Process a refund
    let refund_result = subscription_dispatcher.process_refund(subscription_id);

    // Verify the refund was processed successfully
    assert(refund_result == true, 'Refund processing failed');

    // Check that the RefundProcessed event was emitted
    let timestamp = get_block_timestamp();

    let expected_event = Event::RefundProcessed(
        RefundProcessed { payment_id, subscription_id, amount, timestamp },
    );

    spy.assert_emitted(@array![(contract_address, expected_event)]);
}
