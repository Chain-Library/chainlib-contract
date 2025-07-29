use ChainLib::ChainLib::{EmergencyPaused, EmergencyUnpause};
// Import the contract modules
use chain_lib::base::types::{
    PurchaseStatus, Rank, Refund, RefundRequestReason, RefundStatus, Role, Status,
};
use chain_lib::chainlib::ChainLib;
use chain_lib::chainlib::ChainLib::ChainLib::{Category, ContentType, PlanType, SubscriptionStatus};
use chain_lib::interfaces::IChainLib::{IChainLib, IChainLibDispatcher, IChainLibDispatcherTrait};
use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
use snforge_std::{
    CheatSpan, ContractClassTrait, DeclareResultTrait, EventSpyAssertionsTrait,
    cheat_block_timestamp, cheat_caller_address, declare, spy_events, start_cheat_block_timestamp,
    start_cheat_caller_address, stop_cheat_block_timestamp, stop_cheat_caller_address,
};
use starknet::class_hash::ClassHash;
use starknet::contract_address::contract_address_const;
use starknet::testing::{set_caller_address, set_contract_address};
use starknet::{ContractAddress, get_block_timestamp};
use crate::test_utils::{setup, setup_content_with_price, token_faucet_and_allowance};

#[test]
fn test_initial_data() {
    let (contract_address, admin_address, erc20_address) = setup();

    let dispatcher = IChainLibDispatcher { contract_address };

    // Ensure dispatcher methods exist
    let admin = dispatcher.getAdmin();

    assert(admin == admin_address, 'deployment failed');
}


#[test]
fn test_create_token_bount_account() {
    let (contract_address, _, erc20_address) = setup();
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
    let (contract_address, _, erc20_address) = setup();
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
#[should_panic(expected: 'Contract is paused')]
fn test_create_user_should_panic_if_contract_paused() {
    let (contract_address, admin_address, erc20_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Test input values
    let username: felt252 = 'John';
    let role: Role = Role::READER;
    let rank: Rank = Rank::BEGINNER;
    let metadata: felt252 = 'john is a boy';

    start_cheat_caller_address(contract_address, admin_address);
    dispatcher.emergency_pause();
    stop_cheat_caller_address(contract_address);
    dispatcher.register_user(username, role.clone(), rank.clone(), metadata);
}

#[test]
fn test_verify_user() {
    let (contract_address, admin_address, erc20_address) = setup();
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
fn test_update_user() {
    let (contract_address, _, erc20_address) = setup();
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

    let updated_wallet_Address = contract_address_const::<'user'>();
    let updated_username: felt252 = 'John';
    let updated_metadata: felt252 = 'john is a man now';
    let updated_role = Role::READER;
    let updated_rank = Rank::BEGINNER;
    // Update user data
    dispatcher
        .update_user_profile(
            account_id,
            updated_username,
            updated_wallet_Address,
            updated_role,
            updated_rank,
            updated_metadata,
        );

    // Retrieve the updated user to verify it was stored correctly
    let updated_user = dispatcher.retrieve_user_profile(account_id);
    assert(updated_user.username == username, 'username mismatch');
    assert(updated_user.role == role, 'role mismatch');
    assert(updated_user.rank == rank, 'rank mismatch');
    assert(updated_user.metadata == updated_metadata, 'metadata mismatch');
    assert(!updated_user.verified, 'already verified');
}


#[test]
#[should_panic(expected: 'Contract is paused')]
fn test_update_user_should_panic_if_contract_paused() {
    let (contract_address, admin_address, erc20_address) = setup();
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

    let updated_wallet_Address = contract_address_const::<'user'>();
    let updated_username: felt252 = 'John';
    let updated_metadata: felt252 = 'john is a man now';
    let updated_role = Role::READER;
    let updated_rank = Rank::BEGINNER;

    start_cheat_caller_address(contract_address, admin_address);
    dispatcher.emergency_pause();
    stop_cheat_caller_address(contract_address);

    // Update user data
    dispatcher
        .update_user_profile(
            account_id,
            updated_username,
            updated_wallet_Address,
            updated_role,
            updated_rank,
            updated_metadata,
        );
}

#[test]
fn test_deactivate_user() {
    let (contract_address, _, erc20_address) = setup();
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

    dispatcher.deactivate_profile(account_id);
    let user_deactivated = dispatcher.retrieve_user_profile(account_id);
    assert(user_deactivated.status == Status::DEACTIVATED, 'User should be deactivated');
}


#[test]
#[should_panic(expected: 'Contract is paused')]
fn test_deactivate_user_should_panic_if_contract_paused() {
    let (contract_address, admin_address, erc20_address) = setup();
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

    start_cheat_caller_address(contract_address, admin_address);
    dispatcher.emergency_pause();
    stop_cheat_caller_address(contract_address);

    dispatcher.deactivate_profile(account_id);
}

#[test]
#[should_panic]
fn test_deactivate_user_should_panic_if_diffrent_Address() {
    let (contract_address, _, erc20_address) = setup();
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

    start_cheat_caller_address(contract_address, contract_address_const::<'0x123'>());
    dispatcher.deactivate_profile(account_id);
    assert(user.status == Status::DEACTIVATED, 'User should be deactivated');
}


#[test]
#[should_panic]
fn test_update_user_should_panic_when_address_is_0() {
    let (contract_address, _, erc20_address) = setup();
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

    let updated_wallet_Address = contract_address_const::<0>();
    let updated_username: felt252 = 'John';
    let updated_metadata: felt252 = 'john is a man now';
    let updated_role = Role::READER;
    let updated_rank = Rank::BEGINNER;
    // Update user data
    dispatcher
        .update_user_profile(
            account_id,
            updated_username,
            updated_wallet_Address,
            updated_role,
            updated_rank,
            updated_metadata,
        );
}

#[test]
#[should_panic(expected: 'Only admin can verify users')]
fn test_verify_user_not_admin() {
    let (contract_address, _, erc20_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Test input values
    let username: felt252 = 'John';
    let role: Role = Role::READER;
    let rank: Rank = Rank::BEGINNER;
    let metadata: felt252 = 'john is a boy';

    // Call register
    let account_id = dispatcher.register_user(username, role.clone(), rank.clone(), metadata);
    // Retrieve the user to verify user was stored correctly
    let user = dispatcher.retrieve_user_profile(account_id);
    assert(!user.verified, 'already verified');

    let verify = dispatcher.verify_user(user.id);
    assert(verify, 'Verification Falied');

    let verified_user = dispatcher.retrieve_user_profile(account_id);
    assert(verified_user.verified, 'Not Verified');
}

#[test]
fn test_create_subscription() {
    let (contract_address, _, erc20_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Test input values
    let username: felt252 = 'John';
    let role: Role = Role::READER;
    let rank: Rank = Rank::BEGINNER;
    let metadata: felt252 = 'john is a boy';

    // Call register
    let account_id = dispatcher.register_user(username, role.clone(), rank.clone(), metadata);

    dispatcher.create_subscription(account_id, 500, 1);
    let subscription = dispatcher.get_user_subscription(account_id);
    assert(subscription.id == 1, 'Subscription ID should be 1');
    assert(subscription.subscription_type == PlanType::YEARLY, 'Plan type should be YEARLY');
    assert(subscription.status == SubscriptionStatus::Active, 'Plan type should be YEARLY');
    let subscription_record = dispatcher.get_user_subscription_record(account_id);
    assert(subscription_record.len() == 1, 'record should have length 1');
}


#[test]
#[should_panic(expected: 'Contract is paused')]
fn test_create_subscription_should_panic_if_contract_paused() {
    let (contract_address, admin_address, erc20_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Test input values
    let username: felt252 = 'John';
    let role: Role = Role::READER;
    let rank: Rank = Rank::BEGINNER;
    let metadata: felt252 = 'john is a boy';

    // Call register
    let account_id = dispatcher.register_user(username, role.clone(), rank.clone(), metadata);

    start_cheat_caller_address(contract_address, admin_address);
    dispatcher.emergency_pause();
    stop_cheat_caller_address(contract_address);

    dispatcher.create_subscription(account_id, 500, 1);
}

#[test]
#[should_panic(expected: 'User does not exist')]
fn test_create_subscription_invalid_user() {
    let (contract_address, _, erc20_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Test input values
    let username: felt252 = 'John';
    let role: Role = Role::READER;
    let rank: Rank = Rank::BEGINNER;
    let metadata: felt252 = 'john is a boy';

    // Call register
    let account_id = dispatcher.register_user(username, role.clone(), rank.clone(), metadata);

    dispatcher.create_subscription(20, 500, 2);
    let subscription = dispatcher.get_user_subscription(account_id);
    assert(subscription.id == 1, 'Subscription ID should be 1');
}

#[test]
#[should_panic(expected: "Only WRITER can post content")]
fn test_grant_premium_access_test_admin() {
    let (contract_address, admin, erc20_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Test input values
    let username: felt252 = 'John';
    let role: Role = Role::READER;
    let rank: Rank = Rank::BEGINNER;
    let metadata: felt252 = 'john is a boy';

    let title: felt252 = 'My Content';
    let description: felt252 = 'This is a test content';
    let content_type: ContentType = ContentType::Text;
    let category: Category = Category::Education;

    let content_id = dispatcher.register_content(title, description, content_type, category);

    // Call register
    let account_id = dispatcher.register_user(username, role.clone(), rank.clone(), metadata);

    start_cheat_caller_address(contract_address, admin);
    let access = dispatcher.grant_premium_access(account_id, content_id);
    assert(access, 'Access granted');
}


#[test]
#[should_panic(expected: 'Contract is paused')]
fn test_grant_premium_access_should_panic_if_contract_paused() {
    let (contract_address, admin, erc20_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Test input values
    let username: felt252 = 'John';
    let role: Role = Role::WRITER;
    let rank: Rank = Rank::BEGINNER;
    let metadata: felt252 = 'john is a boy';

    let title: felt252 = 'My Content';
    let description: felt252 = 'This is a test content';
    let content_type: ContentType = ContentType::Text;
    let category: Category = Category::Education;

    let account_id = dispatcher.register_user(username, role.clone(), rank.clone(), metadata);
    let content_id = dispatcher.register_content(title, description, content_type, category);

    start_cheat_caller_address(contract_address, admin);
    dispatcher.emergency_pause();
    stop_cheat_caller_address(contract_address);

    dispatcher.grant_premium_access(account_id, content_id);
}


#[test]
#[should_panic(expected: "Only WRITER can post content")]
fn test_is_in_blacklist() {
    let (contract_address, _, erc20_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    let creator = contract_address_const::<'creator'>();

    start_cheat_caller_address(contract_address, creator);
    // Test input values
    let username: felt252 = 'John';
    let role: Role = Role::WRITER;
    let rank: Rank = Rank::BEGINNER;
    let metadata: felt252 = 'john is a boy';

    let title: felt252 = 'My Content';
    let description: felt252 = 'This is a test content';
    let content_type: ContentType = ContentType::Text;
    let category: Category = Category::Education;
    let content_id = dispatcher.register_content(title, description, content_type, category);

    stop_cheat_caller_address(contract_address);

    // Call register
    let account_id = dispatcher.register_user(username, role.clone(), rank.clone(), metadata);

    let check_blacklist = dispatcher.is_in_blacklist(account_id, content_id);
    assert(check_blacklist, 'User should not be in blacklist');
}

#[test]
#[should_panic(expected: "Only WRITER can post content")]
fn test_revoke_access_by_admin() {
    let (contract_address, admin, erc20_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Test input values
    let username: felt252 = 'John';
    let role: Role = Role::WRITER;
    let rank: Rank = Rank::BEGINNER;
    let metadata: felt252 = 'john is a boy';

    let title: felt252 = 'My Content';
    let description: felt252 = 'This is a test content';
    let content_type: ContentType = ContentType::Text;
    let category: Category = Category::Education;

    let content_id = dispatcher.register_content(title, description, content_type, category);

    // Call register
    let account_id = dispatcher.register_user(username, role.clone(), rank.clone(), metadata);

    start_cheat_caller_address(contract_address, admin);
    dispatcher.revoke_access(account_id, content_id);
    let check_blacklist = dispatcher.is_in_blacklist(account_id, content_id);
    assert(check_blacklist, 'User should not be in blacklist');
}

#[test]
fn test_has_active_subscription() {
    let (contract_address, admin, erc20_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Test input values
    let username: felt252 = 'John';
    let role: Role = Role::READER;
    let rank: Rank = Rank::BEGINNER;
    let metadata: felt252 = 'john is a boy';

    // Call register
    let account_id = dispatcher.register_user(username, role.clone(), rank.clone(), metadata);

    dispatcher.create_subscription(account_id, 500, 2);

    start_cheat_caller_address(contract_address, admin);
    let check_sub = dispatcher.has_active_subscription(account_id);
    assert(check_sub, 'should have an active sub');
}

#[test]
fn test_set_cache_ttl() {
    let (contract_address, admin, erc20_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    start_cheat_caller_address(contract_address, admin);

    let set_cache_ttl = dispatcher.set_cache_ttl(1000);
    assert(set_cache_ttl, 'Cache TTL should be set');
}

#[test]
#[should_panic(expected: "Only WRITER can post content")]
fn test_verify_access() {
    let (contract_address, admin, erc20_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Test input values
    let username: felt252 = 'John';
    let role: Role = Role::WRITER;
    let rank: Rank = Rank::BEGINNER;
    let metadata: felt252 = 'john is a boy';

    let title: felt252 = 'My Content';
    let description: felt252 = 'This is a test content';
    let content_type: ContentType = ContentType::Text;
    let category: Category = Category::Education;

    let content_id = dispatcher.register_content(title, description, content_type, category);

    // Call register
    let account_id = dispatcher.register_user(username, role.clone(), rank.clone(), metadata);

    start_cheat_caller_address(contract_address, admin);
    dispatcher.verify_access(account_id, content_id);
}

#[test]
#[should_panic(expected: "Only WRITER can post content")]
fn test_determine_access() {
    let (contract_address, admin, erc20_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Test input values
    let username: felt252 = 'John';
    let role: Role = Role::WRITER;
    let rank: Rank = Rank::BEGINNER;
    let metadata: felt252 = 'john is a boy';

    let title: felt252 = 'My Content';
    let description: felt252 = 'This is a test content';
    let content_type: ContentType = ContentType::Text;
    let category: Category = Category::Education;

    let content_id = dispatcher.register_content(title, description, content_type, category);

    // Call register
    let account_id = dispatcher.register_user(username, role.clone(), rank.clone(), metadata);

    start_cheat_caller_address(contract_address, admin);
    dispatcher.verify_access(account_id, content_id);
}

#[test]
fn test_purchase_content() {
    let (contract_address, admin_address, erc20_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };
    let user_address = contract_address_const::<'user'>();

    // Token faucet and allowance setup
    token_faucet_and_allowance(dispatcher, user_address, erc20_address, 100000);

    // Set up test data
    let content_id: felt252 = 'content1';
    let price: u256 = 1000_u256;
    let transaction_hash: felt252 = 'tx1';

    // Set up content with price
    setup_content_with_price(dispatcher, admin_address, contract_address, content_id, price);

    // We set user as the caller for the purchase
    cheat_caller_address(contract_address, user_address, CheatSpan::Indefinite);

    // Call the purchase function
    let purchase_id = dispatcher.purchase_content(content_id, transaction_hash);

    // Verify the purchase details
    let purchase = dispatcher.get_purchase_details(purchase_id);
    assert(purchase.id == purchase_id, 'ID mismatch');
    assert(purchase.content_id == content_id, 'Content ID mismatch');
    assert(purchase.buyer == user_address, 'Buyer mismatch');
    assert(purchase.price == price, 'Price mismatch');
    assert(purchase.status == PurchaseStatus::Pending, 'Status mismatch');
    assert(purchase.transaction_hash == transaction_hash, 'Transaction hash mismatch');
}


#[test]
#[should_panic(expected: 'Insufficient token balance')]
fn test_purchase_content_should_fail_if_insufficient_balance() {
    let (contract_address, admin_address, erc20_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };
    let user_address = contract_address_const::<'user'>();

    let token_dispatcher = IERC20Dispatcher { contract_address: erc20_address };
    // Transfer tokens from admin to user
    start_cheat_caller_address(erc20_address, admin_address);
    token_dispatcher.transfer(user_address, 10);
    stop_cheat_caller_address(erc20_address);

    // Set user as caller to approve the contract
    start_cheat_caller_address(erc20_address, user_address);
    token_dispatcher.approve(dispatcher.contract_address, 10000);
    stop_cheat_caller_address(erc20_address);

    // Set up test data
    let content_id: felt252 = 'content1';
    let price: u256 = 1000_u256;
    let transaction_hash: felt252 = 'tx1';

    // Set up content with price
    setup_content_with_price(dispatcher, admin_address, contract_address, content_id, price);

    // We set user as the caller for the purchase
    cheat_caller_address(contract_address, user_address, CheatSpan::Indefinite);

    // Call the purchase function
    let purchase_id = dispatcher.purchase_content(content_id, transaction_hash);

    // Verify the purchase details
    let purchase = dispatcher.get_purchase_details(purchase_id);
    assert(purchase.id == purchase_id, 'ID mismatch');
    assert(purchase.content_id == content_id, 'Content ID mismatch');
    assert(purchase.buyer == user_address, 'Buyer mismatch');
    assert(purchase.price == price, 'Price mismatch');
    assert(purchase.status == PurchaseStatus::Pending, 'Status mismatch');
    assert(purchase.transaction_hash == transaction_hash, 'Transaction hash mismatch');
}


#[test]
#[should_panic(expected: 'Insufficient token allowance')]
fn test_purchase_content_should_fail_if_insufficient_allowance() {
    let (contract_address, admin_address, erc20_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };
    let user_address = contract_address_const::<'user'>();

    let token_dispatcher = IERC20Dispatcher { contract_address: erc20_address };
    // Transfer tokens from admin to user
    start_cheat_caller_address(erc20_address, admin_address);
    token_dispatcher.transfer(user_address, 10000);
    stop_cheat_caller_address(erc20_address);

    // Set user as caller to approve the contract
    start_cheat_caller_address(erc20_address, user_address);
    token_dispatcher.approve(dispatcher.contract_address, 100);
    stop_cheat_caller_address(erc20_address);

    // Set up test data
    let content_id: felt252 = 'content1';
    let price: u256 = 1000_u256;
    let transaction_hash: felt252 = 'tx1';

    // Set up content with price
    setup_content_with_price(dispatcher, admin_address, contract_address, content_id, price);

    // We set user as the caller for the purchase
    cheat_caller_address(contract_address, user_address, CheatSpan::Indefinite);

    // Call the purchase function
    let purchase_id = dispatcher.purchase_content(content_id, transaction_hash);

    // Verify the purchase details
    let purchase = dispatcher.get_purchase_details(purchase_id);
    assert(purchase.id == purchase_id, 'ID mismatch');
    assert(purchase.content_id == content_id, 'Content ID mismatch');
    assert(purchase.buyer == user_address, 'Buyer mismatch');
    assert(purchase.price == price, 'Price mismatch');
    assert(purchase.status == PurchaseStatus::Pending, 'Status mismatch');
    assert(purchase.transaction_hash == transaction_hash, 'Transaction hash mismatch');
}


#[test]
#[should_panic(expected: "Content either doesn't exist")]
fn test_purchase_nonexistent_content() {
    let (contract_address, _, erc20_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };
    let user_address = contract_address_const::<'user'>();

    // Set user as caller
    cheat_caller_address(contract_address, user_address, CheatSpan::Indefinite);

    // Attempt to purchase nonexistent content
    let content_id: felt252 = 'none';
    let transaction_hash: felt252 = 'tx1';

    // This should fail because the content doesn't exist (no price set)
    let _ = dispatcher.purchase_content(content_id, transaction_hash);
}

#[test]
fn test_get_user_purchases() {
    let (contract_address, admin_address, erc20_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };
    let user_address = contract_address_const::<'user'>();

    // Set up multiple content items
    let content_id_1: felt252 = 'content1';
    let content_id_2: felt252 = 'content2';
    let price: u256 = 1000_u256;

    token_faucet_and_allowance(dispatcher, user_address, erc20_address, 100000);

    // Set admin as caller to prepare the contract state
    cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);
    // Set up content with price
    setup_content_with_price(dispatcher, admin_address, contract_address, content_id_1, price);
    setup_content_with_price(dispatcher, admin_address, contract_address, content_id_2, price * 2);

    // Set user as caller for purchases
    cheat_caller_address(contract_address, user_address, CheatSpan::Indefinite);

    // Purchase multiple content items
    let purchase_id_1 = dispatcher.purchase_content(content_id_1, 'tx1');
    let purchase_id_2 = dispatcher.purchase_content(content_id_2, 'tx2');

    // Get user purchases
    let _user_purchases = dispatcher.get_user_purchases(user_address);

    // Verify the purchases array contains the expected items
    assert(_user_purchases.len() == 2, 'Wrong number of purchases');

    // Due to Copy trait constraints, we need to modify how we access array elements
    // Instead of dereferencing, we'll check directly using the array
    let purchase_1 = dispatcher.get_purchase_details(purchase_id_1);
    let purchase_2 = dispatcher.get_purchase_details(purchase_id_2);

    assert(purchase_1.id == purchase_id_1, 'Purchase 1 ID mismatch');
    assert(purchase_1.content_id == content_id_1, 'Purchase 1 content mismatch');

    assert(purchase_2.id == purchase_id_2, 'Purchase 2 ID mismatch');
    assert(purchase_2.content_id == content_id_2, 'Purchase 2 content mismatch');
}

#[test]
fn test_verify_purchase() {
    let (contract_address, admin_address, erc20_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };
    let user_address = contract_address_const::<'user'>();

    token_faucet_and_allowance(dispatcher, user_address, erc20_address, 100000);
    // Set up test data
    let content_id: felt252 = 'content1';
    let price: u256 = 1000_u256;

    // Set admin as caller to set up content price
    cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);

    // Set up content with price
    setup_content_with_price(dispatcher, admin_address, contract_address, content_id, price);

    // Set user as caller
    cheat_caller_address(contract_address, user_address, CheatSpan::Indefinite);

    // Purchase the content
    let purchase_id = dispatcher.purchase_content(content_id, 'tx1');

    // Initially, purchase should not be verified (status is Pending)
    let is_verified = dispatcher.verify_purchase(purchase_id);
    assert(!is_verified, 'Purchase should not be verified');

    // Set admin as caller to update the purchase status
    cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);

    // Update purchase status to Completed
    let update_result = dispatcher.update_purchase_status(purchase_id, PurchaseStatus::Completed);
    assert(update_result, 'Failed to update status');

    // Now the purchase should be verified
    let is_now_verified = dispatcher.verify_purchase(purchase_id);
    assert(is_now_verified, 'Purchase should be verified');

    let receipt = dispatcher.get_receipt(1);

    assert(receipt.purchase_id == purchase_id, 'receipt error');
}


#[test]
fn test_update_purchase_status() {
    let (contract_address, admin_address, erc20_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };
    let user_address = contract_address_const::<'user'>();

    token_faucet_and_allowance(dispatcher, user_address, erc20_address, 100000);

    // Set up test data
    let content_id: felt252 = 'content1';
    let price: u256 = 1000_u256;

    // Set admin as caller to set up content price
    cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);

    // Set up content with price
    setup_content_with_price(dispatcher, admin_address, contract_address, content_id, price);

    // Set user as caller for purchase
    cheat_caller_address(contract_address, user_address, CheatSpan::Indefinite);

    // Purchase the content
    let purchase_id = dispatcher.purchase_content(content_id, 'tx1');

    // Get initial purchase
    let initial_purchase = dispatcher.get_purchase_details(purchase_id);
    assert(initial_purchase.status == PurchaseStatus::Pending, 'Status should be Pending');

    // Set admin as caller to update the purchase status
    cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);

    // Test updating to different statuses
    // 1. Update to Completed
    let update_to_completed = dispatcher
        .update_purchase_status(purchase_id, PurchaseStatus::Completed);
    assert(update_to_completed, 'Failed to update to Completed');

    let completed_purchase = dispatcher.get_purchase_details(purchase_id);
    assert(completed_purchase.status == PurchaseStatus::Completed, 'Status should be Completed');

    // 2. Update to Failed
    let update_to_failed = dispatcher.update_purchase_status(purchase_id, PurchaseStatus::Failed);
    assert(update_to_failed, 'Failed to update to Failed');

    let failed_purchase = dispatcher.get_purchase_details(purchase_id);
    assert(failed_purchase.status == PurchaseStatus::Failed, 'Status should be Failed');

    // 3. Update to Refunded
    let update_to_refunded = dispatcher
        .update_purchase_status(purchase_id, PurchaseStatus::Refunded);
    assert(update_to_refunded, 'Failed to update to Refunded');

    let refunded_purchase = dispatcher.get_purchase_details(purchase_id);
    assert(refunded_purchase.status == PurchaseStatus::Refunded, 'Status should be Refunded');
}

#[test]
#[should_panic(expected: 'Only admin can update status')]
fn test_update_purchase_status_not_admin() {
    let (contract_address, admin_address, erc20_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };
    let user_address = contract_address_const::<'user'>();

    token_faucet_and_allowance(dispatcher, user_address, erc20_address, 100000);
    // Set up test data
    let content_id: felt252 = 'content1';
    let price: u256 = 1000_u256;

    // Set admin as caller to set up content price
    cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);

    // Set up content with price
    setup_content_with_price(dispatcher, admin_address, contract_address, content_id, price);

    // Set user as caller for purchase
    cheat_caller_address(contract_address, user_address, CheatSpan::Indefinite);

    // Purchase the content
    let purchase_id = dispatcher.purchase_content(content_id, 'tx1');

    // Attempt to update purchase status as non-admin user
    // This should fail with the "Only admin can update status" error
    let _ = dispatcher.update_purchase_status(purchase_id, PurchaseStatus::Completed);
}

#[test]
#[should_panic(expected: 'Purchase does not exist')]
fn test_update_nonexistent_purchase() {
    let (contract_address, admin_address, erc20_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Set admin as caller
    cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);

    // Attempt to update a purchase that doesn't exist
    let nonexistent_purchase_id = 42_u256;
    let _ = dispatcher.update_purchase_status(nonexistent_purchase_id, PurchaseStatus::Completed);
}

#[test]
fn test_cancel_subscription() {
    let (contract_address, _, erc20_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Test input values
    let username: felt252 = 'John';
    let role: Role = Role::READER;
    let rank: Rank = Rank::BEGINNER;
    let metadata: felt252 = 'john is a boy';

    // Call register
    let account_id = dispatcher.register_user(username, role.clone(), rank.clone(), metadata);

    dispatcher.create_subscription(account_id, 500, 1);
    let subscription = dispatcher.get_user_subscription(account_id);
    assert(subscription.id == 1, 'Subscription ID should be 1');
    assert(subscription.subscription_type == PlanType::YEARLY, 'Plan type should be YEARLY');
    assert(subscription.status == SubscriptionStatus::Active, 'Plan type should be YEARLY');
    let subscription_record = dispatcher.get_user_subscription_record(account_id);
    assert(subscription_record.len() == 1, 'record should have length 1');

    dispatcher.cancel_subscription(account_id);
    let subscription = dispatcher.get_user_subscription(account_id);
    assert(subscription.id == 1, 'Subscription ID should be 1');
    assert(subscription.subscription_type == PlanType::YEARLY, 'Plan type should be YEARLY');
    assert(subscription.status == SubscriptionStatus::Cancelled, 'Plan status should be cancelled');
    let subscription_record = dispatcher.get_user_subscription_record(account_id);
    assert(subscription_record.len() == 1, 'record should have length 1');
}


#[test]
fn test_renew_subscription() {
    let (contract_address, _, erc20_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Test input values
    let username: felt252 = 'John';
    let role: Role = Role::READER;
    let rank: Rank = Rank::BEGINNER;
    let metadata: felt252 = 'john is a boy';

    // Call register
    let account_id = dispatcher.register_user(username, role.clone(), rank.clone(), metadata);

    dispatcher.create_subscription(account_id, 500, 1);
    let subscription = dispatcher.get_user_subscription(account_id);
    assert(subscription.id == 1, 'Subscription ID should be 1');
    assert(subscription.subscription_type == PlanType::YEARLY, 'Plan type should be YEARLY');
    assert(subscription.status == SubscriptionStatus::Active, 'Plan type should be YEARLY');
    let subscription_record = dispatcher.get_user_subscription_record(account_id);
    assert(subscription_record.len() == 1, 'record should have length 1');

    dispatcher.cancel_subscription(account_id);
    let subscription = dispatcher.get_user_subscription(account_id);
    assert(subscription.id == 1, 'Subscription ID should be 1');
    assert(subscription.subscription_type == PlanType::YEARLY, 'Plan type should be YEARLY');
    assert(subscription.status == SubscriptionStatus::Cancelled, 'Plan status should be cancelled');
    let subscription_record = dispatcher.get_user_subscription_record(account_id);
    assert(subscription_record.len() == 1, 'record should have length 1');

    dispatcher.renew_subscription(account_id);
    let subscription = dispatcher.get_user_subscription(account_id);
    assert(subscription.id == 1, 'Subscription ID should be 1');
    assert(subscription.subscription_type == PlanType::YEARLY, 'Plan type should be YEARLY');
    assert(subscription.status == SubscriptionStatus::Active, 'Plan status should be Active');
    let subscription_record = dispatcher.get_user_subscription_record(account_id);
    assert(subscription_record.len() == 1, 'record should have length 1');
}


#[test]
fn test_batch_payout_creators() {
    let (contract_address, admin_address, erc20_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };
    let user_address = contract_address_const::<'user'>();
    let creator_1 = contract_address_const::<'creator_1'>();
    let creator_2 = contract_address_const::<'creator_2'>();
    let creator_3 = contract_address_const::<'creator_3'>();

    let username1: felt252 = 'creator_1';
    let username2: felt252 = 'creator_2';
    let username3: felt252 = 'creator_3';

    let role: Role = Role::WRITER;
    let rank: Rank = Rank::BEGINNER;
    let metadata: felt252 = 'john is a boy';

    start_cheat_caller_address(contract_address, creator_1);
    let creator1_id = dispatcher.register_user(username1, role.clone(), rank.clone(), metadata);
    println!("successfully registered creator_1 as writer");
    stop_cheat_caller_address(contract_address);

    start_cheat_caller_address(contract_address, creator_2);
    let creator2_id = dispatcher.register_user(username2, role.clone(), rank.clone(), metadata);
    stop_cheat_caller_address(contract_address);

    start_cheat_caller_address(contract_address, creator_3);
    let creator3_id = dispatcher.register_user(username3, role.clone(), rank.clone(), metadata);
    stop_cheat_caller_address(contract_address);

    start_cheat_caller_address(contract_address, admin_address);
    let is_creator_1_verified = dispatcher.verify_user(creator1_id);
    let is_creator_2_verified = dispatcher.verify_user(creator2_id);
    let is_creator_3_verified = dispatcher.verify_user(creator3_id);
    stop_cheat_caller_address(contract_address);

    let erc20_dispatcher = IERC20Dispatcher { contract_address: erc20_address };
    let creator_1_init_bal = erc20_dispatcher.balance_of(creator_1);
    let creator_2_init_bal = erc20_dispatcher.balance_of(creator_2);
    let creator_3_init_bal = erc20_dispatcher.balance_of(creator_3);

    token_faucet_and_allowance(dispatcher, user_address, erc20_address, 100000);
    // Set up test data
    let title1: felt252 = 'Creator 1 content';
    let title2: felt252 = 'Creator 2 content';
    let title3: felt252 = 'Creator 3 content';

    let description: felt252 = 'This is a test content';
    let content_type: ContentType = ContentType::Text;
    let category: Category = Category::Education;

    start_cheat_caller_address(contract_address, creator_1);
    let creator1_content_id: felt252 = dispatcher
        .register_content(title1, description, content_type, category);
    stop_cheat_caller_address(contract_address);

    start_cheat_caller_address(contract_address, creator_2);
    let creator2_content_id: felt252 = dispatcher
        .register_content(title2, description, content_type, category);
    stop_cheat_caller_address(contract_address);

    start_cheat_caller_address(contract_address, creator_3);
    let creator3_content_id: felt252 = dispatcher
        .register_content(title3, description, content_type, category);
    stop_cheat_caller_address(contract_address);
    let price_1: u256 = 1000_u256;
    let price_2: u256 = 2000_u256;
    let price_3: u256 = 1500_u256;

    // Set creator_1 as caller to set up content price
    cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);
    // Set up content with price
    setup_content_with_price(
        dispatcher, admin_address, contract_address, creator1_content_id, price_1,
    );

    // Set up content with price
    setup_content_with_price(
        dispatcher, admin_address, contract_address, creator2_content_id, price_2,
    );

    // Set up content with price
    setup_content_with_price(
        dispatcher, admin_address, contract_address, creator3_content_id, price_3,
    );

    // Set user as content consumer
    cheat_caller_address(contract_address, user_address, CheatSpan::Indefinite);

    // Purchase the content
    let purchase_id_1 = dispatcher.purchase_content(creator1_content_id, 'tx1');
    let purchase_id_2 = dispatcher.purchase_content(creator2_content_id, 'tx2');
    let purchase_id_3 = dispatcher.purchase_content(creator3_content_id, 'tx3');

    // Initially, purchase should not be verified (status is Pending)
    let is_purchase_1_verified = dispatcher.verify_purchase(purchase_id_1);
    let is_purchase_2_verified = dispatcher.verify_purchase(purchase_id_2);
    let is_purchase_3_verified = dispatcher.verify_purchase(purchase_id_3);
    assert(!is_purchase_1_verified, '1 should not be verified');
    assert(!is_purchase_2_verified, '2 should not be verified');
    assert(!is_purchase_3_verified, '3 should not be verified');

    // Set admin as caller to update the purchase status
    cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);
    cheat_block_timestamp(contract_address, 0, CheatSpan::Indefinite);

    // Update purchase status to Completed
    let update_result_1 = dispatcher
        .update_purchase_status(purchase_id_1, PurchaseStatus::Completed);
    assert(update_result_1, 'Failed to update status1');
    let update_result_2 = dispatcher
        .update_purchase_status(purchase_id_2, PurchaseStatus::Completed);
    assert(update_result_2, 'Failed to update status1');
    let update_result_3 = dispatcher
        .update_purchase_status(purchase_id_3, PurchaseStatus::Completed);
    assert(update_result_3, 'Failed to update status1');

    // Now the purchase should be verified
    let is_now_verified1 = dispatcher.verify_purchase(purchase_id_1);
    assert(is_now_verified1, 'Purchase should be verified');
    let is_now_verified2 = dispatcher.verify_purchase(purchase_id_2);
    assert(is_now_verified2, 'Purchase should be verified');
    let is_now_verified3 = dispatcher.verify_purchase(purchase_id_3);
    assert(is_now_verified3, 'Purchase should be verified');

    let receipt = dispatcher.get_receipt(1);

    assert(receipt.purchase_id == purchase_id_1, 'receipt error');

    // Still admin calling
    cheat_block_timestamp(contract_address, 86400 * 8, CheatSpan::Indefinite);
    // start_cheat_block_timestamp(contract_address);
    dispatcher.batch_payout_creators();

    let creator_1_new_bal = erc20_dispatcher.balance_of(creator_1);
    let creator_2_new_bal = erc20_dispatcher.balance_of(creator_2);
    let creator_3_new_bal = erc20_dispatcher.balance_of(creator_3);

    assert(creator_1_new_bal > creator_1_init_bal, 'Failed to credit creator1');
    assert(creator_2_new_bal > creator_2_init_bal, 'Failed to credit creator2');
    assert(creator_3_new_bal > creator_3_init_bal, 'Failed to credit creator3');
}

#[test]
fn test_refund_flow_approve_refund_request() {
    let (contract_address, admin_address, erc20_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };
    let user_address = contract_address_const::<'user'>();
    let creator_1 = contract_address_const::<'creator_1'>();
    let creator_2 = contract_address_const::<'creator_2'>();
    let creator_3 = contract_address_const::<'creator_3'>();

    let username1: felt252 = 'creator_1';
    let username2: felt252 = 'creator_2';
    let username3: felt252 = 'creator_3';
    let user_name: felt252 = 'user';

    let role: Role = Role::WRITER;
    let rank: Rank = Rank::BEGINNER;
    let metadata: felt252 = 'john is a boy';

    start_cheat_caller_address(contract_address, user_address);
    let user_id = dispatcher.register_user(user_name, Role::READER, Rank::BEGINNER, metadata);
    stop_cheat_caller_address(contract_address);

    start_cheat_caller_address(contract_address, creator_1);
    let creator1_id = dispatcher.register_user(username1, role.clone(), rank.clone(), metadata);
    println!("successfully registered creator_1 as writer");
    stop_cheat_caller_address(contract_address);

    start_cheat_caller_address(contract_address, creator_2);
    let creator2_id = dispatcher.register_user(username2, role.clone(), rank.clone(), metadata);
    stop_cheat_caller_address(contract_address);

    start_cheat_caller_address(contract_address, creator_3);
    let creator3_id = dispatcher.register_user(username3, role.clone(), rank.clone(), metadata);
    stop_cheat_caller_address(contract_address);

    start_cheat_caller_address(contract_address, admin_address);
    let is_creator_1_verified = dispatcher.verify_user(creator1_id);
    let is_creator_2_verified = dispatcher.verify_user(creator2_id);
    let is_creator_3_verified = dispatcher.verify_user(creator3_id);
    stop_cheat_caller_address(contract_address);

    let erc20_dispatcher = IERC20Dispatcher { contract_address: erc20_address };
    let creator_1_init_bal = erc20_dispatcher.balance_of(creator_1);
    let creator_2_init_bal = erc20_dispatcher.balance_of(creator_2);
    let creator_3_init_bal = erc20_dispatcher.balance_of(creator_3);

    token_faucet_and_allowance(dispatcher, user_address, erc20_address, 100000);
    // Set up test data
    let title1: felt252 = 'Creator 1 content';
    let title2: felt252 = 'Creator 2 content';
    let title3: felt252 = 'Creator 3 content';

    let description: felt252 = 'This is a test content';
    let content_type: ContentType = ContentType::Text;
    let category: Category = Category::Education;

    start_cheat_caller_address(contract_address, creator_1);
    let creator1_content_id: felt252 = dispatcher
        .register_content(title1, description, content_type, category);
    stop_cheat_caller_address(contract_address);

    start_cheat_caller_address(contract_address, creator_2);
    let creator2_content_id: felt252 = dispatcher
        .register_content(title2, description, content_type, category);
    stop_cheat_caller_address(contract_address);

    start_cheat_caller_address(contract_address, creator_3);
    let creator3_content_id: felt252 = dispatcher
        .register_content(title3, description, content_type, category);
    stop_cheat_caller_address(contract_address);
    let price_1: u256 = 1000_u256;
    let price_2: u256 = 2000_u256;
    let price_3: u256 = 1500_u256;

    // Set creator_1 as caller to set up content price
    cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);
    // Set up content with price
    setup_content_with_price(
        dispatcher, admin_address, contract_address, creator1_content_id, price_1,
    );

    // Set up content with price
    setup_content_with_price(
        dispatcher, admin_address, contract_address, creator2_content_id, price_2,
    );

    // Set up content with price
    setup_content_with_price(
        dispatcher, admin_address, contract_address, creator3_content_id, price_3,
    );

    // Set user as content consumer
    cheat_caller_address(contract_address, user_address, CheatSpan::Indefinite);

    // Purchase the content
    let purchase_id_1 = dispatcher.purchase_content(creator1_content_id, 'tx1');
    let purchase_id_2 = dispatcher.purchase_content(creator2_content_id, 'tx2');
    let purchase_id_3 = dispatcher.purchase_content(creator3_content_id, 'tx3');

    // Initially, purchase should not be verified (status is Pending)
    let is_purchase_1_verified = dispatcher.verify_purchase(purchase_id_1);
    let is_purchase_2_verified = dispatcher.verify_purchase(purchase_id_2);
    let is_purchase_3_verified = dispatcher.verify_purchase(purchase_id_3);
    assert(!is_purchase_1_verified, '1 should not be verified');
    assert(!is_purchase_2_verified, '2 should not be verified');
    assert(!is_purchase_3_verified, '3 should not be verified');

    // Set admin as caller to update the purchase status
    cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);
    cheat_block_timestamp(contract_address, 0, CheatSpan::Indefinite);

    // Update purchase status to Completed
    let update_result_1 = dispatcher
        .update_purchase_status(purchase_id_1, PurchaseStatus::Completed);
    assert(update_result_1, 'Failed to update status1');
    let update_result_2 = dispatcher
        .update_purchase_status(purchase_id_2, PurchaseStatus::Completed);
    assert(update_result_2, 'Failed to update status1');
    let update_result_3 = dispatcher
        .update_purchase_status(purchase_id_3, PurchaseStatus::Completed);
    assert(update_result_3, 'Failed to update status1');

    // Now the purchase should be verified
    let is_now_verified1 = dispatcher.verify_purchase(purchase_id_1);
    assert(is_now_verified1, 'Purchase should be verified');
    let is_now_verified2 = dispatcher.verify_purchase(purchase_id_2);
    assert(is_now_verified2, 'Purchase should be verified');
    let is_now_verified3 = dispatcher.verify_purchase(purchase_id_3);
    assert(is_now_verified3, 'Purchase should be verified');

    let receipt = dispatcher.get_receipt(1);

    assert(receipt.purchase_id == purchase_id_1, 'receipt error');

    start_cheat_caller_address(contract_address, user_address);
    dispatcher.request_refund(purchase_id_1, RefundRequestReason::MISREPRESENTED_CONTENT);
    stop_cheat_caller_address(contract_address);

    start_cheat_caller_address(contract_address, admin_address);
    let refunds_array = dispatcher.get_user_refunds(user_id);
    let refund_request = refunds_array.at(0);
    assert(*refund_request.status == RefundStatus::PENDING, 'Wrong refund status');

    dispatcher.approve_refund(*refund_request.refund_id, user_id, Option::None);
    let new_refunds_array = dispatcher.get_user_refunds(user_id);
    let new_refund_request = new_refunds_array.at(0);
    assert(*new_refund_request.status == RefundStatus::APPROVED, 'Failed to change refund status');

    dispatcher.refund_user(*refund_request.refund_id, user_id);

    let paid_refunds_array = dispatcher.get_user_refunds(user_id);
    let paid_refund = paid_refunds_array.at(0);
    assert(*paid_refund.status == RefundStatus::PAID, 'Failed to change refund status');

    // Still admin calling
    cheat_block_timestamp(contract_address, 86400 * 8, CheatSpan::Indefinite);
    // start_cheat_block_timestamp(contract_address);
    dispatcher.batch_payout_creators();

    let creator_1_new_bal = erc20_dispatcher.balance_of(creator_1);
    let creator_2_new_bal = erc20_dispatcher.balance_of(creator_2);
    let creator_3_new_bal = erc20_dispatcher.balance_of(creator_3);

    assert(creator_1_new_bal > creator_1_init_bal, 'Failed to credit creator1');
    assert(creator_2_new_bal > creator_2_init_bal, 'Failed to credit creator2');
    assert(creator_3_new_bal > creator_3_init_bal, 'Failed to credit creator3');
}


#[test]
#[should_panic(expected: 'Refund request declined')]
fn test_refund_flow_decline_refund_request() {
    let (contract_address, admin_address, erc20_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };
    let user_address = contract_address_const::<'user'>();
    let creator_1 = contract_address_const::<'creator_1'>();
    let creator_2 = contract_address_const::<'creator_2'>();
    let creator_3 = contract_address_const::<'creator_3'>();

    let username1: felt252 = 'creator_1';
    let username2: felt252 = 'creator_2';
    let username3: felt252 = 'creator_3';
    let user_name: felt252 = 'user';

    let role: Role = Role::WRITER;
    let rank: Rank = Rank::BEGINNER;
    let metadata: felt252 = 'john is a boy';

    start_cheat_caller_address(contract_address, user_address);
    let user_id = dispatcher.register_user(user_name, Role::READER, Rank::BEGINNER, metadata);
    stop_cheat_caller_address(contract_address);

    start_cheat_caller_address(contract_address, creator_1);
    let creator1_id = dispatcher.register_user(username1, role.clone(), rank.clone(), metadata);
    println!("successfully registered creator_1 as writer");
    stop_cheat_caller_address(contract_address);

    start_cheat_caller_address(contract_address, creator_2);
    let creator2_id = dispatcher.register_user(username2, role.clone(), rank.clone(), metadata);
    stop_cheat_caller_address(contract_address);

    start_cheat_caller_address(contract_address, creator_3);
    let creator3_id = dispatcher.register_user(username3, role.clone(), rank.clone(), metadata);
    stop_cheat_caller_address(contract_address);

    start_cheat_caller_address(contract_address, admin_address);
    let is_creator_1_verified = dispatcher.verify_user(creator1_id);
    let is_creator_2_verified = dispatcher.verify_user(creator2_id);
    let is_creator_3_verified = dispatcher.verify_user(creator3_id);
    stop_cheat_caller_address(contract_address);

    let erc20_dispatcher = IERC20Dispatcher { contract_address: erc20_address };
    let creator_1_init_bal = erc20_dispatcher.balance_of(creator_1);
    let creator_2_init_bal = erc20_dispatcher.balance_of(creator_2);
    let creator_3_init_bal = erc20_dispatcher.balance_of(creator_3);

    token_faucet_and_allowance(dispatcher, user_address, erc20_address, 100000);
    // Set up test data
    let title1: felt252 = 'Creator 1 content';
    let title2: felt252 = 'Creator 2 content';
    let title3: felt252 = 'Creator 3 content';

    let description: felt252 = 'This is a test content';
    let content_type: ContentType = ContentType::Text;
    let category: Category = Category::Education;

    start_cheat_caller_address(contract_address, creator_1);
    let creator1_content_id: felt252 = dispatcher
        .register_content(title1, description, content_type, category);
    stop_cheat_caller_address(contract_address);

    start_cheat_caller_address(contract_address, creator_2);
    let creator2_content_id: felt252 = dispatcher
        .register_content(title2, description, content_type, category);
    stop_cheat_caller_address(contract_address);

    start_cheat_caller_address(contract_address, creator_3);
    let creator3_content_id: felt252 = dispatcher
        .register_content(title3, description, content_type, category);
    stop_cheat_caller_address(contract_address);
    let price_1: u256 = 1000_u256;
    let price_2: u256 = 2000_u256;
    let price_3: u256 = 1500_u256;

    // Set creator_1 as caller to set up content price
    cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);
    // Set up content with price
    setup_content_with_price(
        dispatcher, admin_address, contract_address, creator1_content_id, price_1,
    );

    // Set up content with price
    setup_content_with_price(
        dispatcher, admin_address, contract_address, creator2_content_id, price_2,
    );

    // Set up content with price
    setup_content_with_price(
        dispatcher, admin_address, contract_address, creator3_content_id, price_3,
    );

    // Set user as content consumer
    cheat_caller_address(contract_address, user_address, CheatSpan::Indefinite);

    // Purchase the content
    let purchase_id_1 = dispatcher.purchase_content(creator1_content_id, 'tx1');
    let purchase_id_2 = dispatcher.purchase_content(creator2_content_id, 'tx2');
    let purchase_id_3 = dispatcher.purchase_content(creator3_content_id, 'tx3');

    // Initially, purchase should not be verified (status is Pending)
    let is_purchase_1_verified = dispatcher.verify_purchase(purchase_id_1);
    let is_purchase_2_verified = dispatcher.verify_purchase(purchase_id_2);
    let is_purchase_3_verified = dispatcher.verify_purchase(purchase_id_3);
    assert(!is_purchase_1_verified, '1 should not be verified');
    assert(!is_purchase_2_verified, '2 should not be verified');
    assert(!is_purchase_3_verified, '3 should not be verified');

    // Set admin as caller to update the purchase status
    cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);
    cheat_block_timestamp(contract_address, 0, CheatSpan::Indefinite);

    // Update purchase status to Completed
    let update_result_1 = dispatcher
        .update_purchase_status(purchase_id_1, PurchaseStatus::Completed);
    assert(update_result_1, 'Failed to update status1');
    let update_result_2 = dispatcher
        .update_purchase_status(purchase_id_2, PurchaseStatus::Completed);
    assert(update_result_2, 'Failed to update status1');
    let update_result_3 = dispatcher
        .update_purchase_status(purchase_id_3, PurchaseStatus::Completed);
    assert(update_result_3, 'Failed to update status1');

    // Now the purchase should be verified
    let is_now_verified1 = dispatcher.verify_purchase(purchase_id_1);
    assert(is_now_verified1, 'Purchase should be verified');
    let is_now_verified2 = dispatcher.verify_purchase(purchase_id_2);
    assert(is_now_verified2, 'Purchase should be verified');
    let is_now_verified3 = dispatcher.verify_purchase(purchase_id_3);
    assert(is_now_verified3, 'Purchase should be verified');

    let receipt = dispatcher.get_receipt(1);

    assert(receipt.purchase_id == purchase_id_1, 'receipt error');

    start_cheat_caller_address(contract_address, user_address);
    dispatcher.request_refund(purchase_id_1, RefundRequestReason::MISREPRESENTED_CONTENT);
    stop_cheat_caller_address(contract_address);

    start_cheat_caller_address(contract_address, admin_address);
    let refunds_array = dispatcher.get_user_refunds(user_id);
    let refund_request = refunds_array.at(0);

    dispatcher.decline_refund(*refund_request.refund_id, user_id);

    let new_refunds_array = dispatcher.get_user_refunds(user_id);
    let new_refund_request = new_refunds_array.at(0);
    assert(*new_refund_request.status == RefundStatus::DECLINED, 'Failed to change refund status');

    dispatcher.refund_user(*refund_request.refund_id, user_id);

    // Still admin calling
    cheat_block_timestamp(contract_address, 86400 * 8, CheatSpan::Indefinite);
    // start_cheat_block_timestamp(contract_address);
    dispatcher.batch_payout_creators();

    let creator_1_new_bal = erc20_dispatcher.balance_of(creator_1);
    let creator_2_new_bal = erc20_dispatcher.balance_of(creator_2);
    let creator_3_new_bal = erc20_dispatcher.balance_of(creator_3);

    assert(creator_1_new_bal > creator_1_init_bal, 'Failed to credit creator1');
    assert(creator_2_new_bal > creator_2_init_bal, 'Failed to credit creator2');
    assert(creator_3_new_bal > creator_3_init_bal, 'Failed to credit creator3');
}

#[test]
#[should_panic(expected: 'Refund window already closed')]
fn test_refund_flow_refund_request_timed_out() {
    let (contract_address, admin_address, erc20_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };
    let user_address = contract_address_const::<'user'>();
    let creator_1 = contract_address_const::<'creator_1'>();
    let creator_2 = contract_address_const::<'creator_2'>();
    let creator_3 = contract_address_const::<'creator_3'>();

    let username1: felt252 = 'creator_1';
    let username2: felt252 = 'creator_2';
    let username3: felt252 = 'creator_3';
    let user_name: felt252 = 'user';

    let role: Role = Role::WRITER;
    let rank: Rank = Rank::BEGINNER;
    let metadata: felt252 = 'john is a boy';

    start_cheat_caller_address(contract_address, user_address);
    let user_id = dispatcher.register_user(user_name, Role::READER, Rank::BEGINNER, metadata);
    stop_cheat_caller_address(contract_address);

    start_cheat_caller_address(contract_address, creator_1);
    let creator1_id = dispatcher.register_user(username1, role.clone(), rank.clone(), metadata);
    println!("successfully registered creator_1 as writer");
    stop_cheat_caller_address(contract_address);

    start_cheat_caller_address(contract_address, creator_2);
    let creator2_id = dispatcher.register_user(username2, role.clone(), rank.clone(), metadata);
    stop_cheat_caller_address(contract_address);

    start_cheat_caller_address(contract_address, creator_3);
    let creator3_id = dispatcher.register_user(username3, role.clone(), rank.clone(), metadata);
    stop_cheat_caller_address(contract_address);

    start_cheat_caller_address(contract_address, admin_address);
    let is_creator_1_verified = dispatcher.verify_user(creator1_id);
    let is_creator_2_verified = dispatcher.verify_user(creator2_id);
    let is_creator_3_verified = dispatcher.verify_user(creator3_id);
    stop_cheat_caller_address(contract_address);

    let erc20_dispatcher = IERC20Dispatcher { contract_address: erc20_address };
    let creator_1_init_bal = erc20_dispatcher.balance_of(creator_1);
    let creator_2_init_bal = erc20_dispatcher.balance_of(creator_2);
    let creator_3_init_bal = erc20_dispatcher.balance_of(creator_3);

    token_faucet_and_allowance(dispatcher, user_address, erc20_address, 100000);
    // Set up test data
    let title1: felt252 = 'Creator 1 content';
    let title2: felt252 = 'Creator 2 content';
    let title3: felt252 = 'Creator 3 content';

    let description: felt252 = 'This is a test content';
    let content_type: ContentType = ContentType::Text;
    let category: Category = Category::Education;

    start_cheat_caller_address(contract_address, creator_1);
    let creator1_content_id: felt252 = dispatcher
        .register_content(title1, description, content_type, category);
    stop_cheat_caller_address(contract_address);
    println!("creator1_content_id: {}", creator1_content_id);
    start_cheat_caller_address(contract_address, creator_2);
    let creator2_content_id: felt252 = dispatcher
        .register_content(title2, description, content_type, category);
    stop_cheat_caller_address(contract_address);

    start_cheat_caller_address(contract_address, creator_3);
    let creator3_content_id: felt252 = dispatcher
        .register_content(title3, description, content_type, category);
    stop_cheat_caller_address(contract_address);
    let price_1: u256 = 1000_u256;
    let price_2: u256 = 2000_u256;
    let price_3: u256 = 1500_u256;

    // Set creator_1 as caller to set up content price
    cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);
    // Set up content with price
    setup_content_with_price(
        dispatcher, admin_address, contract_address, creator1_content_id, price_1,
    );

    // Set up content with price
    setup_content_with_price(
        dispatcher, admin_address, contract_address, creator2_content_id, price_2,
    );

    // Set up content with price
    setup_content_with_price(
        dispatcher, admin_address, contract_address, creator3_content_id, price_3,
    );

    // Set user as content consumer
    cheat_caller_address(contract_address, user_address, CheatSpan::Indefinite);

    // Purchase the content
    let purchase_id_1 = dispatcher.purchase_content(creator1_content_id, 'tx1');
    let purchase_id_2 = dispatcher.purchase_content(creator2_content_id, 'tx2');
    let purchase_id_3 = dispatcher.purchase_content(creator3_content_id, 'tx3');

    // Initially, purchase should not be verified (status is Pending)
    let is_purchase_1_verified = dispatcher.verify_purchase(purchase_id_1);
    let is_purchase_2_verified = dispatcher.verify_purchase(purchase_id_2);
    let is_purchase_3_verified = dispatcher.verify_purchase(purchase_id_3);
    assert(!is_purchase_1_verified, '1 should not be verified');
    assert(!is_purchase_2_verified, '2 should not be verified');
    assert(!is_purchase_3_verified, '3 should not be verified');

    // Set admin as caller to update the purchase status
    cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);
    cheat_block_timestamp(contract_address, 0, CheatSpan::Indefinite);

    // Update purchase status to Completed
    let update_result_1 = dispatcher
        .update_purchase_status(purchase_id_1, PurchaseStatus::Completed);
    assert(update_result_1, 'Failed to update status1');
    let update_result_2 = dispatcher
        .update_purchase_status(purchase_id_2, PurchaseStatus::Completed);
    assert(update_result_2, 'Failed to update status1');
    let update_result_3 = dispatcher
        .update_purchase_status(purchase_id_3, PurchaseStatus::Completed);
    assert(update_result_3, 'Failed to update status1');

    // Now the purchase should be verified
    let is_now_verified1 = dispatcher.verify_purchase(purchase_id_1);
    assert(is_now_verified1, 'Purchase should be verified');
    let is_now_verified2 = dispatcher.verify_purchase(purchase_id_2);
    assert(is_now_verified2, 'Purchase should be verified');
    let is_now_verified3 = dispatcher.verify_purchase(purchase_id_3);
    assert(is_now_verified3, 'Purchase should be verified');

    let receipt = dispatcher.get_receipt(1);

    assert(receipt.purchase_id == purchase_id_1, 'receipt error');

    start_cheat_caller_address(contract_address, user_address);
    start_cheat_block_timestamp(contract_address, 86400 * 3);
    dispatcher.request_refund(purchase_id_1, RefundRequestReason::MISREPRESENTED_CONTENT);
    stop_cheat_block_timestamp(contract_address);
    stop_cheat_caller_address(contract_address);

    start_cheat_caller_address(contract_address, admin_address);
    let refunds_array = dispatcher.get_user_refunds(user_id);
    let refund_request = refunds_array.at(0);

    dispatcher.decline_refund(*refund_request.refund_id, user_id);

    let new_refunds_array = dispatcher.get_user_refunds(user_id);
    let new_refund_request = new_refunds_array.at(0);
    assert(*new_refund_request.status == RefundStatus::DECLINED, 'Failed to change refund status');

    dispatcher.refund_user(*refund_request.refund_id, user_id);

    // Still admin calling
    cheat_block_timestamp(contract_address, 86400 * 8, CheatSpan::Indefinite);
    // start_cheat_block_timestamp(contract_address);
    dispatcher.batch_payout_creators();

    let creator_1_new_bal = erc20_dispatcher.balance_of(creator_1);
    let creator_2_new_bal = erc20_dispatcher.balance_of(creator_2);
    let creator_3_new_bal = erc20_dispatcher.balance_of(creator_3);

    assert(creator_1_new_bal > creator_1_init_bal, 'Failed to credit creator1');
    assert(creator_2_new_bal > creator_2_init_bal, 'Failed to credit creator2');
    assert(creator_3_new_bal > creator_3_init_bal, 'Failed to credit creator3');
}


#[test]
#[should_panic(expected: 'Contract is paused')]
fn test_cancel_subscription_should_panic_if_contract_paused() {
    let (contract_address, admin_address, erc20_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Test input values
    let username: felt252 = 'John';
    let role: Role = Role::READER;
    let rank: Rank = Rank::BEGINNER;
    let metadata: felt252 = 'john is a boy';

    // Call register
    let account_id = dispatcher.register_user(username, role.clone(), rank.clone(), metadata);

    dispatcher.create_subscription(account_id, 500, 1);
    let subscription = dispatcher.get_user_subscription(account_id);
    assert(subscription.id == 1, 'Subscription ID should be 1');
    assert(subscription.subscription_type == PlanType::YEARLY, 'Plan type should be YEARLY');
    assert(subscription.status == SubscriptionStatus::Active, 'Plan type should be YEARLY');
    let subscription_record = dispatcher.get_user_subscription_record(account_id);
    assert(subscription_record.len() == 1, 'record should have length 1');

    start_cheat_caller_address(contract_address, admin_address);
    dispatcher.emergency_pause();
    stop_cheat_caller_address(contract_address);

    dispatcher.cancel_subscription(account_id);
}

#[test]
#[should_panic(expected: 'Contract is paused')]
fn test_renew_subscription_should_panic_if_contract_paused() {
    let (contract_address, admin_address, erc20_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Test input values
    let username: felt252 = 'John';
    let role: Role = Role::READER;
    let rank: Rank = Rank::BEGINNER;
    let metadata: felt252 = 'john is a boy';

    // Call register
    let account_id = dispatcher.register_user(username, role.clone(), rank.clone(), metadata);

    dispatcher.create_subscription(account_id, 500, 1);
    let subscription = dispatcher.get_user_subscription(account_id);
    assert(subscription.id == 1, 'Subscription ID should be 1');
    assert(subscription.subscription_type == PlanType::YEARLY, 'Plan type should be YEARLY');
    assert(subscription.status == SubscriptionStatus::Active, 'Plan type should be YEARLY');
    let subscription_record = dispatcher.get_user_subscription_record(account_id);
    assert(subscription_record.len() == 1, 'record should have length 1');

    dispatcher.cancel_subscription(account_id);
    let subscription = dispatcher.get_user_subscription(account_id);
    assert(subscription.id == 1, 'Subscription ID should be 1');
    assert(subscription.subscription_type == PlanType::YEARLY, 'Plan type should be YEARLY');
    assert(subscription.status == SubscriptionStatus::Cancelled, 'Plan status should be cancelled');
    let subscription_record = dispatcher.get_user_subscription_record(account_id);
    assert(subscription_record.len() == 1, 'record should have length 1');

    start_cheat_caller_address(contract_address, admin_address);
    dispatcher.emergency_pause();
    stop_cheat_caller_address(contract_address);

    dispatcher.renew_subscription(account_id);
}


#[test]
#[should_panic(expected: 'Contract is paused')]
fn test_refund_flow_refund_user_should_panic_if_contract_paused() {
    let (contract_address, admin_address, erc20_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };
    let user_address = contract_address_const::<'user'>();
    let creator_1 = contract_address_const::<'creator_1'>();
    let creator_2 = contract_address_const::<'creator_2'>();
    let creator_3 = contract_address_const::<'creator_3'>();

    let username1: felt252 = 'creator_1';
    let username2: felt252 = 'creator_2';
    let username3: felt252 = 'creator_3';
    let user_name: felt252 = 'user';

    let role: Role = Role::WRITER;
    let rank: Rank = Rank::BEGINNER;
    let metadata: felt252 = 'john is a boy';

    start_cheat_caller_address(contract_address, user_address);
    let user_id = dispatcher.register_user(user_name, Role::READER, Rank::BEGINNER, metadata);
    stop_cheat_caller_address(contract_address);

    start_cheat_caller_address(contract_address, creator_1);
    let creator1_id = dispatcher.register_user(username1, role.clone(), rank.clone(), metadata);
    println!("successfully registered creator_1 as writer");
    stop_cheat_caller_address(contract_address);

    start_cheat_caller_address(contract_address, creator_2);
    let creator2_id = dispatcher.register_user(username2, role.clone(), rank.clone(), metadata);
    stop_cheat_caller_address(contract_address);

    start_cheat_caller_address(contract_address, creator_3);
    let creator3_id = dispatcher.register_user(username3, role.clone(), rank.clone(), metadata);
    stop_cheat_caller_address(contract_address);

    start_cheat_caller_address(contract_address, admin_address);
    let is_creator_1_verified = dispatcher.verify_user(creator1_id);
    let is_creator_2_verified = dispatcher.verify_user(creator2_id);
    let is_creator_3_verified = dispatcher.verify_user(creator3_id);
    stop_cheat_caller_address(contract_address);

    let erc20_dispatcher = IERC20Dispatcher { contract_address: erc20_address };
    let creator_1_init_bal = erc20_dispatcher.balance_of(creator_1);
    let creator_2_init_bal = erc20_dispatcher.balance_of(creator_2);
    let creator_3_init_bal = erc20_dispatcher.balance_of(creator_3);

    token_faucet_and_allowance(dispatcher, user_address, erc20_address, 100000);
    // Set up test data
    let title1: felt252 = 'Creator 1 content';
    let title2: felt252 = 'Creator 2 content';
    let title3: felt252 = 'Creator 3 content';

    let description: felt252 = 'This is a test content';
    let content_type: ContentType = ContentType::Text;
    let category: Category = Category::Education;

    start_cheat_caller_address(contract_address, creator_1);
    let creator1_content_id: felt252 = dispatcher
        .register_content(title1, description, content_type, category);
    stop_cheat_caller_address(contract_address);
    println!("creator1_content_id: {}", creator1_content_id);
    start_cheat_caller_address(contract_address, creator_2);
    let creator2_content_id: felt252 = dispatcher
        .register_content(title2, description, content_type, category);
    stop_cheat_caller_address(contract_address);

    start_cheat_caller_address(contract_address, creator_3);
    let creator3_content_id: felt252 = dispatcher
        .register_content(title3, description, content_type, category);
    stop_cheat_caller_address(contract_address);
    let price_1: u256 = 1000_u256;
    let price_2: u256 = 2000_u256;
    let price_3: u256 = 1500_u256;

    // Set creator_1 as caller to set up content price
    cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);
    // Set up content with price
    setup_content_with_price(
        dispatcher, admin_address, contract_address, creator1_content_id, price_1,
    );

    // Set up content with price
    setup_content_with_price(
        dispatcher, admin_address, contract_address, creator2_content_id, price_2,
    );

    // Set up content with price
    setup_content_with_price(
        dispatcher, admin_address, contract_address, creator3_content_id, price_3,
    );

    // Set user as content consumer
    cheat_caller_address(contract_address, user_address, CheatSpan::Indefinite);

    // Purchase the content
    let purchase_id_1 = dispatcher.purchase_content(creator1_content_id, 'tx1');
    let purchase_id_2 = dispatcher.purchase_content(creator2_content_id, 'tx2');
    let purchase_id_3 = dispatcher.purchase_content(creator3_content_id, 'tx3');

    // Initially, purchase should not be verified (status is Pending)
    let is_purchase_1_verified = dispatcher.verify_purchase(purchase_id_1);
    let is_purchase_2_verified = dispatcher.verify_purchase(purchase_id_2);
    let is_purchase_3_verified = dispatcher.verify_purchase(purchase_id_3);
    assert(!is_purchase_1_verified, '1 should not be verified');
    assert(!is_purchase_2_verified, '2 should not be verified');
    assert(!is_purchase_3_verified, '3 should not be verified');

    // Set admin as caller to update the purchase status
    cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);
    cheat_block_timestamp(contract_address, 0, CheatSpan::Indefinite);

    // Update purchase status to Completed
    let update_result_1 = dispatcher
        .update_purchase_status(purchase_id_1, PurchaseStatus::Completed);
    assert(update_result_1, 'Failed to update status1');
    let update_result_2 = dispatcher
        .update_purchase_status(purchase_id_2, PurchaseStatus::Completed);
    assert(update_result_2, 'Failed to update status1');
    let update_result_3 = dispatcher
        .update_purchase_status(purchase_id_3, PurchaseStatus::Completed);
    assert(update_result_3, 'Failed to update status1');

    // Now the purchase should be verified
    let is_now_verified1 = dispatcher.verify_purchase(purchase_id_1);
    assert(is_now_verified1, 'Purchase should be verified');
    let is_now_verified2 = dispatcher.verify_purchase(purchase_id_2);
    assert(is_now_verified2, 'Purchase should be verified');
    let is_now_verified3 = dispatcher.verify_purchase(purchase_id_3);
    assert(is_now_verified3, 'Purchase should be verified');

    let receipt = dispatcher.get_receipt(1);

    assert(receipt.purchase_id == purchase_id_1, 'receipt error');

    start_cheat_caller_address(contract_address, user_address);
    start_cheat_block_timestamp(contract_address, 86400);
    dispatcher.request_refund(purchase_id_1, RefundRequestReason::MISREPRESENTED_CONTENT);
    stop_cheat_block_timestamp(contract_address);
    stop_cheat_caller_address(contract_address);

    start_cheat_caller_address(contract_address, admin_address);
    let refunds_array = dispatcher.get_user_refunds(user_id);
    let refund_request = refunds_array.at(0);

    start_cheat_caller_address(contract_address, admin_address);
    dispatcher.emergency_pause();
    stop_cheat_caller_address(contract_address);

    dispatcher.decline_refund(*refund_request.refund_id, user_id);
}


#[test]
fn test_contract_pause_and_unpause() {
    let (contract_address, admin_address, erc20_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    start_cheat_caller_address(contract_address, admin_address);
    dispatcher.emergency_pause();
    stop_cheat_caller_address(contract_address);

    let is_paused = dispatcher.is_paused();
    assert(is_paused, 'Contract should be paused');

    start_cheat_caller_address(contract_address, admin_address);
    dispatcher.emergency_unpause();
    stop_cheat_caller_address(contract_address);

    let is_unpaused = dispatcher.is_paused();
    assert(!is_unpaused, 'Contract should be unpaused');
}

#[test]
fn test_contract_pause_event() {
    let (contract_address, admin_address, erc20_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };
    let mut spy = spy_events();
    start_cheat_caller_address(contract_address, admin_address);
    dispatcher.emergency_pause();
    stop_cheat_caller_address(contract_address);
    spy
        .assert_emitted(
            @array![
                (
                    contract_address,
                    chain_lib::chainlib::ChainLib::ChainLib::Event::EmergencyPaused(
                        EmergencyPaused {
                            paused_by: admin_address, timestamp: get_block_timestamp(),
                        },
                    ),
                ),
            ],
        );
}


#[test]
#[should_panic(expected: 'Contract is paused')]
fn test_verify_purchase_should_panic_if_contract_paused() {
    let (contract_address, admin_address, erc20_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };
    let user_address = contract_address_const::<'user'>();

    token_faucet_and_allowance(dispatcher, user_address, erc20_address, 100000);
    // Set up test data
    let content_id: felt252 = 'content1';
    let price: u256 = 1000_u256;

    // Set admin as caller to set up content price
    cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);

    // Set up content with price
    setup_content_with_price(dispatcher, admin_address, contract_address, content_id, price);

    // Set user as caller
    cheat_caller_address(contract_address, user_address, CheatSpan::Indefinite);

    // Purchase the content
    let purchase_id = dispatcher.purchase_content(content_id, 'tx1');

    start_cheat_caller_address(contract_address, admin_address);
    dispatcher.emergency_pause();
    stop_cheat_caller_address(contract_address);

    // Initially, purchase should not be verified (status is Pending)
    let is_verified = dispatcher.verify_purchase(purchase_id);
    assert(!is_verified, 'Purchase should not be verified');
}


#[test]
#[should_panic(expected: 'Contract is paused')]
fn test_update_purchase_status_should_panic_if_contract_paused() {
    let (contract_address, admin_address, erc20_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };
    let user_address = contract_address_const::<'user'>();

    token_faucet_and_allowance(dispatcher, user_address, erc20_address, 100000);
    // Set up test data
    let content_id: felt252 = 'content1';
    let price: u256 = 1000_u256;

    // Set admin as caller to set up content price
    cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);

    // Set up content with price
    setup_content_with_price(dispatcher, admin_address, contract_address, content_id, price);

    // Set user as caller
    cheat_caller_address(contract_address, user_address, CheatSpan::Indefinite);

    // Purchase the content
    let purchase_id = dispatcher.purchase_content(content_id, 'tx1');

    // Initially, purchase should not be verified (status is Pending)
    let is_verified = dispatcher.verify_purchase(purchase_id);
    assert(!is_verified, 'Purchase should not be verified');

    // Set admin as caller to update the purchase status
    cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);

    start_cheat_caller_address(contract_address, admin_address);
    dispatcher.emergency_pause();
    stop_cheat_caller_address(contract_address);

    // Update purchase status to Completed
    let update_result = dispatcher.update_purchase_status(purchase_id, PurchaseStatus::Completed);
    assert(update_result, 'Failed to update status');

    // Now the purchase should be verified
    let is_now_verified = dispatcher.verify_purchase(purchase_id);
    assert(is_now_verified, 'Purchase should be verified');

    let receipt = dispatcher.get_receipt(1);

    assert(receipt.purchase_id == purchase_id, 'receipt error');
}


#[test]
#[should_panic(expected: 'Contract is paused')]
fn test_batch_payout_creators_should_panic_if_contract_paused() {
    let (contract_address, admin_address, erc20_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };
    let user_address = contract_address_const::<'user'>();
    let creator_1 = contract_address_const::<'creator_1'>();
    let creator_2 = contract_address_const::<'creator_2'>();
    let creator_3 = contract_address_const::<'creator_3'>();

    let username1: felt252 = 'creator_1';
    let username2: felt252 = 'creator_2';
    let username3: felt252 = 'creator_3';

    let role: Role = Role::WRITER;
    let rank: Rank = Rank::BEGINNER;
    let metadata: felt252 = 'john is a boy';

    start_cheat_caller_address(contract_address, creator_1);
    let creator1_id = dispatcher.register_user(username1, role.clone(), rank.clone(), metadata);
    println!("successfully registered creator_1 as writer");
    stop_cheat_caller_address(contract_address);

    start_cheat_caller_address(contract_address, creator_2);
    let creator2_id = dispatcher.register_user(username2, role.clone(), rank.clone(), metadata);
    stop_cheat_caller_address(contract_address);

    start_cheat_caller_address(contract_address, creator_3);
    let creator3_id = dispatcher.register_user(username3, role.clone(), rank.clone(), metadata);
    stop_cheat_caller_address(contract_address);

    start_cheat_caller_address(contract_address, admin_address);
    let is_creator_1_verified = dispatcher.verify_user(creator1_id);
    let is_creator_2_verified = dispatcher.verify_user(creator2_id);
    let is_creator_3_verified = dispatcher.verify_user(creator3_id);
    stop_cheat_caller_address(contract_address);

    let erc20_dispatcher = IERC20Dispatcher { contract_address: erc20_address };
    let creator_1_init_bal = erc20_dispatcher.balance_of(creator_1);
    let creator_2_init_bal = erc20_dispatcher.balance_of(creator_2);
    let creator_3_init_bal = erc20_dispatcher.balance_of(creator_3);

    token_faucet_and_allowance(dispatcher, user_address, erc20_address, 100000);
    // Set up test data
    let title1: felt252 = 'Creator 1 content';
    let title2: felt252 = 'Creator 2 content';
    let title3: felt252 = 'Creator 3 content';

    let description: felt252 = 'This is a test content';
    let content_type: ContentType = ContentType::Text;
    let category: Category = Category::Education;

    start_cheat_caller_address(contract_address, creator_1);
    let creator1_content_id: felt252 = dispatcher
        .register_content(title1, description, content_type, category);
    stop_cheat_caller_address(contract_address);

    start_cheat_caller_address(contract_address, creator_2);
    let creator2_content_id: felt252 = dispatcher
        .register_content(title2, description, content_type, category);
    stop_cheat_caller_address(contract_address);

    start_cheat_caller_address(contract_address, creator_3);
    let creator3_content_id: felt252 = dispatcher
        .register_content(title3, description, content_type, category);
    stop_cheat_caller_address(contract_address);
    let price_1: u256 = 1000_u256;
    let price_2: u256 = 2000_u256;
    let price_3: u256 = 1500_u256;

    // Set creator_1 as caller to set up content price
    cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);
    // Set up content with price
    setup_content_with_price(
        dispatcher, admin_address, contract_address, creator1_content_id, price_1,
    );

    // Set up content with price
    setup_content_with_price(
        dispatcher, admin_address, contract_address, creator2_content_id, price_2,
    );

    // Set up content with price
    setup_content_with_price(
        dispatcher, admin_address, contract_address, creator3_content_id, price_3,
    );

    // Set user as content consumer
    cheat_caller_address(contract_address, user_address, CheatSpan::Indefinite);

    // Purchase the content
    let purchase_id_1 = dispatcher.purchase_content(creator1_content_id, 'tx1');
    let purchase_id_2 = dispatcher.purchase_content(creator2_content_id, 'tx2');
    let purchase_id_3 = dispatcher.purchase_content(creator3_content_id, 'tx3');

    // Initially, purchase should not be verified (status is Pending)
    let is_purchase_1_verified = dispatcher.verify_purchase(purchase_id_1);
    let is_purchase_2_verified = dispatcher.verify_purchase(purchase_id_2);
    let is_purchase_3_verified = dispatcher.verify_purchase(purchase_id_3);
    assert(!is_purchase_1_verified, '1 should not be verified');
    assert(!is_purchase_2_verified, '2 should not be verified');
    assert(!is_purchase_3_verified, '3 should not be verified');

    // Set admin as caller to update the purchase status
    cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);
    cheat_block_timestamp(contract_address, 0, CheatSpan::Indefinite);

    // Update purchase status to Completed
    let update_result_1 = dispatcher
        .update_purchase_status(purchase_id_1, PurchaseStatus::Completed);
    assert(update_result_1, 'Failed to update status1');
    let update_result_2 = dispatcher
        .update_purchase_status(purchase_id_2, PurchaseStatus::Completed);
    assert(update_result_2, 'Failed to update status1');
    let update_result_3 = dispatcher
        .update_purchase_status(purchase_id_3, PurchaseStatus::Completed);
    assert(update_result_3, 'Failed to update status1');

    // Now the purchase should be verified
    let is_now_verified1 = dispatcher.verify_purchase(purchase_id_1);
    assert(is_now_verified1, 'Purchase should be verified');
    let is_now_verified2 = dispatcher.verify_purchase(purchase_id_2);
    assert(is_now_verified2, 'Purchase should be verified');
    let is_now_verified3 = dispatcher.verify_purchase(purchase_id_3);
    assert(is_now_verified3, 'Purchase should be verified');

    let receipt = dispatcher.get_receipt(1);

    assert(receipt.purchase_id == purchase_id_1, 'receipt error');

    // Still admin calling
    cheat_block_timestamp(contract_address, 86400 * 8, CheatSpan::Indefinite);
    // start_cheat_block_timestamp(contract_address);
    start_cheat_caller_address(contract_address, admin_address);
    dispatcher.emergency_pause();
    dispatcher.batch_payout_creators();
    stop_cheat_caller_address(contract_address);
}

