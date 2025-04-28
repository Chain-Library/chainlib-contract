// Import the contract modules
use chain_lib::interfaces::IChainLib::{IChainLibDispatcher, IChainLibDispatcherTrait};
use snforge_std::{CheatSpan, ContractClassTrait, DeclareResultTrait, cheat_caller_address, declare};
use starknet::ContractAddress;
use starknet::contract_address::contract_address_const;
use chain_lib::base::types::{Role, Rank, PurchaseStatus};

/// Helper function to create a content item with a price
/// We'll use the set_content_price function implemented in the contract
fn setup_content_with_price(
    dispatcher: IChainLibDispatcher,
    admin_address: ContractAddress,
    contract_address: ContractAddress,
    content_id: felt252,
    price: u256
) {
    // Set admin as caller for setting content price
    cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);

    // Use the new set_content_price function to set the price
    dispatcher.set_content_price(content_id, price);
}

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
    // Retrieve the user to verify user was stored correctly
    let user = dispatcher.retrieve_user_profile(account_id);
    assert(!user.verified, 'already verified');

    let verify = dispatcher.verify_user(user.id);
    assert(verify, 'Verification Falied');

    let verified_user = dispatcher.retrieve_user_profile(account_id);
    assert(verified_user.verified, 'Not Verified');
}

#[test]
fn test_purchase_content() {
    let (contract_address, admin_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };
    let user_address = contract_address_const::<'user'>();

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
    let (contract_address, _) = setup();
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
    let (contract_address, admin_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };
    let user_address = contract_address_const::<'user'>();

    // Set up multiple content items
    let content_id_1: felt252 = 'content1';
    let content_id_2: felt252 = 'content2';
    let price: u256 = 1000_u256;

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
    let (contract_address, admin_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };
    let user_address = contract_address_const::<'user'>();

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
}

#[test]
fn test_update_purchase_status() {
    let (contract_address, admin_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };
    let user_address = contract_address_const::<'user'>();

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
    let (contract_address, admin_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };
    let user_address = contract_address_const::<'user'>();

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
    let (contract_address, admin_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Set admin as caller
    cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);

    // Attempt to update a purchase that doesn't exist
    let nonexistent_purchase_id = 42_u256;
    let _ = dispatcher.update_purchase_status(nonexistent_purchase_id, PurchaseStatus::Completed);
}
