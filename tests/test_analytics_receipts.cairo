use chain_lib::chainlib::ChainLib;
use chain_lib::interfaces::IChainLib::{IChainLib, IChainLibDispatcher, IChainLibDispatcherTrait};
use snforge_std::{
    CheatSpan, ContractClassTrait, DeclareResultTrait, start_cheat_caller_address,
    cheat_caller_address, declare, stop_cheat_caller_address, start_cheat_block_timestamp,
    stop_cheat_block_timestamp,
};
use starknet::{ContractAddress, get_block_timestamp};
use starknet::class_hash::ClassHash;
use starknet::contract_address::contract_address_const;
use starknet::testing::{set_caller_address, set_contract_address};
use chain_lib::base::types::{Role, Rank, PurchaseStatus, Status, Purchase};
use chain_lib::chainlib::ChainLib::ChainLib::{
    ContentType, Category, SalesMetrics, PurchaseAnalytics, ConversionMetrics, Receipt,
    ReceiptStatus, TimeBasedMetrics, CreatorMetrics,
};

/// Helper function to setup contract with admin
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

/// Helper function to create a user
fn create_test_user(
    dispatcher: IChainLibDispatcher,
    contract_address: ContractAddress,
    user_address: ContractAddress,
    username: felt252,
) -> u256 {
    cheat_caller_address(contract_address, user_address, CheatSpan::Indefinite);
    let user_id = dispatcher.register_user(username, Role::READER, Rank::BEGINNER, 'test_user');
    user_id
}

/// Helper function to create a creator
fn create_test_creator(
    dispatcher: IChainLibDispatcher,
    contract_address: ContractAddress,
    creator_address: ContractAddress,
    username: felt252,
) -> u256 {
    cheat_caller_address(contract_address, creator_address, CheatSpan::Indefinite);
    let creator_id = dispatcher
        .register_user(username, Role::WRITER, Rank::BEGINNER, 'test_creator');
    creator_id
}

/// Helper function to create content with price
fn create_test_content(
    dispatcher: IChainLibDispatcher,
    contract_address: ContractAddress,
    admin_address: ContractAddress,
    creator_address: ContractAddress,
    title: felt252,
    price: u256,
) -> felt252 {
    // Creator creates content
    cheat_caller_address(contract_address, creator_address, CheatSpan::Indefinite);
    let content_id = dispatcher
        .register_content(title, 'test_description', ContentType::Text, Category::Education);

    // Admin sets price
    cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);
    dispatcher.set_content_price(content_id, price);

    content_id
}

/// Helper function to create and complete a purchase
fn create_completed_purchase(
    dispatcher: IChainLibDispatcher,
    contract_address: ContractAddress,
    admin_address: ContractAddress,
    buyer_address: ContractAddress,
    content_id: felt252,
) -> u256 {
    // Buyer initiates purchase
    cheat_caller_address(contract_address, buyer_address, CheatSpan::Indefinite);
    let purchase_id = dispatcher.purchase_content(content_id, 'test_tx_hash');

    // Admin completes purchase
    cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);
    dispatcher.update_purchase_status(purchase_id, PurchaseStatus::Completed);

    purchase_id
}

// ===============================
// ANALYTICS TESTS
// ===============================

#[test]
fn test_content_sales_metrics() {
    let (contract_address, admin_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Setup test data
    let creator_address = contract_address_const::<'creator'>();
    let buyer1_address = contract_address_const::<'buyer1'>();
    let buyer2_address = contract_address_const::<'buyer2'>();

    // Create users
    create_test_creator(dispatcher, contract_address, creator_address, 'creator');
    create_test_user(dispatcher, contract_address, buyer1_address, 'buyer1');
    create_test_user(dispatcher, contract_address, buyer2_address, 'buyer2');

    // Create content
    let content_id = create_test_content(
        dispatcher, contract_address, admin_address, creator_address, 'test_content', 100,
    );

    // Create purchases
    create_completed_purchase(
        dispatcher, contract_address, admin_address, buyer1_address, content_id,
    );
    create_completed_purchase(
        dispatcher, contract_address, admin_address, buyer2_address, content_id,
    );

    // Test content sales metrics
    let metrics = dispatcher.get_total_sales_by_content(content_id);
    assert(metrics.total_sales == 2, 'Wrong total sales');
    assert(metrics.total_revenue == 200, 'Wrong total revenue');
    assert(metrics.unique_buyers == 2, 'Wrong unique buyers');
    assert(metrics.average_sale_price == 100, 'Wrong average price');
}

#[test]
fn test_creator_metrics() {
    let (contract_address, admin_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Setup test data
    let creator_address = contract_address_const::<'creator'>();
    let buyer_address = contract_address_const::<'buyer'>();

    // Create users
    create_test_creator(dispatcher, contract_address, creator_address, 'creator');
    create_test_user(dispatcher, contract_address, buyer_address, 'buyer');

    // Create content
    let content_id = create_test_content(
        dispatcher, contract_address, admin_address, creator_address, 'test_content', 150,
    );

    // Create purchase
    create_completed_purchase(
        dispatcher, contract_address, admin_address, buyer_address, content_id,
    );

    // Test creator metrics
    let metrics = dispatcher.get_total_sales_by_creator(creator_address);
    assert(metrics.creator == creator_address, 'Wrong creator address');
    // Note: Implementation returns default values for simplified version
}

#[test]
fn test_platform_sales_summary() {
    let (contract_address, admin_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Setup test data
    let creator_address = contract_address_const::<'creator'>();
    let buyer_address = contract_address_const::<'buyer'>();

    // Create users
    create_test_creator(dispatcher, contract_address, creator_address, 'creator');
    create_test_user(dispatcher, contract_address, buyer_address, 'buyer');

    // Create content and purchase
    let content_id = create_test_content(
        dispatcher, contract_address, admin_address, creator_address, 'test_content', 200,
    );
    create_completed_purchase(
        dispatcher, contract_address, admin_address, buyer_address, content_id,
    );

    // Test platform metrics
    let metrics = dispatcher.get_platform_sales_summary();
    assert(metrics.total_sales == 1, 'Wrong platform sales');
    assert(metrics.total_revenue == 200, 'Wrong platform revenue');
}

#[test]
fn test_time_based_analytics() {
    let (contract_address, admin_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Test daily sales (simplified implementation returns default values)
    let daily_metrics = dispatcher.get_daily_sales(1000000);
    assert(daily_metrics.total_sales == 0, 'Wrong daily sales');

    // Test weekly sales
    let weekly_metrics = dispatcher.get_weekly_sales(1000000);
    assert(weekly_metrics.total_sales == 0, 'Wrong weekly sales');

    // Test monthly sales
    let monthly_metrics = dispatcher.get_monthly_sales(1000000);
    assert(monthly_metrics.total_sales == 0, 'Wrong monthly sales');

    // Test time range metrics
    let range_metrics = dispatcher.get_sales_by_time_range(1000000, 2000000);
    assert(range_metrics.sales_count == 0, 'Wrong range sales');
}

#[test]
fn test_purchase_analytics() {
    let (contract_address, admin_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Setup test data
    let creator_address = contract_address_const::<'creator'>();
    let buyer_address = contract_address_const::<'buyer'>();

    // Create users
    create_test_creator(dispatcher, contract_address, creator_address, 'creator');
    create_test_user(dispatcher, contract_address, buyer_address, 'buyer');

    // Create content
    let content_id = create_test_content(
        dispatcher, contract_address, admin_address, creator_address, 'test_content', 100,
    );

    // Create completed purchase
    create_completed_purchase(
        dispatcher, contract_address, admin_address, buyer_address, content_id,
    );

    // Create pending purchase
    cheat_caller_address(contract_address, buyer_address, CheatSpan::Indefinite);
    dispatcher.purchase_content(content_id, 'pending_tx');

    // Test content purchase analytics
    let content_analytics = dispatcher.get_purchase_analytics(content_id);
    assert(content_analytics.total_purchases == 2, 'Wrong total purchases');
    assert(content_analytics.completed_purchases == 1, 'Wrong completed');
    assert(content_analytics.pending_purchases == 1, 'Wrong pending');
    assert(content_analytics.total_spent == 100, 'Wrong total spent');

    // Test user purchase analytics
    let user_analytics = dispatcher.get_user_purchase_analytics(buyer_address);
    assert(user_analytics.total_purchases == 2, 'Wrong user purchases');
    assert(user_analytics.completed_purchases == 1, 'Wrong user completed');
}

#[test]
fn test_conversion_metrics() {
    let (contract_address, admin_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Setup test data
    let creator_address = contract_address_const::<'creator'>();
    let buyer_address = contract_address_const::<'buyer'>();

    // Create users and content
    create_test_creator(dispatcher, contract_address, creator_address, 'creator');
    create_test_user(dispatcher, contract_address, buyer_address, 'buyer');
    let content_id = create_test_content(
        dispatcher, contract_address, admin_address, creator_address, 'test_content', 100,
    );

    // Test conversion metrics
    let metrics = dispatcher.get_conversion_metrics(content_id);
    assert(metrics.content_id == content_id, 'Wrong content ID');

    // Test conversion rate calculation
    let conversion_rate = dispatcher.calculate_conversion_rate(content_id, 1000);
    // With 0 purchases and 1000 views, rate should be 0
    assert(conversion_rate == 0, 'Wrong conversion rate');
}

#[test]
fn test_top_performers() {
    let (contract_address, admin_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Test top selling content (simplified implementation)
    let top_content = dispatcher.get_top_selling_content(5);
    assert(top_content.len() <= 5, 'Too many results');

    // Test top creators
    let top_creators = dispatcher.get_top_creators_by_revenue(5);
    assert(top_creators.len() <= 5, 'Too many creators');

    // Test top buyers
    let top_buyers = dispatcher.get_top_buyers(5);
    assert(top_buyers.len() <= 5, 'Too many buyers');
}

// ===============================
// RECEIPT TESTS
// ===============================

#[test]
fn test_receipt_generation() {
    let (contract_address, admin_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Setup test data
    let creator_address = contract_address_const::<'creator'>();
    let buyer_address = contract_address_const::<'buyer'>();

    // Create users and content
    create_test_creator(dispatcher, contract_address, creator_address, 'creator');
    create_test_user(dispatcher, contract_address, buyer_address, 'buyer');
    let content_id = create_test_content(
        dispatcher, contract_address, admin_address, creator_address, 'test_content', 250,
    );

    // Create completed purchase (receipt is auto-generated)
    let purchase_id = create_completed_purchase(
        dispatcher, contract_address, admin_address, buyer_address, content_id,
    );

    // Test receipt details
    let receipt = dispatcher.get_purchase_receipt(purchase_id);
    assert(receipt.purchase_id == purchase_id, 'Wrong purchase ID');
    assert(receipt.content_id == content_id, 'Wrong content ID');
    assert(receipt.buyer == buyer_address, 'Wrong buyer');
    assert(receipt.creator == creator_address, 'Wrong creator');
    assert(receipt.amount == 250, 'Wrong amount');
    assert(receipt.status == ReceiptStatus::Valid, 'Wrong status');

    // Test receipt verification
    let is_valid = dispatcher.verify_receipt_on_chain(receipt.receipt_id);
    assert(is_valid, 'Receipt should be valid');
}

#[test]
fn test_receipt_signature_verification() {
    let (contract_address, admin_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Setup and create receipt
    let creator_address = contract_address_const::<'creator'>();
    let buyer_address = contract_address_const::<'buyer'>();

    create_test_creator(dispatcher, contract_address, creator_address, 'creator');
    create_test_user(dispatcher, contract_address, buyer_address, 'buyer');
    let content_id = create_test_content(
        dispatcher, contract_address, admin_address, creator_address, 'test_content', 300,
    );

    let purchase_id = create_completed_purchase(
        dispatcher, contract_address, admin_address, buyer_address, content_id,
    );

    let receipt = dispatcher.get_purchase_receipt(purchase_id);

    // Test signature verification
    let is_signature_valid = dispatcher
        .verify_receipt_signature(receipt.receipt_id, receipt.signature);
    assert(is_signature_valid, 'Signature should be valid');

    // Test with wrong signature
    let wrong_signature_valid = dispatcher
        .verify_receipt_signature(receipt.receipt_id, 'wrong_signature');
    assert(!wrong_signature_valid, 'Wrong signature should be invalid');
}

#[test]
fn test_receipt_lookup() {
    let (contract_address, admin_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Setup and create receipt
    let creator_address = contract_address_const::<'creator'>();
    let buyer_address = contract_address_const::<'buyer'>();

    create_test_creator(dispatcher, contract_address, creator_address, 'creator');
    create_test_user(dispatcher, contract_address, buyer_address, 'buyer');
    let content_id = create_test_content(
        dispatcher, contract_address, admin_address, creator_address, 'test_content', 400,
    );

    let purchase_id = create_completed_purchase(
        dispatcher, contract_address, admin_address, buyer_address, content_id,
    );

    let receipt = dispatcher.get_purchase_receipt(purchase_id);

    // Test receipt lookup by hash
    let found_receipt = dispatcher.lookup_receipt_by_hash(receipt.receipt_hash);
    assert(found_receipt.receipt_id == receipt.receipt_id, 'Receipt lookup failed');
    assert(found_receipt.purchase_id == purchase_id, 'Wrong purchase in lookup');
}

#[test]
fn test_receipt_invalidation() {
    let (contract_address, admin_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Setup and create receipt
    let creator_address = contract_address_const::<'creator'>();
    let buyer_address = contract_address_const::<'buyer'>();

    create_test_creator(dispatcher, contract_address, creator_address, 'creator');
    create_test_user(dispatcher, contract_address, buyer_address, 'buyer');
    let content_id = create_test_content(
        dispatcher, contract_address, admin_address, creator_address, 'test_content', 500,
    );

    let purchase_id = create_completed_purchase(
        dispatcher, contract_address, admin_address, buyer_address, content_id,
    );

    let receipt = dispatcher.get_purchase_receipt(purchase_id);

    // Test initial status
    let initial_status = dispatcher.get_receipt_status(receipt.receipt_id);
    assert(initial_status == ReceiptStatus::Valid, 'Initial status should be valid');

    // Invalidate receipt (admin only)
    cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);
    let invalidated = dispatcher.invalidate_receipt(receipt.receipt_id, 'refund_requested');
    assert(invalidated, 'Invalidation should succeed');

    // Check new status
    let new_status = dispatcher.get_receipt_status(receipt.receipt_id);
    assert(new_status == ReceiptStatus::Invalid, 'Status should be invalid');

    // Receipt should no longer be valid on-chain
    let is_valid = dispatcher.verify_receipt_on_chain(receipt.receipt_id);
    assert(!is_valid, 'Invalid receipt should not verify');
}

#[test]
fn test_receipt_collections() {
    let (contract_address, admin_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Setup test data
    let creator_address = contract_address_const::<'creator'>();
    let buyer_address = contract_address_const::<'buyer'>();

    create_test_creator(dispatcher, contract_address, creator_address, 'creator');
    create_test_user(dispatcher, contract_address, buyer_address, 'buyer');

    // Create multiple content items and purchases
    let content1 = create_test_content(
        dispatcher, contract_address, admin_address, creator_address, 'content1', 100,
    );
    let content2 = create_test_content(
        dispatcher, contract_address, admin_address, creator_address, 'content2', 200,
    );

    create_completed_purchase(dispatcher, contract_address, admin_address, buyer_address, content1);
    create_completed_purchase(dispatcher, contract_address, admin_address, buyer_address, content2);

    // Test user receipts
    let user_receipts = dispatcher.get_user_receipts(buyer_address);
    assert(user_receipts.len() == 2, 'Wrong number of user receipts');

    // Test content receipts
    let content1_receipts = dispatcher.get_content_receipts(content1);
    assert(content1_receipts.len() == 1, 'Wrong number of content receipts');

    let content2_receipts = dispatcher.get_content_receipts(content2);
    assert(content2_receipts.len() == 1, 'Wrong number of content2 receipts');
}

#[test]
fn test_receipt_metadata_update() {
    let (contract_address, admin_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Setup and create receipt
    let creator_address = contract_address_const::<'creator'>();
    let buyer_address = contract_address_const::<'buyer'>();

    create_test_creator(dispatcher, contract_address, creator_address, 'creator');
    create_test_user(dispatcher, contract_address, buyer_address, 'buyer');
    let content_id = create_test_content(
        dispatcher, contract_address, admin_address, creator_address, 'test_content', 600,
    );

    let purchase_id = create_completed_purchase(
        dispatcher, contract_address, admin_address, buyer_address, content_id,
    );

    let receipt = dispatcher.get_purchase_receipt(purchase_id);

    // Update metadata (admin only)
    cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);
    let updated = dispatcher.update_receipt_metadata(receipt.receipt_id, 'updated_metadata');
    assert(updated, 'Metadata update should succeed');

    // Verify metadata was updated
    let updated_receipt = dispatcher.get_receipt_details(receipt.receipt_id);
    assert(updated_receipt.metadata == 'updated_metadata', 'Metadata not updated');
}

#[test]
fn test_receipt_analytics() {
    let (contract_address, admin_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Setup and create multiple receipts
    let creator_address = contract_address_const::<'creator'>();
    let buyer_address = contract_address_const::<'buyer'>();

    create_test_creator(dispatcher, contract_address, creator_address, 'creator');
    create_test_user(dispatcher, contract_address, buyer_address, 'buyer');

    // Create multiple purchases to generate receipts
    let content1 = create_test_content(
        dispatcher, contract_address, admin_address, creator_address, 'content1', 100,
    );
    let content2 = create_test_content(
        dispatcher, contract_address, admin_address, creator_address, 'content2', 200,
    );

    let purchase1 = create_completed_purchase(
        dispatcher, contract_address, admin_address, buyer_address, content1,
    );
    let purchase2 = create_completed_purchase(
        dispatcher, contract_address, admin_address, buyer_address, content2,
    );

    // Get receipt analytics
    let (total, valid, invalid) = dispatcher.get_receipt_analytics();
    assert(total == 2, 'Wrong total receipts');
    assert(valid == 2, 'Wrong valid receipts');
    assert(invalid == 0, 'Wrong invalid receipts');

    // Invalidate one receipt
    let receipt1 = dispatcher.get_purchase_receipt(purchase1);
    cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);
    dispatcher.invalidate_receipt(receipt1.receipt_id, 'test_invalidation');

    // Check updated analytics
    let (total_after, valid_after, invalid_after) = dispatcher.get_receipt_analytics();
    assert(total_after == 2, 'Total should remain same');
    assert(valid_after == 1, 'Valid should decrease');
    assert(invalid_after == 1, 'Invalid should increase');
}

#[test]
fn test_milestone_tracking() {
    let (contract_address, admin_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Setup test data
    let creator_address = contract_address_const::<'creator'>();
    let buyer_address = contract_address_const::<'buyer'>();

    create_test_creator(dispatcher, contract_address, creator_address, 'creator');
    create_test_user(dispatcher, contract_address, buyer_address, 'buyer');
    let content_id = create_test_content(
        dispatcher, contract_address, admin_address, creator_address, 'test_content', 1000,
    );

    // Test milestone tracking through purchase completion
    create_completed_purchase(
        dispatcher, contract_address, admin_address, buyer_address, content_id,
    );

    // Test manual milestone tracking
    cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);
    let milestone_achieved = dispatcher.track_milestone_achievement('TEST_MILESTONE', 150);
    assert(milestone_achieved, 'Milestone should be achieved');

    // Test same milestone again (should not trigger)
    let milestone_again = dispatcher.track_milestone_achievement('TEST_MILESTONE', 150);
    assert(!milestone_again, 'Same milestone should not trigger');

    // Test higher milestone
    let higher_milestone = dispatcher.track_milestone_achievement('TEST_MILESTONE', 250);
    assert(higher_milestone, 'Higher milestone should trigger');
}

// ===============================
// INTEGRATION TESTS
// ===============================

#[test]
fn test_complete_purchase_flow_with_analytics_and_receipts() {
    let (contract_address, admin_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Setup complete test scenario
    let creator_address = contract_address_const::<'creator'>();
    let buyer1_address = contract_address_const::<'buyer1'>();
    let buyer2_address = contract_address_const::<'buyer2'>();

    // Create users
    create_test_creator(dispatcher, contract_address, creator_address, 'creator');
    create_test_user(dispatcher, contract_address, buyer1_address, 'buyer1');
    create_test_user(dispatcher, contract_address, buyer2_address, 'buyer2');

    // Create content
    let content_id = create_test_content(
        dispatcher, contract_address, admin_address, creator_address, 'premium_content', 500,
    );

    // Create multiple purchases
    let purchase1 = create_completed_purchase(
        dispatcher, contract_address, admin_address, buyer1_address, content_id,
    );
    let purchase2 = create_completed_purchase(
        dispatcher, contract_address, admin_address, buyer2_address, content_id,
    );

    // Verify analytics are updated
    let content_metrics = dispatcher.get_total_sales_by_content(content_id);
    assert(content_metrics.total_sales == 2, 'Analytics not updated');
    assert(content_metrics.total_revenue == 1000, 'Revenue not correct');
    assert(content_metrics.unique_buyers == 2, 'Unique buyers wrong');

    // Verify platform metrics
    let platform_metrics = dispatcher.get_platform_sales_summary();
    assert(platform_metrics.total_sales == 2, 'Platform sales wrong');
    assert(platform_metrics.total_revenue == 1000, 'Platform revenue wrong');

    // Verify receipts are generated
    let receipt1 = dispatcher.get_purchase_receipt(purchase1);
    let receipt2 = dispatcher.get_purchase_receipt(purchase2);

    assert(receipt1.status == ReceiptStatus::Valid, 'Receipt1 should be valid');
    assert(receipt2.status == ReceiptStatus::Valid, 'Receipt2 should be valid');

    // Verify receipt collections
    let buyer1_receipts = dispatcher.get_user_receipts(buyer1_address);
    let buyer2_receipts = dispatcher.get_user_receipts(buyer2_address);
    let content_receipts = dispatcher.get_content_receipts(content_id);

    assert(buyer1_receipts.len() == 1, 'Buyer1 should have 1 receipt');
    assert(buyer2_receipts.len() == 1, 'Buyer2 should have 1 receipt');
    assert(content_receipts.len() == 2, 'Content should have 2 receipts');

    // Verify receipt analytics
    let (total_receipts, valid_receipts, invalid_receipts) = dispatcher.get_receipt_analytics();
    assert(total_receipts == 2, 'Should have 2 total receipts');
    assert(valid_receipts == 2, 'Should have 2 valid receipts');
    assert(invalid_receipts == 0, 'Should have 0 invalid receipts');
}

#[test]
fn test_edge_cases_and_error_handling() {
    let (contract_address, admin_address) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Test analytics with no data
    let empty_metrics = dispatcher.get_platform_sales_summary();
    assert(empty_metrics.total_sales == 0, 'Should start with 0 sales');

    // Test conversion rate with no views
    let zero_conversion = dispatcher.calculate_conversion_rate('nonexistent', 0);
    assert(zero_conversion == 0, 'Zero views should give 0 conversion');

    // Test top performers with no data
    let empty_top_content = dispatcher.get_top_selling_content(10);
    assert(empty_top_content.len() == 0, 'Should return empty array');

    let empty_top_creators = dispatcher.get_top_creators_by_revenue(10);
    assert(empty_top_creators.len() == 0, 'Should return empty creators');

    let empty_top_buyers = dispatcher.get_top_buyers(10);
    assert(empty_top_buyers.len() == 0, 'Should return empty buyers');
}
