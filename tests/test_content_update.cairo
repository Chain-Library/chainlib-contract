use chain_lib::base::types::{Rank, Role};
use chain_lib::chainlib::ChainLib::ChainLib::{Category, ContentType, ContentUpdateType};
use chain_lib::interfaces::IChainLib::{IChainLibDispatcher, IChainLibDispatcherTrait};
use snforge_std::{
    spy_events, start_cheat_block_timestamp, start_cheat_caller_address, stop_cheat_block_timestamp,
    stop_cheat_caller_address,
};
use starknet::contract_address::contract_address_const;
use crate::test_utils::setup;

#[test]
fn test_update_content_basic() {
    let (contract_address, _admin_address, _erc20_address) = setup();
    let contract_instance = IChainLibDispatcher { contract_address };

    // Setup addresses
    let creator = contract_address_const::<'CREATOR'>();
    let content_id: felt252 = 0;

    // Set creator as caller
    start_cheat_caller_address(contract_address, creator);

    // Set current time
    let current_time: u64 = 1000;
    start_cheat_block_timestamp(contract_address, current_time);

    // Register user as WRITER first
    let username = 'Creator';
    let role = Role::WRITER;
    let rank = Rank::BEGINNER;
    let metadata = 'Test creator';

    // Register user
    contract_instance.register_user(username, role, rank, metadata);

    // Register content first
    let title = 'Original';
    let description = 'Original Desc';
    let content_type = ContentType::Text;
    let category = Category::Education;

    contract_instance.register_content(title, description, content_type, category);

    // Spy on events
    let mut spy = spy_events();

    // Update content
    let new_title = 'Updated';
    let new_description = 'Updated Desc';
    let new_content_type = ContentType::Video;
    let new_category = Category::Software;

    let result = contract_instance
        .update_content(
            content_id,
            new_title,
            new_description,
            Option::Some(new_content_type),
            Option::Some(new_category),
        );

    assert(result, 'Content update should succeed');

    // Verify content was updated
    let updated_content = contract_instance.get_content(content_id);
    assert(updated_content.title == new_title, 'Title updated');
    assert(updated_content.description == new_description, 'Desc updated');
    assert(updated_content.content_type == new_content_type, 'Type updated');
    assert(updated_content.category == new_category, 'Cat updated');
    assert(updated_content.version == 2, 'Version incremented');
    assert(updated_content.last_updated >= current_time, 'Time updated');

    // Verify event was emitted
    // let expected_event = Event::ContentUpdated(
    //     ContentUpdated {
    //         content_id,
    //         updater: creator,
    //         version: 2,
    //         update_type: ContentUpdateType::Full,
    //         timestamp: get_block_timestamp(),
    //     },
    // );
    // spy.assert_emitted(@array![(contract_address, expected_event)]);

    stop_cheat_caller_address(creator);
    stop_cheat_block_timestamp(contract_address);
}

#[test]
fn test_update_content_partial() {
    let (contract_address, _admin_address, _erc20_address) = setup();
    let contract_instance = IChainLibDispatcher { contract_address };

    // Setup addresses
    let creator = contract_address_const::<'CREATOR'>();
    let content_id: felt252 = 0;

    // Set creator as caller
    start_cheat_caller_address(contract_address, creator);

    // Set current time
    let current_time: u64 = 1000;
    start_cheat_block_timestamp(contract_address, current_time);

    // Register user as WRITER first
    let username = 'Creator';
    let role = Role::WRITER;
    let rank = Rank::BEGINNER;
    let metadata = 'Test creator';

    // Register user
    contract_instance.register_user(username, role, rank, metadata);

    // Register content first
    let title = 'Original';
    let description = 'Original Desc';
    let content_type = ContentType::Text;
    let category = Category::Education;

    contract_instance.register_content(title, description, content_type, category);

    // Spy on events
    let mut spy = spy_events();

    // Update only title
    let new_title = 'Updated';
    let result = contract_instance.update_content_title(content_id, new_title);

    assert(result, 'Title update succeed');

    // Verify only title was updated
    let updated_content = contract_instance.get_content(content_id);
    assert(updated_content.title == new_title, 'Title updated');
    assert(updated_content.description == description, 'Desc unchanged');
    assert(updated_content.content_type == content_type, 'Type unchanged');
    assert(updated_content.category == category, 'Cat unchanged');
    assert(updated_content.version == 2, 'Version incremented');

    // Verify event was emitted
    // let expected_event = Event::ContentUpdated(
    //     ContentUpdated {
    //         content_id,
    //         updater: creator,
    //         version: 2,
    //         update_type: ContentUpdateType::Title,
    //         timestamp: get_block_timestamp(),
    //     },
    // );
    // spy.assert_emitted(@array![(contract_address, expected_event)]);

    stop_cheat_caller_address(creator);
    stop_cheat_block_timestamp(contract_address);
}

#[test]
#[should_panic]
fn test_update_content_not_found() {
    let (contract_address, _admin_address, _erc20_address) = setup();
    let contract_instance = IChainLibDispatcher { contract_address };

    // Setup addresses
    let creator = contract_address_const::<'CREATOR'>();
    let non_existent_content_id: felt252 = 999;

    // Set creator as caller
    start_cheat_caller_address(contract_address, creator);

    // Try to update non-existent content
    contract_instance.update_content_title(non_existent_content_id, 'New Title');

    stop_cheat_caller_address(creator);
}

#[test]
#[should_panic]
fn test_update_content_unauthorized() {
    let (contract_address, _admin_address, _erc20_address) = setup();
    let contract_instance = IChainLibDispatcher { contract_address };

    // Setup addresses
    let creator = contract_address_const::<'CREATOR'>();
    let unauthorized_user = contract_address_const::<'UNAUTHORIZED'>();
    let content_id: felt252 = 0;

    // Set creator as caller to register content
    start_cheat_caller_address(contract_address, creator);

    // Register user as WRITER first
    let username = 'Creator';
    let role = Role::WRITER;
    let rank = Rank::BEGINNER;
    let metadata = 'Test creator';

    // Register user
    contract_instance.register_user(username, role, rank, metadata);

    // Register content
    contract_instance.register_content('Title', 'Desc', ContentType::Text, Category::Education);

    // Switch to unauthorized user
    start_cheat_caller_address(contract_address, unauthorized_user);

    // Try to update content as unauthorized user
    contract_instance.update_content_title(content_id, 'New Title');

    stop_cheat_caller_address(unauthorized_user);
}

#[test]
fn test_update_content_as_admin() {
    let (contract_address, admin_address, _erc20_address) = setup();
    let contract_instance = IChainLibDispatcher { contract_address };

    // Setup addresses
    let creator = contract_address_const::<'CREATOR'>();
    let content_id: felt252 = 0;

    // Set creator as caller to register content
    start_cheat_caller_address(contract_address, creator);

    // Register user as WRITER first
    let username = 'Creator';
    let role = Role::WRITER;
    let rank = Rank::BEGINNER;
    let metadata = 'Test creator';

    // Register user
    contract_instance.register_user(username, role, rank, metadata);

    // Register content
    contract_instance.register_content('Title', 'Desc', ContentType::Text, Category::Education);

    // Switch to admin
    start_cheat_caller_address(contract_address, admin_address);

    // Update content as admin
    let result = contract_instance.update_content_title(content_id, 'Admin Updated');

    assert(result, 'Admin can update');

    // Verify content was updated
    let updated_content = contract_instance.get_content(content_id);
    assert(updated_content.title == 'Admin Updated', 'Title updated by admin');
    assert(updated_content.version == 2, 'Version incremented');

    stop_cheat_caller_address(admin_address);
}

#[test]
fn test_content_update_history() {
    let (contract_address, _admin_address, _erc20_address) = setup();
    let contract_instance = IChainLibDispatcher { contract_address };

    // Setup addresses
    let creator = contract_address_const::<'CREATOR'>();
    let content_id: felt252 = 0;

    // Set creator as caller
    start_cheat_caller_address(contract_address, creator);

    // Set current time
    let current_time: u64 = 1000;
    start_cheat_block_timestamp(contract_address, current_time);

    // Register user as WRITER first
    let username = 'Creator';
    let role = Role::WRITER;
    let rank = Rank::BEGINNER;
    let metadata = 'Test creator';

    // Register user
    contract_instance.register_user(username, role, rank, metadata);

    // Register content
    contract_instance.register_content('Title', 'Desc', ContentType::Text, Category::Education);

    // Update content
    contract_instance.update_content_title(content_id, 'Updated');

    // Get update history
    let history = contract_instance.get_content_update_history(content_id, 2);

    // Verify history was recorded
    assert(history.content_id == content_id, 'Wrong content ID');
    assert(history.version == 2, 'Wrong version');
    assert(history.updater == creator, 'Wrong updater');
    assert(history.update_type == ContentUpdateType::Title, 'Wrong type');
    assert(history.previous_title == 'Title', 'Wrong prev title');
    assert(history.new_title == 'Updated', 'Wrong new title');

    stop_cheat_caller_address(creator);
    stop_cheat_block_timestamp(contract_address);
}

#[test]
fn test_content_version_tracking() {
    let (contract_address, _admin_address, _erc20_address) = setup();
    let contract_instance = IChainLibDispatcher { contract_address };

    // Setup addresses
    let creator = contract_address_const::<'CREATOR'>();
    let content_id: felt252 = 0;

    // Set creator as caller
    start_cheat_caller_address(contract_address, creator);

    // Register user as WRITER first
    let username = 'Creator';
    let role = Role::WRITER;
    let rank = Rank::BEGINNER;
    let metadata = 'Test creator';

    // Register user
    contract_instance.register_user(username, role, rank, metadata);

    // Register content
    contract_instance.register_content('Title', 'Desc', ContentType::Text, Category::Education);

    // Verify initial version after registration
    let initial_content = contract_instance.get_content(content_id);
    assert(initial_content.version == 1, 'Initial version 1');
    assert(contract_instance.get_content_update_count(content_id) == 0, 'Initial count 0');

    // Update content multiple times
    contract_instance.update_content_title(content_id, 'Title 2');
    contract_instance.update_content_description(content_id, 'Desc 2');
    contract_instance.update_content_type(content_id, ContentType::Video);

    // Verify version tracking
    assert(contract_instance.get_content_version(content_id) == 4, 'Version 4 after 3 updates');
    assert(contract_instance.get_content_update_count(content_id) == 3, 'Count 3');

    stop_cheat_caller_address(creator);
}

#[test]
fn test_can_update_content_permissions() {
    let (contract_address, admin_address, _erc20_address) = setup();
    let contract_instance = IChainLibDispatcher { contract_address };

    // Setup addresses
    let creator = contract_address_const::<'CREATOR'>();
    let unauthorized_user = contract_address_const::<'UNAUTHORIZED'>();
    let content_id: felt252 = 0;

    // Set creator as caller to register content
    start_cheat_caller_address(contract_address, creator);

    // Register user as WRITER first
    let username = 'Creator';
    let role = Role::WRITER;
    let rank = Rank::BEGINNER;
    let metadata = 'Test creator';

    // Register user
    contract_instance.register_user(username, role, rank, metadata);

    // Register content
    contract_instance.register_content('Title', 'Desc', ContentType::Text, Category::Education);

    // Test permissions
    assert(contract_instance.can_update_content(content_id, creator), 'Creator has permission');
    assert(contract_instance.can_update_content(content_id, admin_address), 'Admin has permission');
    assert(
        !contract_instance.can_update_content(content_id, unauthorized_user),
        'Unauthorized no permission',
    );

    stop_cheat_caller_address(creator);
}
