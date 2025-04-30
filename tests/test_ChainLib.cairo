// Import the contract modules
use chain_lib::chainlib::ChainLib;

use chain_lib::interfaces::IChainLib::{IChainLib, IChainLibDispatcher, IChainLibDispatcherTrait};
use snforge_std::{
    CheatSpan, ContractClassTrait, DeclareResultTrait, cheat_caller_address, declare, spy_events,
    EventSpy, EventSpyAssertionsTrait
};
use starknet::ContractAddress;
use starknet::class_hash::ClassHash;
use starknet::contract_address::contract_address_const;
use starknet::testing::{set_caller_address, set_contract_address};
use chain_lib::base::types::{Role, Rank};
use chain_lib::chainlib::ChainLib::ChainLib::{ContentType, Category, ContentMetadata};


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
#[should_panic(expected: ('Only admin can verify users',))]
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
fn test_register_content() {
    let (contract_address, _) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    let mut spy = spy_events();

    let title: felt252 = 'My Content';
    let description: felt252 = 'This is a test content';
    let content_type: ContentType = ContentType::Text;
    let category: Category = Category::Education;
    let caller_address: ContractAddress = contract_address_const::<'creator'>();

    // Register a user with WRITER role
    let username: felt252 = 'John';
    let role: Role = Role::WRITER;
    let rank: Rank = Rank::BEGINNER;
    let metadata: felt252 = 'john is a boy';

    // Set caller address for user registration
    cheat_caller_address(contract_address, caller_address, CheatSpan::Indefinite);

    // Call register_user
    let user_id = dispatcher.register_user(username, role.clone(), rank.clone(), metadata);

    // Verify user registration
    let user = dispatcher.retrieve_user_profile(user_id);
    assert(user.role == Role::WRITER, 'User role not WRITER');

    // Register content
    let content_id = dispatcher.register_content(title, description, content_type, category);

    // Verify content ID starts from 0
    assert(content_id == 0, 'content_id should start from 0');

    // Retrieve and verify content metadata
    let content = dispatcher.get_content(content_id);
    assert(content.content_id == content_id, 'content_id mismatch');
    assert(content.title == title, 'title mismatch');
    assert(content.description == description, 'description mismatch');
    assert(content.content_type == content_type, 'content_type mismatch');
    assert(content.creator == caller_address, 'creator mismatch');
    assert(content.category == category, 'category mismatch');

    // Verify that the ContentRegistered event was emitted with correct parameters
    spy
        .assert_emitted(
            @array![
                (
                    contract_address,
                    chain_lib::chainlib::ChainLib::ChainLib::Event::ContentRegistered(
                        chain_lib::chainlib::ChainLib::ChainLib::ContentRegistered {
                            content_id: content_id, creator: caller_address
                        }
                    )
                )
            ]
        );
}

#[test]
fn test_register_content_with_different_types() {
    let (contract_address, _) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    let mut spy = spy_events();

    // Test with different content types and categories
    let title: felt252 = 'Video Tutorial';
    let description: felt252 = 'Cairo programming';
    let content_type: ContentType = ContentType::Video;
    let category: Category = Category::Software;
    let creator_address: ContractAddress = contract_address_const::<'video_creator'>();

    // Register a user with WRITER role
    let username: felt252 = 'VideoCreator';
    let role: Role = Role::WRITER;
    let rank: Rank = Rank::INTERMEDIATE;
    let metadata: felt252 = 'Professional video creator';

    // Set caller address for user registration
    cheat_caller_address(contract_address, creator_address, CheatSpan::Indefinite);

    // Call register_user
    let user_id = dispatcher.register_user(username, role.clone(), rank.clone(), metadata);

    // Register content
    let content_id = dispatcher.register_content(title, description, content_type, category);

    // Verify content was registered correctly
    let content = dispatcher.get_content(content_id);
    assert(content.content_type == ContentType::Video, 'content_type mismatch');
    assert(content.category == Category::Software, 'category mismatch');
    assert(content.creator == creator_address, 'creator mismatch');

    // Verify event emission
    spy
        .assert_emitted(
            @array![
                (
                    contract_address,
                    chain_lib::chainlib::ChainLib::ChainLib::Event::ContentRegistered(
                        chain_lib::chainlib::ChainLib::ChainLib::ContentRegistered {
                            content_id: content_id, creator: creator_address
                        }
                    )
                )
            ]
        );

    // Register another content with different type
    let image_title: felt252 = 'Infographic';
    let image_description: felt252 = 'Visual of Cairo concepts';
    let image_content_type: ContentType = ContentType::Image;
    let image_category: Category = Category::Education;

    let image_content_id = dispatcher
        .register_content(image_title, image_description, image_content_type, image_category);

    // Verify second content was registered with a new ID
    assert(image_content_id == content_id + 1, 'content_id not incremented');

    let image_content = dispatcher.get_content(image_content_id);
    assert(image_content.content_type == ContentType::Image, 'image type mismatch');
    assert(image_content.category == Category::Education, 'image category mismatch');
}

#[test]
#[should_panic]
fn test_register_content_not_writer() {
    let (contract_address, _) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    let title: felt252 = 'Unauthorized Content';
    let description: felt252 = 'This  should not be registered';
    let content_type: ContentType = ContentType::Text;
    let category: Category = Category::Literature;
    let reader_address: ContractAddress = contract_address_const::<'reader'>();

    // Register a user with READER role (not WRITER)
    let username: felt252 = 'Reader';
    let role: Role = Role::READER;
    let rank: Rank = Rank::BEGINNER;
    let metadata: felt252 = 'Just a reader';

    // Set caller address for user registration
    cheat_caller_address(contract_address, reader_address, CheatSpan::Indefinite);

    // Call register_user with READER role
    let user_id = dispatcher.register_user(username, role.clone(), rank.clone(), metadata);

    // Attempt to register content - this should fail
    dispatcher.register_content(title, description, content_type, category);
    // The test should panic for any reason
}

#[test]
#[should_panic]
fn test_register_content_empty_title() {
    let (contract_address, _) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Set up content with empty title
    let title: felt252 = 0; // Empty title
    let description: felt252 = 'Valid description';
    let content_type: ContentType = ContentType::Text;
    let category: Category = Category::Education;
    let creator_address: ContractAddress = contract_address_const::<'empty_title_creator'>();

    // Register a user with WRITER role
    let username: felt252 = 'EmptyTitleCreator';
    let role: Role = Role::WRITER;
    let rank: Rank = Rank::BEGINNER;
    let metadata: felt252 = 'Creator testing empty title';

    // Set caller address for user registration
    cheat_caller_address(contract_address, creator_address, CheatSpan::Indefinite);

    // Call register_user
    let user_id = dispatcher.register_user(username, role.clone(), rank.clone(), metadata);

    // Attempt to register content with empty title - should panic
    dispatcher.register_content(title, description, content_type, category);
    // Test should panic with "Title cannot be empty"
}

#[test]
#[should_panic]
fn test_register_content_empty_description() {
    let (contract_address, _) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Set up content with empty description
    let title: felt252 = 'Valid Title';
    let description: felt252 = 0; // Empty description
    let content_type: ContentType = ContentType::Text;
    let category: Category = Category::Literature;
    let creator_address: ContractAddress = contract_address_const::<'empty_desc_creator'>();

    // Register a user with WRITER role
    let username: felt252 = 'EmptyDescCreator';
    let role: Role = Role::WRITER;
    let rank: Rank = Rank::EXPERT;
    let metadata: felt252 = 'testing empty description';

    // Set caller address for user registration
    cheat_caller_address(contract_address, creator_address, CheatSpan::Indefinite);

    // Call register_user
    let user_id = dispatcher.register_user(username, role.clone(), rank.clone(), metadata);

    // Attempt to register content with empty description - should panic
    dispatcher.register_content(title, description, content_type, category);
    // Test should panic with "Description cannot be empty"
}

#[test]
fn test_register_content_multiple_users() {
    let (contract_address, _) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    let mut spy = spy_events();

    // First user setup
    let first_user_address: ContractAddress = contract_address_const::<'first_creator'>();
    let first_username: felt252 = 'FirstCreator';
    let first_role: Role = Role::WRITER;
    let first_rank: Rank = Rank::BEGINNER;
    let first_metadata: felt252 = 'First content creator';

    // Set caller address for first user registration
    cheat_caller_address(contract_address, first_user_address, CheatSpan::Indefinite);

    // Register first user
    let first_user_id = dispatcher
        .register_user(first_username, first_role.clone(), first_rank.clone(), first_metadata);

    // First user registers content
    let first_title: felt252 = 'First Content';
    let first_description: felt252 = 'Content by first user';
    let first_content_type: ContentType = ContentType::Text;
    let first_category: Category = Category::Education;

    let first_content_id = dispatcher
        .register_content(first_title, first_description, first_content_type, first_category);

    // Verify first content ID is 0
    assert(first_content_id == 0, 'First content_id should be 0');

    // Second user setup
    let second_user_address: ContractAddress = contract_address_const::<'second_creator'>();
    let second_username: felt252 = 'SecondCreator';
    let second_role: Role = Role::WRITER;
    let second_rank: Rank = Rank::INTERMEDIATE;
    let second_metadata: felt252 = 'Second content creator';

    // Set caller address for second user registration
    cheat_caller_address(contract_address, second_user_address, CheatSpan::Indefinite);

    // Register second user
    let second_user_id = dispatcher
        .register_user(second_username, second_role.clone(), second_rank.clone(), second_metadata);

    // Second user registers content
    let second_title: felt252 = 'Second Content';
    let second_description: felt252 = 'Content by second user';
    let second_content_type: ContentType = ContentType::Video;
    let second_category: Category = Category::Software;

    let second_content_id = dispatcher
        .register_content(second_title, second_description, second_content_type, second_category);

    // Verify second content ID is incremented
    assert(second_content_id == first_content_id + 1, ' content_id not incremented');

    // Verify content creators are correctly recorded
    let first_content = dispatcher.get_content(first_content_id);
    let second_content = dispatcher.get_content(second_content_id);

    assert(first_content.creator == first_user_address, 'First creator mismatch');
    assert(second_content.creator == second_user_address, 'Second creator mismatch');

    // Verify events were emitted for both content registrations
    spy
        .assert_emitted(
            @array![
                (
                    contract_address,
                    chain_lib::chainlib::ChainLib::ChainLib::Event::ContentRegistered(
                        chain_lib::chainlib::ChainLib::ChainLib::ContentRegistered {
                            content_id: first_content_id, creator: first_user_address
                        }
                    )
                ),
                (
                    contract_address,
                    chain_lib::chainlib::ChainLib::ChainLib::Event::ContentRegistered(
                        chain_lib::chainlib::ChainLib::ChainLib::ContentRegistered {
                            content_id: second_content_id, creator: second_user_address
                        }
                    )
                )
            ]
        );
}

#[test]
fn test_content_metadata_retrieval() {
    let (contract_address, _) = setup();
    let dispatcher = IChainLibDispatcher { contract_address };

    // Create a user with WRITER role
    let creator_address: ContractAddress = contract_address_const::<'metadata_creator'>();
    let username: felt252 = 'MetadataCreator';
    let role: Role = Role::WRITER;
    let rank: Rank = Rank::INTERMEDIATE;
    let user_metadata: felt252 = 'Content metadata tester';

    // Set caller address for user registration
    cheat_caller_address(contract_address, creator_address, CheatSpan::Indefinite);

    // Register the user
    let _user_id = dispatcher.register_user(username, role.clone(), rank.clone(), user_metadata);

    // Register different types of content

    // 1. Text content in Education category
    let text_title: felt252 = 'Text Article';
    let text_description: felt252 = 'Educational text';
    let text_content_type: ContentType = ContentType::Text;
    let text_category: Category = Category::Education;

    let text_content_id = dispatcher
        .register_content(text_title, text_description, text_content_type, text_category);

    // 2. Image content in Art category
    let image_title: felt252 = 'Art Image';
    let image_description: felt252 = 'Artistic image';
    let image_content_type: ContentType = ContentType::Image;
    let image_category: Category = Category::Art;

    let image_content_id = dispatcher
        .register_content(image_title, image_description, image_content_type, image_category);

    // 3. Video content in Software category
    let video_title: felt252 = 'Tutorial Video';
    let video_description: felt252 = 'Software tutorial';
    let video_content_type: ContentType = ContentType::Video;
    let video_category: Category = Category::Software;

    let video_content_id = dispatcher
        .register_content(video_title, video_description, video_content_type, video_category);

    // Retrieve and verify all content metadata
    let text_content = dispatcher.get_content(text_content_id);
    let image_content = dispatcher.get_content(image_content_id);
    let video_content = dispatcher.get_content(video_content_id);

    // Verify text content metadata
    assert(text_content.content_id == text_content_id, 'Text ID mismatch');
    assert(text_content.title == text_title, 'Text title mismatch');
    assert(text_content.description == text_description, 'Text desc mismatch');
    assert(text_content.content_type == text_content_type, 'Text type mismatch');
    assert(text_content.category == text_category, 'Text category mismatch');
    assert(text_content.creator == creator_address, 'Text creator mismatch');

    // Verify image content metadata
    assert(image_content.content_id == image_content_id, 'Image ID mismatch');
    assert(image_content.title == image_title, 'Image title mismatch');
    assert(image_content.description == image_description, 'Image desc mismatch');
    assert(image_content.content_type == image_content_type, 'Image type mismatch');
    assert(image_content.category == image_category, 'Image category mismatch');
    assert(image_content.creator == creator_address, 'Image creator mismatch');

    // Verify video content metadata
    assert(video_content.content_id == video_content_id, 'Video ID mismatch');
    assert(video_content.title == video_title, 'Video title mismatch');
    assert(video_content.description == video_description, 'Video desc mismatch');
    assert(video_content.content_type == video_content_type, 'Video type mismatch');
    assert(video_content.category == video_category, 'Video category mismatch');
    assert(video_content.creator == creator_address, 'Video creator mismatch');

    // Verify content IDs are sequential
    assert(image_content_id == text_content_id + 1, 'Image ID not sequential');
    assert(video_content_id == image_content_id + 1, 'Video ID not sequential');
}
