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

