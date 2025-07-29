// #[cfg(test)]
// pub mod permission_tests {
// Permission constants
const PERMISSION_TRANSFER: u64 = 0x1;
const PERMISSION_SIGN: u64 = 0x2;
const PERMISSION_CALL: u64 = 0x4;
const PERMISSION_ADMIN: u64 = 0x8;
use chain_lib::chainlib::ChainLib::ChainLib::{
    DelegationCreated, DelegationExpired, DelegationInfo, DelegationRevoked, DelegationUsed, Event,
};
use chain_lib::interfaces::IChainLib::{IChainLibDispatcher, IChainLibDispatcherTrait};
// use chain_lib::interfaces::IChainLib::{
//     IChainLib, IChainLibDispatcher, IChainLibDispatcherTrait
// };
use core::array::ArrayTrait;
use core::result::ResultTrait;
// use chain_lib::base::types::{Permissions, permission_flags, DelegationInfo, delegation_flags};
// use chain_lib::base::types::{DelegationInfo, delegation_flags};

use snforge_std::{
    ContractClassTrait, DeclareResultTrait, EventSpyAssertionsTrait, declare, spy_events,
    start_cheat_block_timestamp, start_cheat_caller_address, stop_cheat_block_timestamp,
    stop_cheat_caller_address,
};
use starknet::class_hash::ClassHash;
use starknet::contract_address::contract_address_const;
use starknet::{ContractAddress, get_block_timestamp, get_caller_address};
use crate::test_utils::{setup, setup_content_with_price, token_faucet_and_allowance};


#[test]
fn test_create_delegation() {
    let (contract_address, admin_address, erc20_address) = setup();
    let contract_instance = IChainLibDispatcher { contract_address };

    // Setup addresses
    let owner = contract_address_const::<'OWNER'>();
    let delegate = contract_address_const::<'DELEGATE'>();

    // Set owner as caller
    start_cheat_caller_address(contract_address, owner);

    // Set current time
    let current_time: u64 = 1000;
    start_cheat_block_timestamp(contract_address, current_time);
    let expiration: u64 = current_time + 3600; // 1 hour in the future
    let max_actions: u64 = 5;

    // Spy on events
    let mut spy = spy_events();

    // Create delegation
    contract_instance.create_delegation(delegate, PERMISSION_TRANSFER, expiration, max_actions);

    // Check delegation was created properly
    let delegation = contract_instance.get_delegation_info(owner, PERMISSION_TRANSFER);
    assert(delegation.delegate == delegate, 'Wrong delegate');
    assert(delegation.max_actions == max_actions, 'Wrong max actions');
    assert(delegation.action_count == 0, 'Action count should be 0');
    assert(delegation.active == true, 'Should be active');

    // Verify event was emitted
    let expected_event = Event::DelegationCreated(
        DelegationCreated {
            delegator: owner, delegate, permissions: PERMISSION_TRANSFER, expiration, max_actions,
        },
    );

    spy.assert_emitted(@array![(contract_address, expected_event)]);

    stop_cheat_caller_address(owner);
    stop_cheat_block_timestamp(contract_address);
}


#[test]
#[should_panic(expected: 'Contract is paused')]
fn test_create_delegation_should_panic_if_contract_paused() {
    let (contract_address, admin_address, erc20_address) = setup();
    let contract_instance = IChainLibDispatcher { contract_address };

    // Setup addresses
    let owner = contract_address_const::<'OWNER'>();
    let delegate = contract_address_const::<'DELEGATE'>();

    // Set owner as caller
    start_cheat_caller_address(contract_address, owner);

    // Set current time
    let current_time: u64 = 1000;
    start_cheat_block_timestamp(contract_address, current_time);
    let expiration: u64 = current_time + 3600; // 1 hour in the future
    let max_actions: u64 = 5;

    start_cheat_caller_address(contract_address, admin_address);
    contract_instance.emergency_pause();
    stop_cheat_caller_address(contract_address);

    // Create delegation
    contract_instance.create_delegation(delegate, PERMISSION_TRANSFER, expiration, max_actions);

    stop_cheat_caller_address(owner);
    stop_cheat_block_timestamp(contract_address);
}

#[test]
#[should_panic(expected: 'Invalid delegate address')]
fn test_create_delegation_zero_address() {
    let (contract_address, admin_address, erc20_address) = setup();
    let contract_instance = IChainLibDispatcher { contract_address };

    // Setup addresses
    let owner = contract_address_const::<'OWNER'>();
    let zero_address: ContractAddress = 0.try_into().unwrap();

    // Set owner as caller
    start_cheat_caller_address(contract_address, owner);

    // Set current time
    let current_time: u64 = 1000;
    start_cheat_block_timestamp(contract_address, current_time);
    let expiry: u64 = current_time + 3600;

    // Try to create delegation with zero address - should fail
    contract_instance.create_delegation(zero_address, PERMISSION_TRANSFER, expiry, 0);

    stop_cheat_caller_address(owner);
    stop_cheat_block_timestamp(contract_address);
}

#[test]
fn test_revoke_delegation() {
    let (contract_address, admin_address, erc20_address) = setup();
    let contract_instance = IChainLibDispatcher { contract_address };

    // Setup addresses
    let owner = contract_address_const::<'OWNER'>();
    let delegate = contract_address_const::<'DELEGATE'>();

    // Set owner as caller
    start_cheat_caller_address(contract_address, owner);

    // Set current time
    let current_time: u64 = 1000;
    start_cheat_block_timestamp(contract_address, current_time);
    let expiry: u64 = current_time + 3600;

    // Create delegation first
    contract_instance.create_delegation(delegate, PERMISSION_SIGN, expiry, 0);

    // Spy on events for revocation
    let mut spy = spy_events();

    // Revoke delegation
    contract_instance.revoke_delegation(delegate, PERMISSION_SIGN);

    // Check delegation was revoked
    let delegation = contract_instance.get_delegation_info(owner, PERMISSION_SIGN);
    assert(delegation.active == false, 'Should be inactive');

    // Verify event was emitted
    let expected_event = Event::DelegationRevoked(DelegationRevoked { delegator: owner, delegate });
    spy.assert_emitted(@array![(contract_address, expected_event)]);

    // Verify is_delegated returns false
    assert(
        !contract_instance.is_delegated(owner, delegate, PERMISSION_SIGN),
        'is_delegated should be false',
    );

    stop_cheat_caller_address(owner);
    stop_cheat_block_timestamp(contract_address);
}


#[test]
#[should_panic(expected: 'Contract is paused')]
fn test_revoke_delegation_should_panic_if_contract_paused() {
    let (contract_address, admin_address, erc20_address) = setup();
    let contract_instance = IChainLibDispatcher { contract_address };

    // Setup addresses
    let owner = contract_address_const::<'OWNER'>();
    let delegate = contract_address_const::<'DELEGATE'>();

    // Set owner as caller
    start_cheat_caller_address(contract_address, owner);

    // Set current time
    let current_time: u64 = 1000;
    start_cheat_block_timestamp(contract_address, current_time);
    let expiry: u64 = current_time + 3600;

    // Create delegation first
    contract_instance.create_delegation(delegate, PERMISSION_SIGN, expiry, 0);

    start_cheat_caller_address(contract_address, admin_address);
    contract_instance.emergency_pause();
    stop_cheat_caller_address(contract_address);

    // Revoke delegation
    contract_instance.revoke_delegation(delegate, PERMISSION_SIGN);

    stop_cheat_caller_address(owner);
    stop_cheat_block_timestamp(contract_address);
}


#[test]
#[should_panic(expected: 'Delegate mismatch')]
fn test_revoke_delegation_wrong_delegate() {
    let (contract_address, admin_address, erc20_address) = setup();
    let contract_instance = IChainLibDispatcher { contract_address };

    // Setup addresses
    let owner = contract_address_const::<'OWNER'>();
    let delegate = contract_address_const::<'DELEGATE'>();
    let wrong_delegate = contract_address_const::<'ANOTHER_USER'>();

    // Set owner as caller
    start_cheat_caller_address(contract_address, owner);

    // Set current time
    let current_time: u64 = 1000;
    start_cheat_block_timestamp(contract_address, current_time);
    let expiry: u64 = current_time + 3600;

    // Create delegation first
    contract_instance.create_delegation(delegate, PERMISSION_SIGN, expiry, 0);

    // Try to revoke for wrong delegate
    contract_instance.revoke_delegation(wrong_delegate, PERMISSION_SIGN);

    stop_cheat_caller_address(owner);
    stop_cheat_block_timestamp(contract_address);
}

#[test]
fn test_use_delegation() {
    let (contract_address, admin_address, erc20_address) = setup();
    let contract_instance = IChainLibDispatcher { contract_address };

    // Setup addresses
    let owner = contract_address_const::<'OWNER'>();
    let delegate = contract_address_const::<'DELEGATE'>();

    // Set current time
    let current_time: u64 = 1000;
    start_cheat_block_timestamp(contract_address, current_time);
    let expiry: u64 = current_time + 3600;

    // Set owner as caller to create delegation
    start_cheat_caller_address(contract_address, owner);

    // Create delegation with max actions
    let max_actions: u64 = 3;
    contract_instance.create_delegation(delegate, PERMISSION_CALL, expiry, max_actions);

    // Switch caller to delegate
    start_cheat_caller_address(contract_address, delegate);

    // Spy on events
    let mut spy = spy_events();

    // Use delegation
    contract_instance.use_delegation(owner, PERMISSION_CALL);

    // Verify action count increased
    let delegation = contract_instance.get_delegation_info(owner, PERMISSION_CALL);
    assert(delegation.action_count == 1, 'Action count should be 1');
    assert(delegation.active == true, 'Should still be active');

    // Verify event was emitted
    let expected_event = Event::DelegationUsed(
        DelegationUsed {
            delegator: owner, delegate, permission: PERMISSION_CALL, remaining_actions: 2,
        },
    );
    spy.assert_emitted(@array![(contract_address, expected_event)]);

    // Use delegation twice more to reach limit
    contract_instance.use_delegation(owner, PERMISSION_CALL);
    spy = spy_events();
    contract_instance.use_delegation(owner, PERMISSION_CALL);

    // Verify delegation is now inactive due to max actions
    let final_delegation = contract_instance.get_delegation_info(owner, PERMISSION_CALL);
    assert(final_delegation.action_count == 3, 'Action count should be 3');
    assert(final_delegation.active == false, 'Should be inactive');

    // Check for both DelegationUsed and DelegationExpired events
    let expected_event = Event::DelegationUsed(
        DelegationUsed {
            delegator: owner, delegate, permission: PERMISSION_CALL, remaining_actions: 0,
        },
    );
    spy.assert_emitted(@array![(contract_address, expected_event)]);

    let expected_event = Event::DelegationExpired(DelegationExpired { delegator: owner, delegate });
    spy.assert_emitted(@array![(contract_address, expected_event)]);

    stop_cheat_caller_address(delegate);
    stop_cheat_block_timestamp(contract_address);
}


#[test]
#[should_panic(expected: 'Contract is paused')]
fn test_use_delegation_should_panic_if_contract_paused() {
    let (contract_address, admin_address, erc20_address) = setup();
    let contract_instance = IChainLibDispatcher { contract_address };

    // Setup addresses
    let owner = contract_address_const::<'OWNER'>();
    let delegate = contract_address_const::<'DELEGATE'>();

    // Set current time
    let current_time: u64 = 1000;
    start_cheat_block_timestamp(contract_address, current_time);
    let expiry: u64 = current_time + 3600;

    // Set owner as caller to create delegation
    start_cheat_caller_address(contract_address, owner);

    // Create delegation with max actions
    let max_actions: u64 = 3;
    contract_instance.create_delegation(delegate, PERMISSION_CALL, expiry, max_actions);

    // Switch caller to delegate
    start_cheat_caller_address(contract_address, delegate);

    start_cheat_caller_address(contract_address, admin_address);
    contract_instance.emergency_pause();
    stop_cheat_caller_address(contract_address);

    // Use delegation
    contract_instance.use_delegation(owner, PERMISSION_CALL);

    stop_cheat_caller_address(delegate);
    stop_cheat_block_timestamp(contract_address);
}


#[test]
#[should_panic(expected: 'Permission denied')]
fn test_use_delegation_exceed_max_actions() {
    let (contract_address, admin_address, erc20_address) = setup();
    let contract_instance = IChainLibDispatcher { contract_address };

    // Setup addresses
    let owner = contract_address_const::<'OWNER'>();
    let delegate = contract_address_const::<'DELEGATE'>();

    // Set current time
    let current_time: u64 = 1000;
    start_cheat_block_timestamp(contract_address, current_time);
    let expiry: u64 = current_time + 3600;

    // Set owner as caller to create delegation
    start_cheat_caller_address(contract_address, owner);

    // Create delegation with max actions = 1
    contract_instance.create_delegation(delegate, PERMISSION_TRANSFER, expiry, 1);

    // Switch caller to delegate
    start_cheat_caller_address(contract_address, delegate);

    // Use delegation once (should succeed)
    contract_instance.use_delegation(owner, PERMISSION_TRANSFER);

    // Try to use it again (should fail)
    contract_instance.use_delegation(owner, PERMISSION_TRANSFER);

    stop_cheat_caller_address(delegate);
    stop_cheat_block_timestamp(contract_address);
}

#[test]
fn test_is_delegated_expired() {
    let (contract_address, admin_address, erc20_address) = setup();
    let contract_instance = IChainLibDispatcher { contract_address };

    // Setup addresses
    let owner = contract_address_const::<'OWNER'>();
    let delegate = contract_address_const::<'DELEGATE'>();

    // Set current time
    let current_time: u64 = 1000;
    start_cheat_block_timestamp(contract_address, current_time);
    let expiry: u64 = current_time + 3600; // 1 hour in future

    // Set owner as caller
    start_cheat_caller_address(contract_address, owner);

    // Create delegation with expiry
    contract_instance.create_delegation(delegate, PERMISSION_ADMIN, expiry, 0);

    // Check delegation is valid before expiry
    assert(
        contract_instance.is_delegated(owner, delegate, PERMISSION_ADMIN),
        'Should be valid before expiry',
    );

    // Advance time to after expiry
    stop_cheat_block_timestamp(contract_address);
    start_cheat_block_timestamp(contract_address, expiry + 1);

    // Check delegation is no longer valid
    assert(!contract_instance.is_delegated(owner, delegate, PERMISSION_ADMIN), 'Should be expired');

    stop_cheat_caller_address(owner);
    stop_cheat_block_timestamp(contract_address);
}

#[test]
fn test_is_delegated_multiple_permissions() {
    let (contract_address, admin_address, erc20_address) = setup();
    let contract_instance = IChainLibDispatcher { contract_address };

    // Setup addresses
    let owner = contract_address_const::<'OWNER'>();
    let delegate = contract_address_const::<'DELEGATE'>();

    // Set current time
    let current_time: u64 = 1000;
    start_cheat_block_timestamp(contract_address, current_time);
    let expiry: u64 = current_time + 3600;

    // Set owner as caller
    start_cheat_caller_address(contract_address, owner);

    // Create delegations for multiple permissions
    contract_instance.create_delegation(delegate, PERMISSION_TRANSFER, expiry, 0);
    contract_instance.create_delegation(delegate, PERMISSION_SIGN, expiry, 0);

    // Check each permission
    assert(
        contract_instance.is_delegated(owner, delegate, PERMISSION_TRANSFER),
        'Should have TRANSFER permission',
    );
    assert(
        contract_instance.is_delegated(owner, delegate, PERMISSION_SIGN),
        'Should have SIGN permission',
    );
    assert(
        !contract_instance.is_delegated(owner, delegate, PERMISSION_CALL),
        'Should not have CALL permission',
    );

    stop_cheat_caller_address(owner);
    stop_cheat_block_timestamp(contract_address);
}

#[test]
#[should_panic(expected: 'Permission denied')]
fn test_use_delegation_wrong_delegate() {
    let (contract_address, admin_address, erc20_address) = setup();
    let contract_instance = IChainLibDispatcher { contract_address };

    // Setup addresses
    let owner = contract_address_const::<'OWNER'>();
    let delegate = contract_address_const::<'DELEGATE'>();
    let wrong_delegate = contract_address_const::<'ANOTHER_USER'>();

    // Set current time
    let current_time: u64 = 1000;
    start_cheat_block_timestamp(contract_address, current_time);
    let expiry: u64 = current_time + 3600;

    // Set owner as caller to create delegation
    start_cheat_caller_address(contract_address, owner);

    // Create delegation
    contract_instance.create_delegation(delegate, PERMISSION_ADMIN, expiry, 0);

    // Set wrong delegate as caller
    start_cheat_caller_address(contract_address, wrong_delegate);

    // Try to use delegation as wrong delegate (should fail)
    contract_instance.use_delegation(owner, PERMISSION_ADMIN);

    stop_cheat_caller_address(wrong_delegate);
    stop_cheat_block_timestamp(contract_address);
}


#[test]
fn test_delegation_unlimited() {
    let (contract_address, admin_address, erc20_address) = setup();
    let contract_instance = IChainLibDispatcher { contract_address };

    // Setup addresses
    let owner = contract_address_const::<'OWNER'>();
    let delegate = contract_address_const::<'DELEGATE'>();

    // Set current time
    let current_time: u64 = 1000;
    start_cheat_block_timestamp(contract_address, current_time);

    // Set owner as caller
    start_cheat_caller_address(contract_address, owner);

    // Create delegation with no expiry and unlimited actions
    contract_instance.create_delegation(delegate, PERMISSION_CALL, 0, 0);

    // Set delegate as caller
    start_cheat_caller_address(contract_address, delegate);

    // Use delegation multiple times (should all succeed)
    contract_instance.use_delegation(owner, PERMISSION_CALL);
    contract_instance.use_delegation(owner, PERMISSION_CALL);
    contract_instance.use_delegation(owner, PERMISSION_CALL);

    // Check delegation info
    let delegation = contract_instance.get_delegation_info(owner, PERMISSION_CALL);
    assert(delegation.action_count == 3, 'Action count should be 3');
    assert(delegation.active == true, 'Should still be active');

    // Advance time far in the future
    stop_cheat_block_timestamp(contract_address);
    start_cheat_block_timestamp(contract_address, current_time + 1000000);

    // Should still work since no expiry
    contract_instance.use_delegation(owner, PERMISSION_CALL);

    stop_cheat_caller_address(delegate);
    stop_cheat_block_timestamp(contract_address);
}

#[test]
fn test_get_delegation_info() {
    let (contract_address, admin_address, erc20_address) = setup();
    let contract_instance = IChainLibDispatcher { contract_address };

    // Setup addresses
    let owner = contract_address_const::<'OWNER'>();
    let delegate = contract_address_const::<'DELEGATE'>();

    // Set current time
    let current_time: u64 = 1000;
    start_cheat_block_timestamp(contract_address, current_time);
    let expiry: u64 = current_time + 3600;
    let max_actions: u64 = 10;

    // Set owner as caller
    start_cheat_caller_address(contract_address, owner);

    // Create delegation
    contract_instance.create_delegation(delegate, PERMISSION_TRANSFER, expiry, max_actions);

    // Get and verify delegation info
    let info = contract_instance.get_delegation_info(owner, PERMISSION_TRANSFER);
    assert(info.delegate == delegate, 'Wrong delegate');
    assert(info.expiration == expiry, 'Wrong expiry');
    assert(info.max_actions == max_actions, 'Wrong max actions');
    assert(info.action_count == 0, 'Wrong action count');
    assert(info.active == true, 'Wrong active status');

    stop_cheat_caller_address(owner);
    stop_cheat_block_timestamp(contract_address);
}

