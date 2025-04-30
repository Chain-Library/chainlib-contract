// Permission constants
const PERMISSION_TRANSFER: u8 = 1;
const PERMISSION_SIGN: u8 = 2;
const PERMISSION_CALL: u8 = 3;
const PERMISSION_ADMIN: u8 = 4;
// use chain_lib::chainlib::AccountDelegation::AccountDelegation::*;
use chain_lib::events::AccountDelegationEvent::{
    DelegationCreated, DelegationExpire, DelegationRevoked, DelegationUsed
};

use chain_lib::interfaces::IAccountDelegation::{
    IAccountDelegationDispatcher, IAccountDelegationDispatcherTrait,
};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, EventSpyAssertionsTrait, declare, spy_events,
    start_cheat_caller_address, stop_cheat_caller_address,
};
use starknet::{ContractAddress, contract_address_const, get_block_timestamp};


fn setup() -> ContractAddress {
    let contract_class = declare("AccountDelegation").unwrap().contract_class();

    // prepare constructor argument
    // let next_namespace: felt252 = 1;
    let account: ContractAddress = contract_address_const::<'OWNER'>();

    let calldata = array![account.into()];

    let (contract_address, _) = contract_class.deploy(@calldata).unwrap();
    contract_address
}


#[test]
fn test_constructor() {
    let contract_address = setup();
    let contract_instance = IAccountDelegationDispatcher { contract_address };

    let owner = contract_address_const::<'OWNER'>();
    let non_owner = contract_address_const::<'another'>();

    start_cheat_caller_address(contract_address, owner);

    // Check if the initial owner is correctly set
    let rightful_owner = contract_instance.is_owner(owner);
    assert(rightful_owner == true, 'Owner should be set');

    // Verify non-owner
    assert(!contract_instance.is_owner(non_owner), 'Non-owner should not be set');
    stop_cheat_caller_address(owner);
}


#[test]
fn test_add_owner() {
    let contract_address = setup();
    let contract_instance = IAccountDelegationDispatcher { contract_address };

    let owner = contract_address_const::<'OWNER'>();
    let new_owner = contract_address_const::<'ANOTHER_USER'>();

    // Set caller as owner
    start_cheat_caller_address(contract_address, owner);

    // Add new owner
    contract_instance.add_owner(new_owner);

    // Verify new owner was added
    assert(contract_instance.is_owner(new_owner), 'New owner should be set');
    stop_cheat_caller_address(owner);
}

#[test]
#[should_panic(expected: 'NotAuthorized')]
fn test_add_owner_unauthorized() {
    let contract_address = setup();
    let contract_instance = IAccountDelegationDispatcher { contract_address };

    let non_owner = contract_address_const::<'ANOTHER_USER'>();
    let new_address = contract_address_const::<'DELEGATE'>();

    // Set caller as non-owner
    start_cheat_caller_address(contract_address, non_owner);

    // Attempt to add new owner, should fail
    contract_instance.add_owner(new_address);

    stop_cheat_caller_address(non_owner);
}


#[test]
fn test_delegate_permission() {
    let contract_address = setup();
    let contract_instance = IAccountDelegationDispatcher { contract_address };

    let owner = contract_address_const::<'OWNER'>();
    let delegate = contract_address_const::<'DELEGATE'>();

    // Set caller as owner
    start_cheat_caller_address(contract_address, owner);

    // Set current time
    let current_time: u64 = 1000;
    // set_block_timestamp(current_time);
    // let future_time = current_time + 3600;

    // Delegate permission with expiry and max actions
    let expiry: u64 = current_time + 3600; // 1 hour in the future
    let max_actions: u64 = 5;
    contract_instance.delegate_permission(delegate, PERMISSION_TRANSFER, expiry, max_actions);

    // Check delegation info
    let delegation = contract_instance.get_delegation_info(owner, PERMISSION_TRANSFER);
    assert(delegation.delegate == delegate, 'Delegate address mismatch');
    assert(delegation.expiry == expiry, 'Expiry time mismatch');
    assert(delegation.max_actions == max_actions, 'Max actions mismatch');
    assert(delegation.action_count == 0, 'Action count should be 0');
    assert(delegation.active == true, 'Delegation should be active');

    // Verify has_delegation returns true
    assert(
        contract_instance.has_delegation(owner, delegate, PERMISSION_TRANSFER) == true,
        'has_delegation is true',
    );
}

#[test]
fn test_delegate_permission_unlimited() {
    let contract_address = setup();
    let contract_instance = IAccountDelegationDispatcher { contract_address };

    let owner = contract_address_const::<'OWNER'>();
    let delegate = contract_address_const::<'DELEGATE'>();

    // Set caller as owner
    start_cheat_caller_address(contract_address, owner);

    // Delegate permission with no expiry and unlimited actions
    contract_instance.delegate_permission(delegate, PERMISSION_SIGN, 0, 0);

    // Check delegation info
    let delegation = contract_instance.get_delegation_info(owner, PERMISSION_SIGN);
    assert(delegation.expiry == 0, 'Expiry should be 0');
    assert(delegation.max_actions == 0, 'Max actions should be 0');
    assert(delegation.active == true, 'Delegation should be active');
}

#[test]
#[should_panic(expected: 'InvalidDelegation')]
fn test_delegate_permission_zero_address() {
    let contract_address = setup();
    let contract_instance = IAccountDelegationDispatcher { contract_address };

    let owner = contract_address_const::<'OWNER'>();

    let current_time = 1000;
    let FUTURE_TIME = current_time + 3600;

    let delegate: ContractAddress = 0.try_into().unwrap();
    // Set caller as owner
    start_cheat_caller_address(contract_address, owner);

    // Try to delegate to zero address
    contract_instance.delegate_permission(delegate, PERMISSION_TRANSFER, FUTURE_TIME, 0);
}


#[test]
#[should_panic(expected: 'InvalidPermission')]
fn test_delegate_invalid_permission() {
    let contract_address = setup();
    let contract_instance = IAccountDelegationDispatcher { contract_address };

    let owner = contract_address_const::<'OWNER'>();
    let delegate = contract_address_const::<'DELEGATE'>();

    let current_time = 1000;
    let FUTURE_TIME = current_time + 3600;

    // Set caller as owner
    start_cheat_caller_address(contract_address, owner);

    // Try to use an invalid permission ID
    let invalid_permission: u8 = 99;
    contract_instance.delegate_permission(delegate, invalid_permission, FUTURE_TIME, 0);
}


#[test]
fn test_revoke_delegation() {
    let contract_address = setup();
    let contract_instance = IAccountDelegationDispatcher { contract_address };

    let owner = contract_address_const::<'OWNER'>();
    let delegate = contract_address_const::<'DELEGATE'>();

    let current_time = 1000;
    let FUTURE_TIME = current_time + 3600;

    // Set caller as owner
    start_cheat_caller_address(contract_address, owner);

    // First delegate permission
    contract_instance.delegate_permission(delegate, PERMISSION_TRANSFER, FUTURE_TIME, 0);

    // Then revoke it
    contract_instance.revoke_delegation(PERMISSION_TRANSFER, delegate);

    // Check delegation info is updated
    let delegation = contract_instance.get_delegation_info(owner, PERMISSION_TRANSFER);
    assert(delegation.active == false, 'Delegation should be inactive');

    // Verify has_delegation returns false
    assert(
        !contract_instance.has_delegation(owner, delegate, PERMISSION_TRANSFER),
        'has_delegation is false',
    );
}

#[test]
#[should_panic(expected: 'NotAuthorized')]
fn test_revoke_delegation_wrong_delegate() {
    let contract_address = setup();
    let contract_instance = IAccountDelegationDispatcher { contract_address };

    let owner = contract_address_const::<'OWNER'>();
    let delegate = contract_address_const::<'DELEGATE'>();
    let wrong_delegate = contract_address_const::<'ANOTHER_USER'>();

    let current_time = 1000;
    let FUTURE_TIME = current_time + 3600;

    // Set caller as owner
    start_cheat_caller_address(contract_address, owner);

    // First delegate permission
    contract_instance.delegate_permission(delegate, PERMISSION_TRANSFER, FUTURE_TIME, 0);

    // Try to revoke for wrong delegate
    contract_instance.revoke_delegation(PERMISSION_TRANSFER, wrong_delegate);
}

#[test]
fn test_use_delegation() {
    let contract_address = setup();
    let contract_instance = IAccountDelegationDispatcher { contract_address };

    let owner = contract_address_const::<'OWNER'>();
    let delegate = contract_address_const::<'DELEGATE'>();

    // Set owner as caller to create delegation
    start_cheat_caller_address(contract_address, owner);

    // Set current time
    let current_time = 1000;
    let FUTURE_TIME = current_time + 3600;

    // Create delegation with max actions
    let max_actions: u64 = 3;
    contract_instance.delegate_permission(delegate, PERMISSION_CALL, FUTURE_TIME, max_actions);

    // Switch caller to delegate
    start_cheat_caller_address(contract_address, delegate);

    // Use delegation
    contract_instance.use_delegation(owner, PERMISSION_CALL);

    // Verify action count increased
    let delegation = contract_instance.get_delegation_info(owner, PERMISSION_CALL);
    assert(delegation.action_count == 1, 'Action count should increase');
    assert(delegation.active == true, 'Delegation should still active');

    // Use delegation two more times
    contract_instance.use_delegation(owner, PERMISSION_CALL);
    contract_instance.use_delegation(owner, PERMISSION_CALL);

    // Verify delegation is now inactive due to reaching max actions
    let final_delegation = contract_instance.get_delegation_info(owner, PERMISSION_CALL);
    assert(final_delegation.action_count == 3, 'Action count should be max');
    assert(final_delegation.active == false, 'Delegation should be inactive');
}

#[test]
#[should_panic(expected: 'DelegationNotActive')]
fn test_use_delegation_exceed_max_actions() {
    let contract_address = setup();
    let contract_instance = IAccountDelegationDispatcher { contract_address };

    let owner = contract_address_const::<'OWNER'>();
    let delegate = contract_address_const::<'DELEGATE'>();

    let current_time = 1000;
    let FUTURE_TIME = current_time + 3600;

    // Set owner as caller to create delegation
    start_cheat_caller_address(contract_address, owner);

    // Create delegation with max actions
    contract_instance.delegate_permission(delegate, PERMISSION_TRANSFER, FUTURE_TIME, 1);

    // Switch caller to delegate
    start_cheat_caller_address(contract_address, delegate);

    // Use delegation once (should succeed)
    contract_instance.use_delegation(owner, PERMISSION_TRANSFER);

    // Try to use it again (should fail)
    contract_instance.use_delegation(owner, PERMISSION_TRANSFER);
}


#[test]
#[should_panic(expected: 'NotAuthorized')]
fn test_use_delegation_wrong_delegate() {
    let contract_address = setup();
    let contract_instance = IAccountDelegationDispatcher { contract_address };

    let owner = contract_address_const::<'OWNER'>();
    let delegate = contract_address_const::<'DELEGATE'>();
    let wrong_delegate = contract_address_const::<'ANOTHER_USER'>();

    let current_time = 1000;
    let FUTURE_TIME = current_time + 3600;

    // Set owner as caller to create delegation
    start_cheat_caller_address(contract_address, owner);

    // Create delegation
    contract_instance.delegate_permission(delegate, PERMISSION_ADMIN, FUTURE_TIME, 0);

    // Set wrong delegate as caller
    start_cheat_caller_address(contract_address, wrong_delegate);

    // Try to use delegation as wrong delegate
    contract_instance.use_delegation(owner, PERMISSION_ADMIN);
}


#[test]
#[should_panic(expected: 'DelegationNotActive')]
fn test_use_delegation_inactive() {
    let contract_address = setup();
    let contract_instance = IAccountDelegationDispatcher { contract_address };

    let owner = contract_address_const::<'OWNER'>();
    let delegate = contract_address_const::<'DELEGATE'>();

    let current_time = 1000;
    let FUTURE_TIME = current_time + 3600;

    // Set owner as caller to create delegation
    start_cheat_caller_address(contract_address, owner);

    // Create delegation
    contract_instance.delegate_permission(delegate, PERMISSION_SIGN, FUTURE_TIME, 0);

    // Revoke delegation
    contract_instance.revoke_delegation(PERMISSION_SIGN, delegate);

    // Set delegate as caller
    start_cheat_caller_address(contract_address, delegate);

    // Try to use inactive delegation
    contract_instance.use_delegation(owner, PERMISSION_SIGN);
}


#[test]
fn test_has_delegation_multiple_permissions() {
    let contract_address = setup();
    let contract_instance = IAccountDelegationDispatcher { contract_address };

    let owner = contract_address_const::<'OWNER'>();
    let delegate = contract_address_const::<'DELEGATE'>();

    let current_time = 1000;
    let FUTURE_TIME = current_time + 3600;

    // Set owner as caller
    start_cheat_caller_address(contract_address, owner);

    // Create delegations for different permissions
    contract_instance.delegate_permission(delegate, PERMISSION_TRANSFER, FUTURE_TIME, 0);
    contract_instance.delegate_permission(delegate, PERMISSION_SIGN, FUTURE_TIME, 0);

    // Check has_delegation for both permissions
    assert(
        contract_instance.has_delegation(owner, delegate, PERMISSION_TRANSFER),
        'Should have Transfer permission',
    );
    assert(
        contract_instance.has_delegation(owner, delegate, PERMISSION_SIGN),
        'Should have Sign permission',
    );

    // Should not have Call permission
    assert(
        !contract_instance.has_delegation(owner, delegate, PERMISSION_CALL),
        'Should not have Call permission',
    );
}


#[test]
fn test_multiple_owners() {
    let contract_address = setup();
    let contract_instance = IAccountDelegationDispatcher { contract_address };

    let owner1 = contract_address_const::<'OWNER'>();
    let owner2 = contract_address_const::<'ANOTHER_USER'>();
    let delegate = contract_address_const::<'DELEGATE'>();

    let current_time = 1000;
    let FUTURE_TIME = current_time + 3600;

    // Set first owner as caller
    start_cheat_caller_address(contract_address, owner1);

    // Add second owner
    contract_instance.add_owner(owner2);

    // Second owner should be able to delegate permissions
    start_cheat_caller_address(contract_address, owner2);
    contract_instance.delegate_permission(delegate, PERMISSION_ADMIN, FUTURE_TIME, 0);

    // Check delegation info
    let delegation = contract_instance.get_delegation_info(owner2, PERMISSION_ADMIN);
    assert(delegation.delegate == delegate, 'Delegate address mismatch');
    assert(delegation.active == true, 'Delegation should be active');
}
