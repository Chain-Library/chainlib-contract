#[starknet::contract]
pub mod AccountDelegation {
    use chain_lib::base::errors::Error;
    use chain_lib::events::AccountDelegationEvent::*;
    use chain_lib::interfaces::IAccountDelegation::IAccountDelegation;
    use core::num::traits::zero::Zero;
    use core::traits::{Into, TryInto};
    use starknet::contract_address::ContractAddress;
    use starknet::event::EventEmitter;
    use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess};
    use starknet::{get_block_timestamp, get_caller_address};


    // Structure to represent delegation permissions
    #[derive(Copy, Drop, Serde, starknet::Store)]
    pub struct DelegationInfo {
        pub delegate: ContractAddress, // Delegate account address
        pub expiry: u64, // Unix timestamp when delegation expires (0 for no expiration)
        pub max_actions: u64, // Maximum number of actions allowed (0 for unlimited)
        pub action_count: u64, // Current count of actions performed
        pub active: bool // Whether this delegation is active
    }

    // Permission constants
    const PERMISSION_TRANSFER: u8 = 1;
    const PERMISSION_SIGN: u8 = 2;
    const PERMISSION_CALL: u8 = 3;
    const PERMISSION_ADMIN: u8 = 4;

    #[storage]
    pub struct Storage {
        owner_namespaces: Map<
            ContractAddress, felt252,
        >, // Maps from owner address to a namespace identifier
        delegations: Map<
            (felt252, u8), DelegationInfo,
        >, // Maps from (namespace, permission_id) to delegation info
        owners: Map<ContractAddress, bool>, // Mapping to store if an address is the owner
        next_namespace: felt252 // Counter for generating unique namespaces
    }

    // Events for delegation activities
    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        DelegationCreated: DelegationCreated,
        DelegationRevoked: DelegationRevoked,
        DelegationUsed: DelegationUsed,
        DelegationExpire: DelegationExpire,
    }


    #[constructor]
    fn constructor(ref self: ContractState, initial_owner: ContractAddress) {
        self.owners.write(initial_owner, true);
        // Initialize namespace counter
        self.next_namespace.write(1);
    }

    #[external(v0)]
    impl AccountDelegationImpl of IAccountDelegation<ContractState> {
        // Function to add a new owner
        fn add_owner(ref self: ContractState, new_owner: ContractAddress) {
            let caller = get_caller_address();
            self.assert_is_owner(caller);
            self.owners.write(new_owner, true);
        }

        // Function to delegate permission to another account
        fn delegate_permission(
            ref self: ContractState,
            delegate: ContractAddress,
            permission_id: u8,
            expiry: u64,
            max_actions: u64,
        ) {
            // Validate inputs
            assert(!delegate.is_zero(), Error::INVALID_DELEGATION);
            assert(self.is_valid_permission(permission_id), Error::INVALID_PERMISSION);

            // Check that caller is the owner
            let owner = get_caller_address();
            self.assert_is_owner(owner);

            // Check that expiry is in the future if provided
            let current_time = get_block_timestamp();
            if expiry != 0 {
                assert(expiry > current_time, Error::INVALID_EXPIRY);
            }

            // Create delegation info
            let delegation = DelegationInfo {
                delegate, expiry, max_actions, action_count: 0, active: true,
            };

            // Store delegation using the nested maps approach
            let namespace = self.get_or_create_namespace(owner);
            self.delegations.write((namespace, permission_id), delegation);

            // Emit event
            self
                .emit(
                    Event::DelegationCreated(
                        DelegationCreated { owner, delegate, permission_id, expiry, max_actions },
                    ),
                );
        }

        // Function to revoke delegation
        fn revoke_delegation(
            ref self: ContractState, permission_id: u8, delegate: ContractAddress,
        ) {
            // Validate permission
            assert(self.is_valid_permission(permission_id), Error::INVALID_PERMISSION);

            let owner = get_caller_address();
            self.assert_is_owner(owner);

            // Get current delegation info
            let namespace = self.owner_namespaces.read(owner);
            let mut delegation_info = self.delegations.read((namespace, permission_id));

            // Ensure delegate matches
            assert(delegation_info.delegate == delegate, Error::NOT_AUTHORIZED);

            // Deactivate delegation
            delegation_info.active = false;
            self.delegations.write((namespace, permission_id), delegation_info);

            // Emit event
            self
                .emit(
                    Event::DelegationRevoked(DelegationRevoked { owner, delegate, permission_id }),
                );
        }

        // Function to check if a caller has delegated permission
        fn has_delegation(
            self: @ContractState,
            owner: ContractAddress,
            caller: ContractAddress,
            permission_id: u8,
        ) -> bool {
            // Validate permission
            if !self.is_valid_permission(permission_id) {
                return false;
            }

            let namespace = self.owner_namespaces.read(owner);
            if namespace == 0 {
                return false; // No delegations exist for this owner
            }

            let delegation = self.delegations.read((namespace, permission_id));

            if delegation.delegate != caller || !delegation.active {
                return false;
            }

            // Check expiry
            if delegation.expiry != 0 && delegation.expiry <= get_block_timestamp() {
                return false;
            }

            // Check action limit
            if delegation.max_actions != 0 && delegation.action_count >= delegation.max_actions {
                return false;
            }

            true
        }

        // Function to use a delegation (increment action count)
        fn use_delegation(ref self: ContractState, owner: ContractAddress, permission_id: u8) {
            // Validate permission
            assert(self.is_valid_permission(permission_id), Error::INVALID_PERMISSION);

            let caller = get_caller_address();
            let namespace = self.owner_namespaces.read(owner);
            assert(namespace != 0, Error::NOT_AUTHORIZED);

            // Get delegation info
            let mut delegation = self.delegations.read((namespace, permission_id));

            // Verify delegation
            assert(delegation.delegate == caller, Error::NOT_AUTHORIZED);
            assert(delegation.active, Error::DELEGATION_NOT_ACTIVE);

            // Check expiry
            let current_time = get_block_timestamp();
            if delegation.expiry != 0 && delegation.expiry <= current_time {
                // Mark as inactive since it's expired
                delegation.active = false;
                self.delegations.write((namespace, permission_id), delegation);

                // Emit expiry event
                self
                    .emit(
                        Event::DelegationExpire(
                            DelegationExpire { owner, delegate: caller, permission_id },
                        ),
                    );

                // panic!("Delegation Expired");
                assert(delegation.expiry > current_time, Error::DELEGATION_EXPIRED);
            }

            // Check action limit
            if delegation.max_actions != 0 {
                assert(
                    delegation.action_count < delegation.max_actions, Error::ACTION_LIMIT_REACHED,
                );

                // Increment action count
                delegation.action_count += 1;

                // Update if this was the last allowed action
                if delegation.action_count == delegation.max_actions {
                    delegation.active = false;
                }

                // Update storage
                self.delegations.write((namespace, permission_id), delegation);
            }

            // Emit usage event
            self
                .emit(
                    Event::DelegationUsed(
                        DelegationUsed {
                            owner,
                            delegate: caller,
                            permission_id,
                            action_count: delegation.action_count,
                        },
                    ),
                );
        }

        // Function to get delegation details
        fn get_delegation_info(
            self: @ContractState, owner: ContractAddress, permission_id: u8,
        ) -> DelegationInfo {
            assert(self.is_valid_permission(permission_id), Error::INVALID_PERMISSION);

            let namespace = self.owner_namespaces.read(owner);
            if namespace == 0 {
                // Return empty delegation if namespace doesn't exist
                // let zero_address: ContractAddress = 0.try_into();
                return DelegationInfo {
                    delegate: 0.try_into().unwrap(),
                    expiry: 0,
                    max_actions: 0,
                    action_count: 0,
                    active: false,
                };
            }

            self.delegations.read((namespace, permission_id))
        }

        // Function to check if an address is an owner
        fn is_owner(self: @ContractState, address: ContractAddress) -> bool {
            self.owners.read(address)
        }

        // Function to check if a permission ID is valid
        fn is_valid_permission(self: @ContractState, permission_id: u8) -> bool {
            permission_id == PERMISSION_TRANSFER
                || permission_id == PERMISSION_SIGN
                || permission_id == PERMISSION_CALL
                || permission_id == PERMISSION_ADMIN
        }
    }

    // Internal helper functions
    #[generate_trait]
    impl HelperImpl of HelperTrait {
        fn assert_is_owner(self: @ContractState, address: ContractAddress) {
            assert(self.owners.read(address), Error::NOT_AUTHORIZED);
        }

        fn get_or_create_namespace(ref self: ContractState, owner: ContractAddress) -> felt252 {
            let namespace = self.owner_namespaces.read(owner);
            if namespace == 0 {
                // Create new namespace if it doesn't exist
                let new_namespace = self.next_namespace.read();
                self.next_namespace.write(new_namespace + 1);
                self.owner_namespaces.write(owner, new_namespace);
                return new_namespace;
            }
            namespace
        }
    }
}
