#[starknet::contract]
pub mod ChainLib {
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_block_timestamp, get_caller_address};
    use crate::interfaces::IChainLib::IChainLib;
    use crate::base::types::{TokenBoundAccount};


    #[storage]
    struct Storage {
        // Contract addresses for component management
        deployed: bool,
        current_account_id: u256,
        accounts: Map<u256, TokenBoundAccount>,
        accountsaddr: Map<ContractAddress, TokenBoundAccount>,
        next_course_id: u256,
        nuum: Map<u8, u8>,
    }


    #[constructor]
    fn constructor(ref self: ContractState) {
        // Store the values in contract state
        self.deployed.write(true);
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        TokenBountAccountcreated: TokenBountAccountcreated,
    }

    #[derive(Drop, starknet::Event)]
    pub struct TokenBountAccountcreated {
        pub id: u256,
    }

    #[abi(embed_v0)]
    impl ChainLibNetImpl of IChainLib<ContractState> {
        fn create_token_account(
            ref self: ContractState,
            user_name: felt252,
            init_param1: felt252,
            init_param2: felt252,
        ) -> u256 {
            // Validate input parameters.
            assert!(user_name != 0, "User name cannot be empty");
            assert!(init_param1 != 0, "Initialization parameter 1 cannot be empty");
          

            // Retrieve the current account ID before incrementing.
            let account_id = self.current_account_id.read();

            // Create a new token bound account struct.
            let new_token_bound_account = TokenBoundAccount {
                id: account_id,
                address: get_caller_address(),
                user_name: user_name,
                init_param1: init_param1,
                init_param2: init_param2,
                created_at: get_block_timestamp(),
                updated_at: get_block_timestamp(),
            };

            // Store the new account in the accounts map.
            self.accounts.write(account_id, new_token_bound_account);

            // Increment the account ID counter after using the current value.
            self.current_account_id.write(account_id + 1);

            // Emit an event to signal the creation of the token bound account.
            self.emit(TokenBountAccountcreated { id: account_id });

            account_id
        }

        fn get_token_bound_account(ref self: ContractState, id: u256) -> TokenBoundAccount{
            let token_bound_account = self.accounts.read(id);
            token_bound_account
        }
        fn get_token_bound_account_by_owner(ref self: ContractState, address: ContractAddress) -> TokenBoundAccount{
            let token_bound_account = self.accountsaddr.read(address);
            token_bound_account
        }
        fn test_deployment(ref self: ContractState) -> bool {
            self.deployed.read()
           
        }
    }
}
