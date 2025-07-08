use chain_lib::interfaces::IChainLib::{IChainLibDispatcher, IChainLibDispatcherTrait};
use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
use snforge_std::{
    CheatSpan, ContractClassTrait, DeclareResultTrait, cheat_caller_address, declare,
    start_cheat_caller_address, stop_cheat_caller_address,
};
use starknet::{ContractAddress, contract_address_const};

pub fn setup() -> (ContractAddress, ContractAddress, ContractAddress) {
    let admin_address: ContractAddress = contract_address_const::<'admin'>();

    // Deploy mock ERC20
    let erc20_class = declare("mock_erc20").unwrap().contract_class();
    let mut calldata = array![admin_address.into(), admin_address.into(), 6];
    let (erc20_address, _) = erc20_class.deploy(@calldata).unwrap();

    // Deploy the ChainLib contract
    let declare_result = declare("ChainLib");
    assert(declare_result.is_ok(), 'Contract declaration failed');

    let contract_class = declare_result.unwrap().contract_class();
    let mut calldata = array![admin_address.into(), erc20_address.into()];

    let deploy_result = contract_class.deploy(@calldata);
    assert(deploy_result.is_ok(), 'Contract deployment failed');

    let (contract_address, _) = deploy_result.unwrap();

    (contract_address, admin_address, erc20_address)
}


// Token faucet and allowance setup
pub fn token_faucet_and_allowance(
    dispatcher: IChainLibDispatcher,
    user_address: ContractAddress,
    erc20_address: ContractAddress,
    token_amount: u256,
) {
    let admin_address = contract_address_const::<'admin'>();

    let token_dispatcher = IERC20Dispatcher { contract_address: erc20_address };
    // Transfer tokens from admin to user
    start_cheat_caller_address(erc20_address, admin_address);
    token_dispatcher.transfer(user_address, token_amount);
    stop_cheat_caller_address(erc20_address);

    let user_token_balance = token_dispatcher.balance_of(user_address);
    assert(user_token_balance >= token_amount, 'User tokens not gotten');

    // Set user as caller to approve the contract
    start_cheat_caller_address(erc20_address, user_address);
    token_dispatcher.approve(dispatcher.contract_address, token_amount);
    stop_cheat_caller_address(erc20_address);

    let allowance = token_dispatcher.allowance(user_address, dispatcher.contract_address);
    assert(allowance >= token_amount, 'Allowance not set correctly');
}

/// Helper function to create a content item with a price
/// We'll use the set_content_price function implemented in the contract
pub fn setup_content_with_price(
    dispatcher: IChainLibDispatcher,
    admin_address: ContractAddress,
    contract_address: ContractAddress,
    content_id: felt252,
    price: u256,
) {
    // Set admin as caller for setting content price
    cheat_caller_address(contract_address, admin_address, CheatSpan::Indefinite);

    // Use the new set_content_price function to set the price
    dispatcher.set_content_price(content_id, price);
}