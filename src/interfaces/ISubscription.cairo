use starknet::ContractAddress;

/// Interface for managing subscription-based payments and related operations
#[starknet::interface]
pub trait ISubscription<TContractState> {
    /// Process the initial payment when a subscriber signs up
    /// @param amount: The payment amount in wei
    /// @param subscriber: The address of the subscriber
    /// @return: Boolean indicating if the payment was successful
    fn process_initial_payment(
        ref self: TContractState, amount: u256, subscriber: ContractAddress
    ) -> bool;

    /// Process a recurring payment for an existing subscription
    /// @param subscription_id: The unique identifier of the subscription
    /// @return: Boolean indicating if the payment was successful
    fn process_recurring_payment(ref self: TContractState, subscription_id: u256) -> bool;

    /// Verify if a payment has been processed successfully
    /// @param payment_id: The unique identifier of the payment
    /// @return: Boolean indicating if the payment is verified
    fn verify_payment(ref self: TContractState, payment_id: u256) -> bool;

    /// Process a refund for a subscription
    /// @param subscription_id: The unique identifier of the subscription to refund
    /// @return: Boolean indicating if the refund was successful
    fn process_refund(ref self: TContractState, subscription_id: u256) -> bool;
}
