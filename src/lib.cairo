pub mod base {
    pub mod errors;
    pub mod types;
}
pub mod chainlib {
    pub mod ChainLib;
    pub mod AccountDelegation;
}
pub mod interfaces {
    pub mod IChainLib;
    pub mod IAccountDelegation;
}

pub mod events {
    pub mod AccountDelegationEvent;
}
