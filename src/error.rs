use web3::types::{H256,U256};

use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Web3 error: {0}")]
    Web3Error(#[from] web3::Error),
    #[error("Web3 contract error: {0}")]
    Web3ContractError(#[from] web3::contract::Error),
    #[error("Web3 abi decoding/encoding error: {0}")]
    Web3AbiError(#[from] web3::ethabi::Error),
    #[error("Web3 no transactions found {0}")]
    Web3NoTransactionError(H256),
    #[error("Stellar SDK error")]
    StellarSDKError(Arc<anyhow::Error>),
    #[error("Stellar parsing error")]
    StellarParsingFloatError(#[from] std::num::ParseFloatError),
    #[error("Reqwest rates error")]
    ReqwestRatesError(#[from] reqwest::Error),
    #[error("Decoding from hex error")]
    RustcFromHexError(#[from] rustc_hex::FromHexError),
    #[error("secp256k1 error")]
    Secp256Error(#[from] secp256k1::Error),
    #[error("Base58 decoding/encoding error")]
    Base58Error(#[from] bitcoin::base58::Error),
    #[error("Bitcoin bip32 error")]
    BitcoinBip32Error(#[from] bitcoin::bip32::Error),
    #[error("Hex decoding error")]
    HexError(#[from] hex::FromHexError),
    #[error("EthAddr is {0} instead of 42 chars long")]
    EthAddrLengthError(usize),
    #[error("Config error")]
    ConfigError(#[from] config::ConfigError),
    #[error("Mnemonic error")]
    MnemonicError(String),
    #[error("Tron address {0} to hex error")]
    TronToHexError(String),
    #[error("Tron transfer error")]
    TronTransferError(#[from] crate::tron::error::Error),
    #[error("Balance {0} is less than the required fee {1} at {2}")]
    NotEnoughBalanceError(U256,U256,String)
}
