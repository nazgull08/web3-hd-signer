use serde_derive::Deserialize;
use web3::types::U256;

use clap::{Parser, Subcommand, ValueEnum};
use std::fmt::Display;

#[derive(Debug, Clone)]
pub struct WalletAddress {
    pub id: u32,
    pub address: String,
    pub balance: U256,
    pub balance_token: (String, U256),
}

#[derive(Debug, Deserialize)]
pub struct Settings {
    pub sweeper: String,
    pub sweeper_tron_address: String,
    pub hd_phrase: String,
    pub eth_tokens: Vec<String>,
    pub eth_safe: String,
    pub eth_provider: String,
    pub tron_tokens: Vec<String>,
    pub tron_safe: String,
    pub tron_provider: String,
    pub plg_tokens: Vec<String>,
    pub plg_safe: String,
    pub plg_provider: String,
    pub bsc_tokens: Vec<String>,
    pub bsc_safe: String,
    pub bsc_provider: String,
    pub stl_master_key: String,
    pub stl_tokens: Vec<String>,
    pub stl_safe: String,
    pub stl_provider: String,
    pub btc_safe: String,
    pub btc_provider: String,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Balance {
        c: u32,
    },
    Balances {
        c_from: Option<u32>,
        c_to: Option<u32>,
    },
    Refill,
    Sweep {
        c: u32,
    },
    GenPhrase,
    PrivKey {
        c: u32,
    },
    DebugSend {
        c_from: u32,
        c_to: String,
    },
}

#[derive(ValueEnum, Debug, Clone)]
pub enum Crypto {
    Eth,
    Tron,
    Polygon,
    BSC,
    Stellar,
}

#[derive(Debug, Clone)]
pub struct WalletState {
    pub id: u32,
    pub address: String,
    pub state: BalanceState,
}

/// Enum of possible balance states
#[derive(Debug, Clone)]
pub enum BalanceState {
    Empty,
    ///< No money on wallet
    Tokens {
        ///< Only tokens on wallet
        tokens_balance: Vec<(String, U256)>,
    },
    ///< Tokens and main currency on wallet
    TokensMain {
        tokens_balance: Vec<(String, U256)>,
        balance: U256,
    },
    ///< Only main currency on wallet
    Main {
        balance: U256,
    },
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[arg(short, long)]
    crypto: Crypto,
    #[arg(default_value = "./config.toml")]
    path: String,
    #[command(subcommand)]
    command: Commands,
}
#[allow(non_snake_case)]
#[derive(Debug, Deserialize)]
pub struct RatesRaw {
    pub ETH: f64,
    pub TRX: f64,
    pub MATIC: f64,
    pub BNB: f64,
    pub XLM: f64,
}

#[derive(Debug, Deserialize)]
pub struct Rates {
    pub eth: f64,
    pub trx: f64,
    pub mtc: f64,
    pub bnb: f64,
    pub xlm: f64,
}

#[derive(Debug, Clone)]
pub struct TokenData {
    pub balance: U256,
    pub balance_f: f64,
    pub decimals: u8,
    pub symbol: String,
    pub address: String,
}

impl Display for Crypto {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::result::Result<(), ::std::fmt::Error> {
        match *self {
            Crypto::Eth => f.write_str("Eth"),
            Crypto::Tron => f.write_str("Tron"),
            Crypto::Polygon => f.write_str("Polygon"),
            Crypto::BSC => f.write_str("BSC"),
            Crypto::Stellar => f.write_str("Stellar"),
        }
    }
}
