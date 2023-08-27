use std::{collections::HashMap, str::FromStr, thread};

use bip39::Mnemonic;
use config::Config;
use serde_derive::Deserialize;
use web3::types::{H160, H256, U256};

use clap::{Parser, Subcommand, ValueEnum};

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
    pub stl_tokens: Vec<String>,
    pub stl_safe: String,
    pub stl_provider: String,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Balance {
        c_from: Option<u32>,
        c_to: Option<u32>,
    },
    Refill,
    Sweep,
    GenPhrase,
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
pub enum BalanceState {
    Empty,
    Tokens {
        tokens_balance: Vec<(String, U256)>,
    },
    TokensMain {
        tokens_balance: Vec<(String, U256)>,
        balance: U256,
    },
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
}

