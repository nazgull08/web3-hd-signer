#![feature(let_chains)]
use std::{str::FromStr, thread, collections::HashMap};


use bip39::Mnemonic;
use config::Config;
use serde_derive::Deserialize;
use web3::types::{U256, H160, H256};
use web3_hd::wallet::{HDWallet, HDSeed, gas_price, send_main, tx_receipt, tx_info};

use clap::{Parser, Subcommand};

#[derive(Debug, Clone)]
struct WalletAddress {
    pub id : u32,
    pub address : String,
    pub balance : U256,
    pub balance_token : (String, U256),
}

#[derive(Debug, Deserialize)]
pub struct Settings {
    pub sweeper : String, 
    pub hd_phrase : String, 
    pub token : String,
    pub safe : String
}

#[derive(Subcommand, Debug)]
enum Commands {
    Balance {c_from: Option<u32>, c_to: Option<u32>},
    Refill,
    Sweep
}

//NTD
// ETH gas usage 94,795 | 63,197 
// BSC gas usage 76,654 | 51,103 
// MTC gas usage 96,955 | 57,294

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {     
    #[arg(default_value = "./config.toml")]
    config_path: String,
    #[command(subcommand)]
    command: Commands
}

#[tokio::main]
async fn main() {     
    let args = Cli::parse();
    
    let conf = Config::builder()
        .add_source(config::File::with_name("config.toml"))
        .build()
        .unwrap()
        .try_deserialize::<Settings>()
        .unwrap();
    match args.command {
        Commands::Balance{c_from: o_c_from, c_to: o_c_to} => {
            if let Some(c_from) = o_c_from && let Some(c_to) = o_c_to{
                balance(conf,c_from,c_to).await
            } else {
                balance(conf,0,10).await
            }
        },
        Commands::Refill => {
            println!("Implement refill...");
        },
        Commands::Sweep => {
            println!("Implement sweep...");
        }
    }
}


async fn test_wallet(conf : Settings) {
//        let a = Mnemonic::new(bip39::MnemonicType::Words12, bip39::Language::English);
    let sweeper_prvk = conf.sweeper;
    let phrase = conf.hd_phrase;
    println!("=======================");
    println!("phrase: {:?}",&phrase);
    println!("=======================");

    let hdw_eth = HDWallet::Ethereum(HDSeed::new(&phrase));
    let hdw_tron = HDWallet::Tron(HDSeed::new(&phrase));

    let usdt = &conf.token;

    let to = conf.safe;

    let mut wal_addrs_eth: Vec<WalletAddress> = vec![];
    let mut wal_addrs_token: Vec<WalletAddress> = vec![];

    for i in 0..5 {
        let eth_i = hdw_eth.address(i as i32);
        let tron_i = hdw_tron.address(i as i32);
        let eth_priv = hdw_eth.private(i as i32);
        let tron_priv = hdw_tron.private(i as i32);
        let eth_pub = hdw_eth.public(i as i32);
        let tron_pub = hdw_tron.public(i as i32);
        let eth_bal = hdw_eth.balance(i as i32).await;
        let eth_bal_token = hdw_eth.balance_token(i as i32,usdt).await;
        println!("=======================");
        println!("ETH");
        println!("addr: {:?}", eth_i);
        println!("priv: {:?}", eth_priv);
        println!("pub: {:?}", eth_pub);
        println!("bal: {:?}", eth_bal.1);
        println!("bal_token: {:?}", eth_bal_token.1);
        println!("TRON");
        println!("addr: {:?}", tron_i);
        println!("priv: {:?}", tron_priv);
        println!("pub: {:?}", tron_pub);
        println!("=======================");
        let g_price = gas_price().await.unwrap(); 
        let tx_fee = g_price * 21000 * 5;
        if eth_bal_token.1 > U256::zero() {
            wal_addrs_token.push(WalletAddress { id: i, address: eth_i.clone(), balance: eth_bal.1, balance_token: (usdt.to_owned(), eth_bal_token.1) });
        }
        if eth_bal.1 > tx_fee {
            wal_addrs_eth.push(WalletAddress { id: i, address: eth_i.clone(), balance: eth_bal.1, balance_token: (usdt.to_owned(), eth_bal_token.1) });
        println!("Found {:?} money. Tx fee {tx_fee} Sweeping...",eth_bal.1);
        } else {
            println!("No funds on wallet: {:?} Skipping", eth_bal.1)
        }

    }

    println!("--------------------");
    println!("Addrs: {:?}",wal_addrs_eth);
    println!("Addrs: {:?}",wal_addrs_token);
    println!("--------------------");
    let gas_for_main = wal_addrs_eth.len() * 21000;
    let gas_for_tokens = wal_addrs_token.len() * 65000;
    println!("gas for main: {:?}",gas_for_main);
    println!("gas for tokens: {:?}",gas_for_tokens);

}

async fn refill(sweeper_prvk : &str, main_addrs : Vec<WalletAddress>, token_addrs : Vec<WalletAddress>){
    for m_a in main_addrs {
        let g_price = gas_price().await.unwrap();
        let val = g_price * 21000;
        let hash = send_main(sweeper_prvk, &m_a.address, val).await.unwrap();
        let mut info= tx_info(hash).await.unwrap();
        println!("--------------------");
        println!("{:?}",info);
        while info.transaction_index == None {
            println!("waiting for confirmation...");
            thread::sleep_ms(5000);
            info = tx_info(hash).await.unwrap();
        }
        println!("---------confirmed-----------");
        println!("{:?}",info)
    }
    for m_a in token_addrs {
        let g_price = gas_price().await.unwrap();
        let val = g_price * 2 * 65000;
        let hash = send_main(sweeper_prvk, &m_a.address, val).await.unwrap();
        let mut info= tx_info(hash).await.unwrap();
        println!("--------------------");
        println!("{:?}",info);
        while info.transaction_index == None {
            thread::sleep_ms(5000);
            info = tx_info(hash).await.unwrap();
        }
        println!("---------confirmed-----------");
        println!("{:?}",info)
    }
}


async fn balance(conf: Settings, c_from: u32, c_to: u32) {
    println!("Calcing balances...");
    let rates = rates().await;
    let sweeper_prvk = conf.sweeper;
    let phrase = conf.hd_phrase;
    let hdw_eth = HDWallet::Ethereum(HDSeed::new(&phrase));
    let usdt = &conf.token;
    let to = conf.safe;
    let mut wal_addrs_eth: Vec<WalletAddress> = vec![];
    let mut wal_addrs_token: Vec<WalletAddress> = vec![];

    for i in c_from..c_to {
        println!("---------");
        let eth_i = hdw_eth.address(i as i32);
        println!("i: = {:?}, addr: {eth_i}", i);
        let eth_priv = hdw_eth.private(i as i32);
        let eth_pub = hdw_eth.public(i as i32);
        let eth_bal = hdw_eth.balance(i as i32).await;
        let eth_bal_token = hdw_eth.balance_token(i as i32,usdt).await;
        let eth_bal_f = eth_bal.1.as_u128() as f64 ;
        let eth_bal_f_prep = eth_bal_f / 1_000_000_000_000_000_000.0;
        let eth_bal_in_usd = eth_bal_f_prep * rates.eth;
        let g_price = gas_price().await.unwrap(); 
        let tx_fee: U256 = g_price * 21000 * 5;
        let tx_fee_prep = tx_fee.as_u128() as f64 / 1_000_000_000_000_000_000.0;
        if eth_bal_token.1 > U256::zero() {
            wal_addrs_token.push(WalletAddress { id: i, address: eth_i.clone(), balance: eth_bal.1, balance_token: (usdt.to_owned(), eth_bal_token.1) });
            println!("Found {:.10} token money.",eth_bal_f_prep);
            println!("bal: {:?}", eth_bal.1);
            println!("bal_in_usd: {:.15}", eth_bal_in_usd);
            println!("bal_token: {:?}", eth_bal_token.1);
        }
        if eth_bal.1 > tx_fee {
            wal_addrs_eth.push(WalletAddress { id: i, address: eth_i.clone(), balance: eth_bal.1, balance_token: (usdt.to_owned(), eth_bal_token.1) });
            println!("Found {:.10} main money. Tx fee {tx_fee_prep}",eth_bal_f_prep);
            println!("bal: {:?}", eth_bal.1);
            println!("bal_in_usd: {:.15}", eth_bal_in_usd);
            println!("bal_token: {:?}", eth_bal_token.1);
        } else {
            println!("No funds on wallet. Skipping")
        }

    }
}
#[allow(non_snake_case)]
#[derive(Debug,Deserialize)]
pub struct RatesRaw{
    pub ETH: f64,
    pub TRX: f64,
    pub MATIC: f64,
    pub BNB: f64,
    pub XLM: f64,
}

#[derive(Debug,Deserialize)]
pub struct Rates{
    pub eth: f64,
    pub trx: f64,
    pub mtc: f64,
    pub bnb: f64,
    pub xlm: f64,
}

async fn rates() -> Rates {
    println!("getting current rates...");
    let rs:RatesRaw = reqwest::get("https://min-api.cryptocompare.com/data/price?fsym=USD&tsyms=ETH,TRX,MATIC,BNB,XLM")
        .await
        .unwrap()
        .json::<RatesRaw>()
        .await
        .unwrap();
    let rates: Rates = Rates { eth: 1./rs.ETH, trx: 1./rs.TRX, mtc: 1./rs.MATIC, bnb: 1./rs.BNB, xlm: 1./rs.XLM};
    println!("Rates:\nETH:{:.4}$\nTRX:{:.4}$\nMTC:{:.4}$\nBNB:{:.4}$\nXLM:{:.4}$\n", rates.eth,rates.trx,rates.mtc,rates.bnb,rates.xlm);
    rates
}
