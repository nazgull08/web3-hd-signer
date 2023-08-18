#![feature(let_chains)]


use std::{str::FromStr, thread, collections::HashMap};


use bip39::Mnemonic;
use config::Config;
use serde_derive::Deserialize;
use web3::types::{U256, H160, H256};
use web3_hd::wallet::{HDWallet, HDSeed, gas_price, send_main, tx_receipt, tx_info};

use clap::{Parser, Subcommand, ValueEnum};

use web3_hd::types::*;

//NTD
// ETH gas usage 94,795 | 63,197 
// BSC gas usage 76,654 | 51,103 
// MTC gas usage 96,955 | 57,294


#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {     
    #[arg(short,long)]
    crypto: Crypto,
    #[arg(default_value = "./config.toml")]
    path: String,
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
    let crypto = args.crypto;
    match args.command {
        Commands::Balance{c_from: o_c_from, c_to: o_c_to} => {
            let (c_from,c_to) = match (o_c_to,o_c_from) {
                (Some(cfrom),Some(cto)) => (cfrom,cto),
                _ => (0,10)
            };
            balance(conf,c_from,c_to,crypto).await;
        },
        Commands::Refill => {
            println!("Implement refill...");
        },
        Commands::Sweep => {
            println!("Implement sweep...");
        }
    }
}

async fn refill(sweeper_prvk : &str, main_addrs : Vec<WalletAddress>, token_addrs : Vec<WalletAddress>, conf: Settings){
    let provider = &conf.eth_provider;
    for m_a in main_addrs {
        let g_price = gas_price(provider).await.unwrap();
        let val = g_price * 21000;
        let hash = send_main(sweeper_prvk, &m_a.address, val, provider).await.unwrap();
        let mut info= tx_info(hash, provider).await.unwrap();
        println!("--------------------");
        println!("{:?}",info);
        while info.transaction_index == None {
            println!("waiting for confirmation...");
            thread::sleep_ms(5000);
            info = tx_info(hash, provider).await.unwrap();
        }
        println!("---------confirmed-----------");
        println!("{:?}",info)
    }
    for m_a in token_addrs {
        let g_price = gas_price(provider).await.unwrap();
        let val = g_price * 2 * 65000;
        let hash = send_main(sweeper_prvk, &m_a.address, val, provider).await.unwrap();
        let mut info= tx_info(hash, provider).await.unwrap();
        println!("--------------------");
        println!("{:?}",info);
        while info.transaction_index == None {
            thread::sleep_ms(5000);
            info = tx_info(hash, provider).await.unwrap();
        }
        println!("---------confirmed-----------");
        println!("{:?}",info)
    }
}


async fn balance(conf: Settings, c_from: u32, c_to: u32, crypto: Crypto) {
    println!("Calcing balances...");
    let rates = rates().await;
    let sweeper_prvk = conf.sweeper;
    let phrase = conf.hd_phrase;
    //let hdw_eth = HDWallet::Ethereum(HDSeed::new(&phrase));
    let hdw_eth = HDWallet::Tron(HDSeed::new(&phrase));
    let usdt = &conf.eth_token;
    let to = conf.eth_safe;
    let mut wal_addrs_eth: Vec<WalletAddress> = vec![];
    let mut wal_addrs_token: Vec<WalletAddress> = vec![];
    let provider = match crypto {
        Crypto::Eth => {conf.eth_provider},
        Crypto::Tron => {conf.tron_provider},
        Crypto::BSC => {conf.bsc_provider},
        Crypto::Polygon => {conf.plg_provider},
        Crypto::Stellar => {conf.stl_provider},
    };

    for i in c_from..c_to {
        println!("---------");
        let eth_i = hdw_eth.address(i as i32);
        println!("i: = {:?}, addr: {eth_i}", i);
        let eth_priv = hdw_eth.private(i as i32);
        let eth_pub = hdw_eth.public(i as i32);
        let eth_bal = hdw_eth.balance(i as i32, &provider).await;
        let eth_bal_token = ("", U256::zero());// hdw_eth.balance_token(i as i32,usdt, &provider).await;
        let eth_bal_f = eth_bal.1.as_u128() as f64 ;
        let eth_bal_f_prep = eth_bal_f / 1_000_000_000_000_000_000.0;
        let eth_bal_in_usd = eth_bal_f_prep * rates.eth;
        let g_price = gas_price(&provider).await.unwrap(); 
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
