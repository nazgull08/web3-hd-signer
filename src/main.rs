use std::{str::FromStr, thread, collections::HashMap};


use bip39::Mnemonic;
use config::Config;
use serde_derive::Deserialize;
use web3::types::{U256, H160, H256};
use web3_hd::wallet::{HDWallet, HDSeed, gas_price, send_main, tx_receipt, tx_info};

use clap::Parser;

#[derive(Debug, Clone)]
struct WalletAddress {
    pub id : i32,
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

//NTD
// ETH gas usage 94,795 | 63,197 
// BSC gas usage 76,654 | 51,103 
// PLG gas usage 96,955 | 57,294

#[derive(Parser)]
struct Cli {     
    pattern: String,
    path: std::path::PathBuf
}

#[tokio::main]
async fn main() {     
    let args = Cli::parse();
    let v = vec![1, 2, 3];     
    println!("Hello, world!"); 
    
    //let a = Mnemonic::new(bip39::MnemonicType::Words12, bip39::Language::English);
    //println!("a: {:?}",a);
    let conf = Config::builder()
        .add_source(config::File::with_name("config.toml"))
        .build()
        .unwrap()
        .try_deserialize::<Settings>()
        .unwrap();
    println!("{:?}",conf);
    //test_wallet().await
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
        //let a_token = hdw_eth.sweep_token(i, usdt,to).await;
        }
        if eth_bal.1 > tx_fee {
            wal_addrs_eth.push(WalletAddress { id: i, address: eth_i.clone(), balance: eth_bal.1, balance_token: (usdt.to_owned(), eth_bal_token.1) });
        println!("Found {:?} money. Tx fee {tx_fee} Sweeping...",eth_bal.1);
        //let a = hdw_eth.sweep(i, to).await;
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
