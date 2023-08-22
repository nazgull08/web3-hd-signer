#![feature(let_chains)]

use std::{collections::HashMap, str::FromStr, thread};

use bip39::Mnemonic;
use config::Config;
use serde_derive::Deserialize;
use web3::types::{H160, H256, U256};
use web3_hd::wallet::{gas_price, send_main, tx_info, tx_receipt, HDSeed, HDWallet};

use clap::{Parser, Subcommand, ValueEnum};

use web3_hd::types::*;

//NTD
// ETH gas usage 94,795 | 63,197
// BSC gas usage 76,654 | 51,103
// MTC gas usage 96,955 | 57,294

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long)]
    crypto: Crypto,
    #[arg(default_value = "./config.toml")]
    path: String,
    #[command(subcommand)]
    command: Commands,
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
        Commands::Balance {
            c_from: o_c_from,
            c_to: o_c_to,
        } => {
            let (c_from, c_to) = match (o_c_to, o_c_from) {
                (Some(cfrom), Some(cto)) => (cto, cfrom),
                _ => (0, 10),
            };
            balance(conf, c_from, c_to, crypto).await;
        }
        Commands::Refill => {
            println!("Implement refill...");
        }
        Commands::Sweep => {
            println!("Implement sweep...");
        }
        Commands::GenPhrase => {
            generate_hd_prase().await;
        }
    }
}

async fn refill(
    sweeper_prvk: &str,
    main_addrs: Vec<WalletAddress>,
    token_addrs: Vec<WalletAddress>,
    conf: Settings,
) {
    let provider = &conf.eth_provider;
    for m_a in main_addrs {
        let g_price = gas_price(provider).await.unwrap();
        let val = g_price * 21000;
        let hash = send_main(sweeper_prvk, &m_a.address, val, provider)
            .await
            .unwrap();
        let mut info = tx_info(hash, provider).await.unwrap();
        println!("--------------------");
        println!("{:?}", info);
        while info.transaction_index == None {
            println!("waiting for confirmation...");
            thread::sleep_ms(5000);
            info = tx_info(hash, provider).await.unwrap();
        }
        println!("---------confirmed-----------");
        println!("{:?}", info)
    }
    for m_a in token_addrs {
        let g_price = gas_price(provider).await.unwrap();
        let val = g_price * 2 * 65000;
        let hash = send_main(sweeper_prvk, &m_a.address, val, provider)
            .await
            .unwrap();
        let mut info = tx_info(hash, provider).await.unwrap();
        println!("--------------------");
        println!("{:?}", info);
        while info.transaction_index == None {
            thread::sleep_ms(5000);
            info = tx_info(hash, provider).await.unwrap();
        }
        println!("---------confirmed-----------");
        println!("{:?}", info)
    }
}

async fn generate_hd_prase() -> () {
    let a = Mnemonic::new(bip39::MnemonicType::Words12, bip39::Language::English);
    let phrase = a.into_phrase();
    println!("-----------");
    println!("{:?}", phrase);
}

async fn balance(conf: Settings, c_from: u32, c_to: u32, crypto: Crypto) {
    println!("Calcing balances...");
    let rates = rates().await;
    let phrase = conf.hd_phrase;
    let hdw = match crypto {
        Crypto::Eth => HDWallet::Ethereum(HDSeed::new(&phrase)),
        Crypto::Tron => HDWallet::Tron(HDSeed::new(&phrase)),
        Crypto::BSC => HDWallet::Ethereum(HDSeed::new(&phrase)),
        Crypto::Polygon => HDWallet::Ethereum(HDSeed::new(&phrase)),
        Crypto::Stellar => HDWallet::Stellar(HDSeed::new(&phrase)),
    };

    let usdt = match crypto {
        Crypto::Eth => &conf.eth_tokens[0],
        Crypto::Tron => &conf.tron_tokens[0],
        Crypto::BSC => &conf.bsc_tokens[0],
        Crypto::Polygon => &conf.plg_tokens[0],
        Crypto::Stellar => &conf.stl_tokens[0],
    };
    let to = conf.eth_safe;
    let mut wal_addrs_main: Vec<WalletAddress> = vec![];
    let mut wal_addrs_token: Vec<WalletAddress> = vec![];
    let provider = match crypto {
        Crypto::Eth => conf.eth_provider,
        Crypto::Tron => conf.tron_provider,
        Crypto::BSC => conf.bsc_provider,
        Crypto::Polygon => conf.plg_provider,
        Crypto::Stellar => conf.stl_provider,
    };
    let rate = match crypto {
        Crypto::Eth => rates.eth,
        Crypto::Tron => rates.trx,
        Crypto::BSC => rates.bnb,
        Crypto::Polygon => rates.mtc,
        Crypto::Stellar => rates.xlm,
    };

    let decimals = match crypto {
        Crypto::Eth => 1_000_000_000_000_000_000.0,
        Crypto::Tron => 1_000_000.0,
        Crypto::BSC => 1_000_000_000_000_000_000.0,
        Crypto::Polygon => 1_000_000_000_000_000_000.0,
        Crypto::Stellar => 1_000_000_000_000_000_000.0,
    };

    let token_decimals = 1_000_000.0;

    for i in c_from..c_to {
        println!("---------");
        let addr_i = hdw.address(i as i32);
        println!("i: = {:?}, addr: {addr_i}", i);
        let addr_bal = hdw.balance(i as i32, &provider).await;
        let addr_bal_token = hdw.balance_token(i as i32, &usdt, &provider).await;
        let addr_bal_token_f = addr_bal_token.as_u128() as f64 / token_decimals;
        let addr_bal_f = addr_bal.as_u128() as f64;
        let addr_bal_f_prep = addr_bal_f / decimals;
        let addr_bal_in_usd = addr_bal_f_prep * rate;
        let g_price = gas_price(&provider).await.unwrap();
        let tx_fee: U256 = g_price * 21000 * 5;
        let tx_fee_prep = tx_fee.as_u128() as f64 / decimals;
        if addr_bal_token > U256::zero() {
            wal_addrs_token.push(WalletAddress {
                id: i,
                address: addr_i.clone(),
                balance: addr_bal,
                balance_token: (usdt.to_owned(), addr_bal_token),
            });
            println!("Found {:.10} token money.", addr_bal_token_f);
            println!("bal: {:?}", addr_bal);
            println!("bal_in_usd: {:.15}", addr_bal_in_usd);
            println!("bal_token: {:?}", addr_bal_token);
        }
        if addr_bal > tx_fee {
            wal_addrs_main.push(WalletAddress {
                id: i,
                address: addr_i.clone(),
                balance: addr_bal,
                balance_token: (usdt.to_owned(), addr_bal_token),
            });
            println!(
                "Found {:.10} main money. Tx fee {tx_fee_prep}",
                addr_bal_f_prep
            );
            println!("bal: {:?}", addr_bal);
            println!("bal_in_usd: {:.15}", addr_bal_in_usd);
            println!("bal_token: {:?}", addr_bal_token);
        } else if (addr_bal.is_zero() && addr_bal_token.is_zero()) {
            println!("Zero funds on address. Skipping.");
        } else {
            println!(
                "Funds < fee: {:.12} < {:.12}. Skipping.",
                addr_bal_f_prep, tx_fee_prep
            );
        }
    }
}

async fn check_main_balance(
    hdw: HDWallet,
    id: i32,
    provider: &str,
    decimals: f64,
    rate: f64,
) -> f64 {
    let addr_bal = hdw.balance(id, &provider).await;
    let addr_bal_f = addr_bal.as_u128() as f64;
    let addr_bal_f_prep = addr_bal_f / decimals;
    addr_bal_f_prep * rate
}

async fn rates() -> Rates {
    println!("getting current rates...");
    let rs: RatesRaw = reqwest::get(
        "https://min-api.cryptocompare.com/data/price?fsym=USD&tsyms=ETH,TRX,MATIC,BNB,XLM",
    )
    .await
    .unwrap()
    .json::<RatesRaw>()
    .await
    .unwrap();
    let rates: Rates = Rates {
        eth: 1. / rs.ETH,
        trx: 1. / rs.TRX,
        mtc: 1. / rs.MATIC,
        bnb: 1. / rs.BNB,
        xlm: 1. / rs.XLM,
    };
    println!(
        "Rates:\nETH:{:.4}$\nTRX:{:.4}$\nMTC:{:.4}$\nBNB:{:.4}$\nXLM:{:.4}$\n",
        rates.eth, rates.trx, rates.mtc, rates.bnb, rates.xlm
    );
    rates
}
