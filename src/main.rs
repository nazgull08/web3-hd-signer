#![feature(let_chains)]

use std::{collections::HashMap, str::FromStr, thread};

use bip39::Mnemonic;
use config::Config;
use serde_derive::Deserialize;
use web3::types::{H160, H256, U256};
use web3_hd_signer::wallet::{gas_price, send_main, tx_info, tx_receipt, HDSeed, HDWallet, validate_tron_address};

use clap::{Parser, Subcommand, ValueEnum};

use web3_hd_signer::types::*;

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

    let tokens= match crypto {
        Crypto::Eth => conf.eth_tokens,
        Crypto::Tron => conf.tron_tokens,
        Crypto::BSC => conf.bsc_tokens,
        Crypto::Polygon => conf.plg_tokens,
        Crypto::Stellar => conf.stl_tokens,
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
        Crypto::Eth => U256::exp10(16), 
        Crypto::Tron => U256::exp10(4), 
        Crypto::BSC => U256::exp10(16),
        Crypto::Polygon => U256::exp10(16),
        Crypto::Stellar => U256::exp10(16)
    };

    for i in c_from..c_to {
        println!("---------");
        let addr_i = hdw.address(i as i32);
        println!("i: = {:?}, addr: {addr_i}", i);
        let (main_bal,main_bal_usd) = check_main_balance(&hdw, i as i32, &provider, decimals, rate).await;
        let tokens_bal = check_tokens_balance(&hdw, i as i32, &provider, &tokens).await;
        println!("tokens_bal: {:?}", tokens_bal);
        let g_price = gas_price(&provider).await.unwrap();
        let tx_fee: U256 = g_price * 21000 * 5;
        let tx_fee_prep = (tx_fee / decimals).as_u128() as f64 * 0.01;
        for t in tokens_bal {
            if t.balance > U256::zero() {
                println!("Found {:.4} token money.", t.balance_f);
                println!("bal_token: {:?}", t.symbol);
            }
        }
        if main_bal > tx_fee {
            println!("bal: {:?}", main_bal/decimals);
            println!("bal_in_usd: {:.15}", main_bal_usd);
        } else if main_bal.is_zero() { 
            println!("Zero funds on address. Skipping.");
        } else {
            println!(
                "Funds < fee: {:.12} < {:.12}. Skipping.",
                main_bal, tx_fee_prep
            );
        }
    }
}

async fn check_main_balance(
    hdw: &HDWallet,
    id: i32,
    provider: &str,
    decimals: U256,
    rate: f64,
) -> (U256,f64) {
    let addr_bal = hdw.balance(id, &provider).await;
    let addr_bal_f = addr_bal / decimals;
    let addr_bal_f_prep = addr_bal_f.as_u128() as f64 * 0.01;
    (addr_bal,addr_bal_f_prep * rate)
}

async fn check_tokens_balance(
    hdw: &HDWallet,
    id: i32,
    provider: &str,
    tokens: &Vec<String>
) -> Vec<TokenData> {
    let mut tokens_balances : Vec<TokenData> = vec![];
    for token in tokens{
        let t_data = hdw.balance_token(id as i32, &token, &provider).await;
        tokens_balances.push(t_data);
    };
    tokens_balances
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
