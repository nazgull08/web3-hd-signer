#![feature(let_chains)]

use std::{collections::HashMap, str::FromStr, thread};

use bip39::Mnemonic;
use config::Config;
use serde_derive::Deserialize;
use web3::types::{H160, H256, U256};
use web3_hd_signer::wallet::{gas_price, send_main, tx_info, tx_receipt, HDSeed, HDWallet, validate_tron_address};

use clap::{Parser, Subcommand, ValueEnum};

use web3_hd_signer::types::*;
use web3_hd_signer::functions::*;

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
            balance
            (conf, c_from, c_to, crypto).await;
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

