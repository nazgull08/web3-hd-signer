#![feature(let_chains)]

use std::{thread, time};

use bip39::Mnemonic;
use config::Config;
use web3_hd_signer::wallet::{gas_price, send_main, tx_info};

use clap::Parser;

use web3_hd_signer::functions::*;
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
async fn main() -> Result<(), Error> {
    let args = Cli::parse();

    let conf = Config::builder()
        .add_source(config::File::with_name("config.toml"))
        .build()?
        .try_deserialize::<Settings>()?;
    let crypto = args.crypto;
    match args.command {
        Commands::Balance {c} =>{
            let b = balance(&conf,c,&crypto).await?;
            println!("{:?}",b);
        },
        Commands::Balances {
            c_from: o_c_from,
            c_to: o_c_to,
        } => {
            let (c_from, c_to) = match (o_c_to, o_c_from) {
                (Some(cfrom), Some(cto)) => (cto, cfrom),
                _ => (0, 10),
            };
            let balances = balances(&conf, c_from, c_to, &crypto).await?;
            for b in balances {
                println!("================================");
                println!("{:?}", b);
            }
        },
        Commands::Refill => {
            println!("Implement refill...");
        },
        Commands::Sweep{c} => {
            let b = balance(&conf, c, &crypto).await?;
            match b.state {
                BalanceState::Empty => {println!("nothing to sweep")},
                BalanceState::Main { balance } => { sweep_main(conf, c, crypto).await?; },
                BalanceState::Tokens { tokens_balance } => {
                    sweep_tokens(&conf, c, &crypto, tokens_balance).await?;
                },
                BalanceState::TokensMain { tokens_balance, balance } => { 
                    sweep_tokens(&conf, c, &crypto, tokens_balance).await?;
                    sweep_main(conf, c, crypto).await?; 
                },
            };
        },
        Commands::GenPhrase => {
            generate_hd_prase().await;
        }
        Commands::PrivKey{c}=> {
            let b = privkey(&conf,c,&crypto).await?;
        }
    };
    Ok(())
}

async fn refill_all(
    sweeper_prvk: &str,
    main_addrs: Vec<WalletAddress>,
    token_addrs: Vec<WalletAddress>,
    conf: Settings,
) -> Result<(), Error> {
    let provider = &conf.eth_provider;
    for m_a in main_addrs {
        let g_price = gas_price(provider).await?;
        let val = g_price * 21000;
        let hash = send_main(sweeper_prvk, &m_a.address, val, provider).await?;
        let mut info = tx_info(hash, provider).await?;
        println!("--------------------");
        println!("{:?}", info);
        while info.transaction_index.is_none() {
            println!("waiting for confirmation...");
            thread::sleep(time::Duration::from_secs(5));
            info = tx_info(hash, provider).await?;
        }
        println!("---------confirmed-----------");
        println!("{:?}", info)
    }
    for m_a in token_addrs {
        let g_price = gas_price(provider).await?;
        let val = g_price * 2 * 65000;
        let hash = send_main(sweeper_prvk, &m_a.address, val, provider).await?;
        let mut info = tx_info(hash, provider).await?;
        println!("--------------------");
        println!("{:?}", info);
        while info.transaction_index.is_none() {
            thread::sleep(time::Duration::from_secs(5));
            info = tx_info(hash, provider).await?;
        }
        println!("---------confirmed-----------");
        println!("{:?}", info)
    }
    Ok(())
}

async fn generate_hd_prase() {
    let a = Mnemonic::new(bip39::MnemonicType::Words12, bip39::Language::English);
    let phrase = a.into_phrase();
    println!("-----------");
    println!("{:?}", phrase);
}
