use std::{str::FromStr, thread, time};
use web3::types::{H160, U256};

use crate::{
    error::Error,
    fee::check_fee_token,
    tron::calls::{transfer_trc20, transfer_trx},
    types::*,
    wallet::{send_main, tron_to_hex_raw, tx_info, HDSeed, HDWallet},
};

pub async fn sweep_main(conf: Settings, i: u32, crypto: Crypto) -> Result<(), Error> {
    let hdw = match crypto {
        Crypto::Eth => HDWallet::Ethereum(HDSeed::new(&conf.hd_phrase)?),
        Crypto::Tron => HDWallet::Tron(HDSeed::new(&conf.hd_phrase)?),
        Crypto::BSC => HDWallet::Ethereum(HDSeed::new(&conf.hd_phrase)?),
        Crypto::Polygon => HDWallet::Ethereum(HDSeed::new(&conf.hd_phrase)?),
        Crypto::Stellar => HDWallet::Stellar(conf.stl_master_key),
    };
    let provider = match crypto {
        Crypto::Eth => conf.eth_provider,
        Crypto::Tron => conf.tron_provider,
        Crypto::BSC => conf.bsc_provider,
        Crypto::Polygon => conf.plg_provider,
        Crypto::Stellar => conf.stl_provider,
    };
    let to = match crypto {
        Crypto::Eth => conf.eth_safe,
        Crypto::Tron => conf.tron_safe,
        Crypto::BSC => conf.bsc_safe,
        Crypto::Polygon => conf.plg_safe,
        Crypto::Stellar => conf.stl_safe,
    };
    println!(
        "Sweeping from {0} in {1}...",
        hdw.address(i as i32)?,
        crypto
    );
    let res = hdw.sweep(i as i32, &to, &provider).await?;
    println!("{res}");
    Ok(())
}

pub async fn sweep_tokens(
    conf: &Settings,
    i: u32,
    crypto: &Crypto,
    tokens: Vec<(String, U256)>,
) -> Result<(), Error> {
    let hdw = match crypto {
        Crypto::Eth => HDWallet::Ethereum(HDSeed::new(&conf.hd_phrase)?),
        Crypto::Tron => HDWallet::Tron(HDSeed::new(&conf.hd_phrase)?),
        Crypto::BSC => HDWallet::Ethereum(HDSeed::new(&conf.hd_phrase)?),
        Crypto::Polygon => HDWallet::Ethereum(HDSeed::new(&conf.hd_phrase)?),
        Crypto::Stellar => HDWallet::Stellar(conf.stl_master_key.to_owned()),
    };
    let provider = match crypto {
        Crypto::Eth => &conf.eth_provider,
        Crypto::Tron => &conf.tron_provider,
        Crypto::BSC => &conf.bsc_provider,
        Crypto::Polygon => &conf.plg_provider,
        Crypto::Stellar => &conf.stl_provider,
    };
    let to = match crypto {
        Crypto::Eth => &conf.eth_safe,
        Crypto::Tron => &conf.tron_safe,
        Crypto::BSC => &conf.bsc_safe,
        Crypto::Polygon => &conf.plg_safe,
        Crypto::Stellar => &conf.stl_safe,
    };
    let addr = hdw.address(i as i32)?;
    println!("Sweeping from {0} in {1}...", &addr, crypto);
    let balance = hdw.balance(i as i32, provider).await?;
    let fee = check_fee_token(&hdw, provider).await? * tokens.len();
    if balance < fee {
        let val = fee - balance;
        println!(
            "Balance: {0}, fee {1}, refilling for {2}",
            balance, fee, val
        );
        refill_address(&conf.sweeper, &addr, val, provider).await?;
    };
    for (tok, _) in tokens {
        println!("token_addr: {:?}", &tok);
        println!("tok: {tok}");
        let hash = hdw.sweep_token(i as i32, &tok, to, provider).await?;
        println!("sweeped: {:?}", hash);
        let mut info = tx_info(hash, provider).await?;
        while info.transaction_index.is_none() {
            println!("waiting for confirmation...");
            thread::sleep(time::Duration::from_secs(5));
            info = tx_info(hash, provider).await?;
        }
        println!("---------confirmed-----------");
    }
    Ok(())
}

pub async fn refill_address(
    sweeper_prvk: &str,
    addr: &str,
    val: U256,
    provider: &str,
) -> Result<(), Error> {
    let hash = send_main(sweeper_prvk, addr, val, provider).await?;
    let mut info = {
        let r_info = tx_info(hash, provider).await;
        while r_info.is_err() {
            println!("waiting for transaction...");
            thread::sleep(time::Duration::from_secs(1));
        }
        r_info?
    };
    println!("--------------------");
    println!("{:?}", info);
    while info.transaction_index.is_none() {
        println!("waiting for confirmation...");
        thread::sleep(time::Duration::from_secs(5));
        info = tx_info(hash, provider).await?;
    }
    println!("---------confirmed-----------");
    println!("{:?}", info);
    Ok(())
}

pub fn tron_call(conf: &Settings, i: i32) -> Result<String, Error> {
    let _tx_raw = "0a026ffa22086e06b4977c94304540908fb8e4a6315a67080112630a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412320a1541279f93bc1feb8af89d3253c5471b823c26671a92121541c90c049a15d5ef5af136653ccd6f26758b821e9018a08d0670c3c5b4e4a631";
    let hdw = HDWallet::Tron(HDSeed::new(&conf.hd_phrase)?);
    let hdw_addr = hdw.address(i)?;
    let hdw_priv = hdw.private(i)?;
    let hdw_keypair = hdw.keypair(i)?;
    let _tx_par = web3::types::TransactionParameters {
        nonce: Some(U256::from(10)),
        to: Some(H160::from_str(
            "0x41c90c049a15d5ef5af136653ccd6f26758b821e90",
        )?),
        value: U256::from(15000),
        ..Default::default()
    };
    //    let accs = web3::api::Accounts::
    //    let res = web3::api::Accounts::sign_transaction(tx_par, hdw_keypair.0);
    println!("hdw_addr: {:?}", hdw_addr);
    println!("hdw_priv: {:?}", hdw_priv);
    println!("hdw_keypair: {:?}", hdw_keypair);
    Ok("still not implemented".to_owned())
}

pub async fn privkey_print(conf: &Settings, i: u32, crypto: &Crypto) -> Result<(), Error> {
    let phrase = &conf.hd_phrase;
    let mk = &conf.stl_master_key;

    let hdw = match crypto {
        Crypto::Eth => HDWallet::Ethereum(HDSeed::new(phrase)?),
        Crypto::Tron => HDWallet::Tron(HDSeed::new(phrase)?),
        Crypto::BSC => HDWallet::Ethereum(HDSeed::new(phrase)?),
        Crypto::Polygon => HDWallet::Ethereum(HDSeed::new(phrase)?),
        Crypto::Stellar => HDWallet::Stellar(mk.to_owned()),
    };

    let addr_i = hdw.address(i as i32)?;
    let priv_k = hdw.private(i as i32)?;
    println!("addr: {:?}", addr_i);
    println!("priv: {:?}", priv_k);
    Ok(())
}

pub async fn privkey(conf: &Settings, i: u32, crypto: &Crypto) -> Result<String, Error> {
    let phrase = &conf.hd_phrase;
    let mk = &conf.stl_master_key;

    let hdw = match crypto {
        Crypto::Eth => HDWallet::Ethereum(HDSeed::new(phrase)?),
        Crypto::Tron => HDWallet::Tron(HDSeed::new(phrase)?),
        Crypto::BSC => HDWallet::Ethereum(HDSeed::new(phrase)?),
        Crypto::Polygon => HDWallet::Ethereum(HDSeed::new(phrase)?),
        Crypto::Stellar => HDWallet::Stellar(mk.to_owned()),
    };

    hdw.private(i as i32)
}

pub async fn debug_send(
    conf: &Settings,
    c_from: u32,
    _c_to: String,
    crypto: &Crypto,
) -> Result<String, Error> {
    let phrase = &conf.hd_phrase;
    let mk = &conf.stl_master_key;

    let hdw = match crypto {
        Crypto::Eth => HDWallet::Ethereum(HDSeed::new(phrase)?),
        Crypto::Tron => HDWallet::Tron(HDSeed::new(phrase)?),
        Crypto::BSC => HDWallet::Ethereum(HDSeed::new(phrase)?),
        Crypto::Polygon => HDWallet::Ethereum(HDSeed::new(phrase)?),
        Crypto::Stellar => HDWallet::Stellar(mk.to_owned()),
    };
    let pk = hdw.private(c_from as i32)?;
    let from_hex = tron_to_hex_raw(&hdw.address(c_from as i32)?)?;

    let from_1_hex = tron_to_hex_raw(&hdw.address((c_from + 1) as i32)?)?;
    let contract_addr = conf.tron_tokens[0].clone();

    transfer_trx(&from_hex, &from_1_hex, &pk, 23456).await;
    transfer_trc20(&from_hex, &from_1_hex, &pk, 154321, &contract_addr).await;

    Ok("werwe".to_string())
}
