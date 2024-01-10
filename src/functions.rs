use ethers::types::H256;
use std::{str::FromStr, thread, time};
use web3::types::{U256, Transaction};

use crate::{
    error::Error,
    fee::check_fee_token,
    tron::calls::transfer_trx,
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
        "Sweeping from {0} to {1} in {2}...",
        hdw.address(i as i32)?,
        &to,
        crypto
    );
    let res = hdw.sweep(i as i32, &to, &provider).await?;
    println!("{:?}",res);
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
        let _ = refill_address(
            &conf.sweeper,
            &conf.sweeper_tron_address,
            &addr,
            val,
            provider,
            crypto,
        )
        .await?;
    };
    for (tok, _) in tokens {
        let (tx,_)= hdw.sweep_token(i as i32, &tok, to, provider).await?;
        println!("sweeped: {:?}", tx);
        let mut info = tx_info(tx.hash, provider).await?;
        while info.transaction_index.is_none() {
            println!("waiting for confirmation...");
            thread::sleep(time::Duration::from_secs(5));
            info = tx_info(tx.hash, provider).await?;
        }
        println!("---------confirmed-----------");
    }
    Ok(())
}

pub async fn refill_address(
    sweeper_prvk: &str,
    sweeper_tron_address: &str,
    addr: &str,
    val: U256,
    provider: &str,
    crypto: &Crypto,
) -> Result<Transaction, Error> {
    let hash = match crypto {
        Crypto::Tron => {
            let amount = 10120000;
            let sweeper_addr = tron_to_hex_raw(sweeper_tron_address)?;
            let to = tron_to_hex_raw(addr)?;
            //
            H256::from_str(&transfer_trx(&sweeper_addr, &to, sweeper_prvk, amount).await?)?
        }
        _ => send_main(sweeper_prvk, addr, val, provider).await?,
    };
    println!("{:?}", hash);
    let mut info = {
        let r_info = tx_info(hash, provider).await;
        let mut counter = 0;
        while r_info.is_err() && counter < 10 {
            counter += 1;
            println!("waiting for transaction {:?}...", hash);
            thread::sleep(time::Duration::from_secs(5));
        }
        r_info?
    };
    println!("--------------------");
    println!("{:?}", info);
    let mut counter = 0;
    while info.transaction_index.is_none() && counter < 10 {
        counter += 1;
        println!("waiting for confirmation... {:?}",hash);
        thread::sleep(time::Duration::from_secs(5));
        info = tx_info(hash, provider).await?;
    }
    println!("---------confirmed-----------");
    println!("{:?}", info);
    Ok(info)
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
    c_to: String,
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

    //let from_1_hex = tron_to_hex_raw(&hdw.address((c_from + 1) as i32)?)?;
    let to = tron_to_hex_raw(&c_to)?;
    let _res = transfer_trx(&from_hex, &to, &pk, 881188).await;
    //let contract_addr = conf.tron_tokens[0].clone();
    //transfer_trc20(&from_hex, &from_1_hex, &pk, 154321, &contract_addr).await;

    Ok("werwe".to_string())
}
