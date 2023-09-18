use std::{thread, time, str::FromStr};
use bitcoin::PrivateKey;
use secp256k1::Secp256k1;
use web3::types::{U256, H160, H256};

use crate::{
    types::*,
    wallet::{gas_price, HDSeed, HDWallet, send_main, tx_info},
};

pub async fn balances(
    conf: &Settings,
    c_from: u32,
    c_to: u32,
    crypto: &Crypto,
) -> Result<Vec<WalletState>, Error> {
    println!("Calcing balances...");
    let rates = rates().await?;
    let phrase = &conf.hd_phrase;
    let mk = &conf.stl_master_key;

    let hdw = match crypto {
        Crypto::Eth => HDWallet::Ethereum(HDSeed::new(&phrase)?),
        Crypto::Tron => HDWallet::Tron(HDSeed::new(&phrase)?),
        Crypto::BSC => HDWallet::Ethereum(HDSeed::new(&phrase)?),
        Crypto::Polygon => HDWallet::Ethereum(HDSeed::new(&phrase)?),
        Crypto::Stellar => HDWallet::Stellar(mk.to_owned()),
        Crypto::Btc => HDWallet::Bitcoin(HDSeed::new(&phrase)?)
    };

    let empty = vec![];

    let tokens = match crypto {
        Crypto::Eth => &conf.eth_tokens,
        Crypto::Tron => &conf.tron_tokens,
        Crypto::BSC => &conf.bsc_tokens,
        Crypto::Polygon => &conf.plg_tokens,
        Crypto::Stellar => &conf.stl_tokens,
        Crypto::Btc => &empty
    };
    let provider = match crypto {
        Crypto::Eth => &conf.eth_provider,
        Crypto::Tron => &conf.tron_provider,
        Crypto::BSC => &conf.bsc_provider,
        Crypto::Polygon => &conf.plg_provider,
        Crypto::Stellar => &conf.stl_provider,
        Crypto::Btc => &conf.btc_provider,
    };
    let rate = match crypto {
        Crypto::Eth => rates.eth,
        Crypto::Tron => rates.trx,
        Crypto::BSC => rates.bnb,
        Crypto::Polygon => rates.mtc,
        Crypto::Stellar => rates.xlm,
        Crypto::Btc => rates.btc
    };

    let decimals = match crypto {
        Crypto::Eth => U256::exp10(16),
        Crypto::Tron => U256::exp10(4),
        Crypto::BSC => U256::exp10(16),
        Crypto::Polygon => U256::exp10(16),
        Crypto::Stellar => U256::exp10(16),
        Crypto::Btc => U256::exp10(8),
    };

    let mut balance_states = vec![];

    for i in c_from..c_to {
        let mut tokens_b: bool = false;
        let mut main_b: bool = false;
        let addr_i = hdw.address(i as i32)?;
        let (m_bal, m_bal_f, m_bal_usd) =
            check_main_balance(&hdw, i as i32, &provider, decimals, rate).await?;
        let tokens_bal = check_tokens_balance(&hdw, i as i32, &provider, &tokens).await?;
        let (tx_fee, txo_fee_prep) = check_fee(&hdw, &provider, decimals).await?;
        let mut tokens_bals = vec![];
        for t in tokens_bal {
            if t.balance > U256::zero() {
                tokens_b = true;
                tokens_bals.push((t.address, t.balance));
            }
        }
        if m_bal > tx_fee {
            main_b = true;
        };
        let mut wal_state = WalletState {
            id: i,
            address: addr_i,
            state: BalanceState::Empty,
        };
        match (tokens_b, main_b) {
            (false, false) => {
                balance_states.push(wal_state);
            }
            (true, false) => {
                wal_state.state = BalanceState::Tokens {
                    tokens_balance: tokens_bals,
                };
                balance_states.push(wal_state);
            }
            (false, true) => {
                wal_state.state = BalanceState::Main { balance: m_bal };
                balance_states.push(wal_state);
            }
            (true, true) => {
                wal_state.state = BalanceState::TokensMain {
                    tokens_balance: tokens_bals,
                    balance: m_bal,
                };
                balance_states.push(wal_state)
            }
        }
    }
    Ok(balance_states)
}
pub async fn balance(
    conf: &Settings,
    i: u32,
    crypto: &Crypto,
) -> Result<WalletState, Error> {
    println!("Calcing balances...");
    let rates = rates().await?;
    let phrase = &conf.hd_phrase;
    let mk= &conf.stl_master_key;

    let hdw = match crypto {
        Crypto::Eth => HDWallet::Ethereum(HDSeed::new(&phrase)?),
        Crypto::Tron => HDWallet::Tron(HDSeed::new(&phrase)?),
        Crypto::BSC => HDWallet::Ethereum(HDSeed::new(&phrase)?),
        Crypto::Polygon => HDWallet::Ethereum(HDSeed::new(&phrase)?),
        Crypto::Stellar => HDWallet::Stellar(mk.to_owned()),
        Crypto::Btc=> HDWallet::Bitcoin(HDSeed::new(&phrase)?),
    };

    let empty = vec![];

    let tokens = match crypto {
        Crypto::Eth => &conf.eth_tokens,
        Crypto::Tron => &conf.tron_tokens,
        Crypto::BSC => &conf.bsc_tokens,
        Crypto::Polygon => &conf.plg_tokens,
        Crypto::Stellar => &conf.stl_tokens,
        Crypto::Btc=> &empty

    };
    let provider = match crypto {
        Crypto::Eth => &conf.eth_provider,
        Crypto::Tron => &conf.tron_provider,
        Crypto::BSC => &conf.bsc_provider,
        Crypto::Polygon => &conf.plg_provider,
        Crypto::Stellar => &conf.stl_provider,
        Crypto::Btc => &conf.btc_provider,
    };
    let rate = match crypto {
        Crypto::Eth => rates.eth,
        Crypto::Tron => rates.trx,
        Crypto::BSC => rates.bnb,
        Crypto::Polygon => rates.mtc,
        Crypto::Stellar => rates.xlm,
        Crypto::Btc => rates.btc,
    };

    let decimals = match crypto {
        Crypto::Eth => U256::exp10(16),
        Crypto::Tron => U256::exp10(4),
        Crypto::BSC => U256::exp10(16),
        Crypto::Polygon => U256::exp10(16),
        Crypto::Stellar => U256::exp10(16),
        Crypto::Btc => U256::exp10(8),
    };


    let mut tokens_b: bool = false;
    let mut main_b: bool = false;
    let addr_i = hdw.address(i as i32)?;
    let (m_bal, m_bal_f, m_bal_usd) =
        check_main_balance(&hdw, i as i32, &provider, decimals, rate).await?;
    let tokens_bal = check_tokens_balance(&hdw, i as i32, &provider, &tokens).await?;
    let (tx_fee, txo_fee_prep) = check_fee(&hdw, &provider, decimals).await?;
    let mut tokens_bals = vec![];
    for t in tokens_bal {
        if t.balance > U256::zero() {
            tokens_b = true;
            tokens_bals.push((t.address, t.balance));
        }
    }
    if m_bal > tx_fee {
        main_b = true;
    };
    let mut wal_state = WalletState {
        id: i,
        address: addr_i,
        state: BalanceState::Empty,
    };
    match (tokens_b, main_b) {
        (false, false) => {
            Ok(wal_state)
        }
        (true, false) => {
            wal_state.state = BalanceState::Tokens {
                tokens_balance: tokens_bals,
            };
            Ok(wal_state)
        }
        (false, true) => {
            wal_state.state = BalanceState::Main { balance: m_bal };
            Ok(wal_state)
        }
        (true, true) => {
            wal_state.state = BalanceState::TokensMain {
                tokens_balance: tokens_bals,
                balance: m_bal,
            };
            Ok(wal_state)
        }
    }
}

async fn check_fee(hdw: &HDWallet, provider: &str, decimals: U256) -> Result<(U256, f64), Error> {
    match hdw {
        HDWallet::Stellar(_) => Ok((U256::zero(), 0.0)),
        _ => {
            let g_price = gas_price(&provider).await?;
            let tx_fee: U256 = g_price * 21000 * 5;
            let tx_fee_prep = (tx_fee / decimals).as_u128() as f64 * 0.01;
            Ok((tx_fee, tx_fee_prep))
        }
    }
}

async fn check_fee_token(hdw: &HDWallet, provider: &str) -> Result<U256, Error> {
    match hdw {
        HDWallet::Stellar(_) => Ok(U256::zero()),
        _ => {
            let g_price = gas_price(&provider).await?;
            let tx_fee: U256 = g_price * 65000 * 2;
            Ok(tx_fee)
        }
    }
}

async fn check_main_balance(
    hdw: &HDWallet,
    id: i32,
    provider: &str,
    decimals: U256,
    rate: f64,
) -> Result<(U256, f64, f64), Error> {
    let addr_bal = hdw.balance(id, provider).await?;
    let addr_bal_f = addr_bal / decimals;
    let addr_bal_f_prep = addr_bal_f.as_u128() as f64 * 0.01;
    Ok((addr_bal, addr_bal_f_prep, addr_bal_f_prep / rate))
}

async fn check_tokens_balance(
    hdw: &HDWallet,
    id: i32,
    provider: &str,
    tokens: &Vec<String>,
) -> Result<Vec<TokenData>, Error> {
    let mut tokens_balances: Vec<TokenData> = vec![];
    for token in tokens {
        let t_data = hdw.balance_token(id, token, provider).await?;
        tokens_balances.push(t_data);
    }
    Ok(tokens_balances)
}

pub async fn rates() -> Result<Rates, Error> {
    println!("getting current rates...");
    let rs: RatesRaw = reqwest::get(
        "https://min-api.cryptocompare.com/data/price?fsym=USD&tsyms=ETH,TRX,MATIC,BNB,XLM,BTC",
    )
    .await?
    .json::<RatesRaw>()
    .await?;
    let rates: Rates = Rates {
        eth: 1. / rs.ETH,
        trx: 1. / rs.TRX,
        mtc: 1. / rs.MATIC,
        bnb: 1. / rs.BNB,
        xlm: 1. / rs.XLM,
        btc: 1. / rs.BTC,
    };
    println!(
        "Rates:\nETH:{:.4}$\nTRX:{:.4}$\nMTC:{:.4}$\nBNB:{:.4}$\nXLM:{:.4}$\nBTC:{:.4}$\n",
        rates.eth, rates.trx, rates.mtc, rates.bnb, rates.xlm, rates.btc
    );
    Ok(rates)
}


pub async fn sweep_main(
    conf: Settings,
    i: u32,
    crypto: Crypto,
    ) -> Result<(),Error> {
    let hdw = match crypto {
        Crypto::Eth => HDWallet::Ethereum(HDSeed::new(&conf.hd_phrase)?),
        Crypto::Tron => HDWallet::Tron(HDSeed::new(&conf.hd_phrase)?),
        Crypto::BSC => HDWallet::Ethereum(HDSeed::new(&conf.hd_phrase)?),
        Crypto::Polygon => HDWallet::Ethereum(HDSeed::new(&conf.hd_phrase)?),
        Crypto::Stellar => HDWallet::Stellar(conf.stl_master_key),
        Crypto::Btc => HDWallet::Bitcoin(HDSeed::new(&conf.hd_phrase)?),
    };
    let provider = match crypto {
        Crypto::Eth => conf.eth_provider,
        Crypto::Tron => conf.tron_provider,
        Crypto::BSC => conf.bsc_provider,
        Crypto::Polygon => conf.plg_provider,
        Crypto::Stellar => conf.stl_provider,
        Crypto::Btc => conf.btc_provider,
    };
    let to = match crypto {
        Crypto::Eth => conf.eth_safe,
        Crypto::Tron => conf.tron_safe,
        Crypto::BSC => conf.bsc_safe,
        Crypto::Polygon => conf.plg_safe,
        Crypto::Stellar => conf.stl_safe,
        Crypto::Btc => conf.btc_safe,
    };
    println!("Sweeping from {0} in {1}...", hdw.address(i as i32)?,crypto);
    let res = hdw.sweep(i as i32, &to, &provider).await?;
    println!("{res}");
    Ok(())
}

pub async fn sweep_tokens(
    conf: &Settings,
    i: u32,
    crypto: &Crypto,
    tokens: Vec<(String, U256)>,
    ) -> Result<(),Error> {
    let hdw = match crypto {
        Crypto::Eth => HDWallet::Ethereum(HDSeed::new(&conf.hd_phrase)?),
        Crypto::Tron => HDWallet::Tron(HDSeed::new(&conf.hd_phrase)?),
        Crypto::BSC => HDWallet::Ethereum(HDSeed::new(&conf.hd_phrase)?),
        Crypto::Polygon => HDWallet::Ethereum(HDSeed::new(&conf.hd_phrase)?),
        Crypto::Stellar => HDWallet::Stellar(conf.stl_master_key.to_owned()),
        Crypto::Btc => HDWallet::Bitcoin(HDSeed::new(&conf.hd_phrase)?),
    };
    let provider = match crypto {
        Crypto::Eth => &conf.eth_provider,
        Crypto::Tron => &conf.tron_provider,
        Crypto::BSC => &conf.bsc_provider,
        Crypto::Polygon => &conf.plg_provider,
        Crypto::Stellar => &conf.stl_provider,
        Crypto::Btc => &conf.btc_provider,
    };
    let to = match crypto {
        Crypto::Eth => &conf.eth_safe,
        Crypto::Tron => &conf.tron_safe,
        Crypto::BSC => &conf.bsc_safe,
        Crypto::Polygon => &conf.plg_safe,
        Crypto::Stellar => &conf.stl_safe,
        Crypto::Btc => &conf.btc_safe,
    };
    let addr = hdw.address(i as i32)?;
    println!("Sweeping from {0} in {1}...",&addr,crypto);
    let balance = hdw.balance(i as i32, &provider).await?;
    let fee = check_fee_token(&hdw, &provider).await? * tokens.len();
    if balance < fee{
        let val = fee - balance;
        println!("Balance: {0}, fee {1}, refilling for {2}",balance,fee,val);
        refill_address(&conf.sweeper, &addr, val, &provider).await?;
    };
    for (tok,_) in tokens{
        println!("token_addr: {:?}",&tok);
        println!("tok: {tok}");
        let hash = hdw.sweep_token(i as i32, &tok, &to, &provider).await?;
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


pub async fn refill_address(sweeper_prvk: &str, addr :&str, val: U256, provider: &str) -> Result<(),Error> {
    let hash = send_main(sweeper_prvk, addr, val, provider).await?;
    let mut info ={
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


pub fn tron_call(
    conf: &Settings,
    i: i32, 
    ) -> Result<String,Error>{
    let tx_raw = "0a026ffa22086e06b4977c94304540908fb8e4a6315a67080112630a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412320a1541279f93bc1feb8af89d3253c5471b823c26671a92121541c90c049a15d5ef5af136653ccd6f26758b821e9018a08d0670c3c5b4e4a631";
    let hdw = HDWallet::Tron(HDSeed::new(&conf.hd_phrase)?);
    let hdw_addr = hdw.address(i)?;
    let hdw_priv = hdw.private(i)?;
    let hdw_keypair = hdw.keypair(i)?;
    let tx_par = web3::types::TransactionParameters{
        nonce:Some(U256::from(10)),
        to:Some(H160::from_str("0x41c90c049a15d5ef5af136653ccd6f26758b821e90")?),
        value:U256::from(15000),
        ..Default::default()
    };
//    let accs = web3::api::Accounts::
//    let res = web3::api::Accounts::sign_transaction(tx_par, hdw_keypair.0);
    println!("hdw_addr: {:?}",hdw_addr);
    println!("hdw_priv: {:?}",hdw_priv);
    println!("hdw_keypair: {:?}",hdw_keypair);
    Ok("still not implemented".to_owned())

}

pub async fn privkey(
    conf: &Settings,
    i: u32,
    crypto: &Crypto,
) -> Result<(), Error> {
    let phrase = &conf.hd_phrase;
    let mk= &conf.stl_master_key;

    let hdw = match crypto {
        Crypto::Eth => HDWallet::Ethereum(HDSeed::new(&phrase)?),
        Crypto::Tron => HDWallet::Tron(HDSeed::new(&phrase)?),
        Crypto::BSC => HDWallet::Ethereum(HDSeed::new(&phrase)?),
        Crypto::Polygon => HDWallet::Ethereum(HDSeed::new(&phrase)?),
        Crypto::Stellar => HDWallet::Stellar(mk.to_owned()),
        Crypto::Btc => HDWallet::Bitcoin(HDSeed::new(&phrase)?),
    };

    let addr_i = hdw.address(i as i32)?;
    let priv_k = hdw.private(i as i32)?;
    println!("addr: {:?}",addr_i);
    println!("priv: {:?}",priv_k);
    Ok(())
}


