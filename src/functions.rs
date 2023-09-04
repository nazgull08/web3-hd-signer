use web3::types::U256;

use crate::{
    types::*,
    wallet::{gas_price, HDSeed, HDWallet},
};

pub async fn balance(
    conf: Settings,
    c_from: u32,
    c_to: u32,
    crypto: Crypto,
) -> Result<Vec<WalletState>, Error> {
    println!("Calcing balances...");
    let rates = rates().await?;
    let phrase = conf.hd_phrase;

    let hdw = match crypto {
        Crypto::Eth => HDWallet::Ethereum(HDSeed::new(&phrase)?),
        Crypto::Tron => HDWallet::Tron(HDSeed::new(&phrase)?),
        Crypto::BSC => HDWallet::Ethereum(HDSeed::new(&phrase)?),
        Crypto::Polygon => HDWallet::Ethereum(HDSeed::new(&phrase)?),
        Crypto::Stellar => HDWallet::Stellar(conf.stl_master_key),
    };

    let tokens = match crypto {
        Crypto::Eth => conf.eth_tokens,
        Crypto::Tron => conf.tron_tokens,
        Crypto::BSC => conf.bsc_tokens,
        Crypto::Polygon => conf.plg_tokens,
        Crypto::Stellar => conf.stl_tokens,
    };
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
        Crypto::Stellar => U256::exp10(16),
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
        "https://min-api.cryptocompare.com/data/price?fsym=USD&tsyms=ETH,TRX,MATIC,BNB,XLM",
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
    };
    println!(
        "Rates:\nETH:{:.4}$\nTRX:{:.4}$\nMTC:{:.4}$\nBNB:{:.4}$\nXLM:{:.4}$\n",
        rates.eth, rates.trx, rates.mtc, rates.bnb, rates.xlm
    );
    Ok(rates)
}
