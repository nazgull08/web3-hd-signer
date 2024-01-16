use web3::types::U256;

use crate::{
    error::Error,
    wallet::{gas_price, HDWallet},
};

pub async fn check_fee(
    hdw: &HDWallet,
    provider: &str,
    decimals: U256,
) -> Result<(U256, f64), Error> {
    match hdw {
        HDWallet::Stellar(_) => Ok((U256::zero(), 0.0)),
        _ => {
            let g_price = gas_price(provider).await?;
            let tx_fee: U256 = g_price * 31000;
            let tx_fee_prep = (tx_fee / decimals).as_u128() as f64 * 0.01;
            Ok((tx_fee, tx_fee_prep))
        }
    }
}

pub async fn check_fee_token(hdw: &HDWallet, provider: &str) -> Result<U256, Error> {
    match hdw {
        HDWallet::Stellar(_) => Ok(U256::zero()),
        _ => {
            let g_price = gas_price(provider).await?;
            let tx_fee: U256 = g_price * 85000;
            Ok(tx_fee)
        }
    }
}
