use crate::{error::Error, types::*};

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
