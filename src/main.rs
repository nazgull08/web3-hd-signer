use bip39::Mnemonic;
use web3::types::{U256, H160};
use web3_hd::wallet::{HDWallet, HDSeed};

#[derive(Debug, Clone)]
struct WalletAddress {
    pub address : String,
    pub balance : U256,
    pub balance_token : (String, U256),
}

#[tokio::main]
async fn main() {     
    let v = vec![1, 2, 3];     
    println!("Hello, world!"); 
    test_wallet().await
}

async fn test_wallet() {
//        let a = Mnemonic::new(bip39::MnemonicType::Words12, bip39::Language::English);
    let phrase = "super ordinary tip dirt claim rhythm example learn beauty thing region faint"; //a.into_phrase();
    println!("=======================");
    println!("phrase: {:?}",&phrase);
    println!("=======================");

    let hdw_eth = HDWallet::Ethereum(HDSeed::new(&phrase));
    let hdw_tron = HDWallet::Tron(HDSeed::new(&phrase));

    let usdt = "0x6BABFBA7200f683c267ce892C94e1e110Df390c7";

    let mut wal_addrs: Vec<WalletAddress> = vec![];

    for i in 0..5 {
        let eth_i = hdw_eth.address(i as i32);
        let tron_i = hdw_tron.address(i as i32);
        let eth_priv = hdw_eth.private(i as i32);
        let tron_priv = hdw_tron.private(i as i32);
        let eth_pub = hdw_eth.public(i as i32);
        let tron_pub = hdw_tron.public(i as i32);
        let eth_bal = hdw_eth.balance(i as i32).await;
//        let eth_sweep = hdw_eth.sweep(i as i32).await;
        let eth_bal_token = hdw_eth.balance_token(i as i32,usdt).await;
//        let eth_sweep_token = hdw_eth.sweep_token(i as i32,usdt).await;
        println!("=======================");
        println!("ETH");
        println!("addr: {:?}", eth_i);
        println!("priv: {:?}", eth_priv);
        println!("pub: {:?}", eth_pub);
        println!("bal: {:?}", eth_bal.1);
        println!("bal_token: {:?}", eth_bal_token.1);
        println!("TRON");
        println!("addr: {:?}", tron_i);
        println!("priv: {:?}", tron_priv);
        println!("pub: {:?}", tron_pub);
        println!("=======================");

        wal_addrs.push(WalletAddress { address: eth_i, balance: eth_bal.1, balance_token: (usdt.to_owned(), eth_bal_token.1) })
    }

    println!("--------------------");
    println!("Addrs: {:?}",wal_addrs);


}
