pub mod types;
pub mod wallet;

#[cfg(test)]
mod tests {
    use bip39::Mnemonic;

    use crate::wallet::HDSeed;
    use crate::wallet::HDWallet;

    #[test]
    fn test_wallet() {
        //        let a = Mnemonic::new(bip39::MnemonicType::Words12, bip39::Language::English);
        let phrase = "super ordinary tip dirt claim rhythm example learn beauty thing region faint"; //a.into_phrase();
        println!("=======================");
        println!("phrase: {:?}", &phrase);
        println!("=======================");

        let hdw_eth = HDWallet::Ethereum(HDSeed::new(&phrase));
        let hdw_tron = HDWallet::Tron(HDSeed::new(&phrase));

        for i in 0..2 {
            let eth_i = hdw_eth.address(i as i32);
            let tron_i = hdw_tron.address(i as i32);
            let eth_priv = hdw_eth.private(i as i32);
            let tron_priv = hdw_tron.private(i as i32);
            let eth_pub = hdw_eth.public(i as i32);
            let tron_pub = hdw_tron.public(i as i32);
            println!("=======================");
            println!("ETH");
            println!("addr: {:?}", eth_i);
            println!("priv: {:?}", eth_priv);
            println!("pub: {:?}", eth_pub);
            println!("TRON");
            println!("addr: {:?}", tron_i);
            println!("priv: {:?}", tron_priv);
            println!("pub: {:?}", tron_pub);
            println!("=======================");
        }
    }
}
