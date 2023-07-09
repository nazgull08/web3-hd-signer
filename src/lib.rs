pub mod wallet;

#[cfg(test)]
mod tests {
    use crate::wallet::HDSeed;
    use crate::wallet::HDWallet;

    #[test]
    fn test_wallet() {
        let eth_addrs = vec![
            "0xa03eF5A8A00b938886b5e54b228759Ce8cBb6bF5",
            "0x94A902854842c4A5931AB49E558690b1dfd16394",
            "0x7c132f9840602B086b51aEAa6367518b210C69D7",
        ];
        let tron_addrs = vec![
            "TDLSuRq683BHiBuV9oSBFTxxJs1U1YuT1n",
            "THh8xUn3R8B51U6UD8YAp9mhUkcRM8fJEL",
            "TDe2FTTE6B16LzDUKLoWQvvF4iEEdYHCnM",
        ];

        let tron_privs = vec![
            "a",
            "b",
            "c",
        ];

        let eth_privs = vec![
            "a",
            "b",
            "c",
        ];

        let phrase = "";
        let hdw_eth = HDWallet::Ethereum(HDSeed::new(phrase));
        let hdw_tron = HDWallet::Tron(HDSeed::new(phrase));
        for i in 545..546 {
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
