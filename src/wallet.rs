use std::str::FromStr;

use ::sha256::digest;
use bip39::Language;
use bip39::{Mnemonic, Seed};
use bitcoin::base58;
use bitcoin::bip32::ExtendedPubKey;
use bitcoin::{
    bip32::{DerivationPath, ExtendedPrivKey},
    network::constants::Network,
    PublicKey,
};
use secp256k1::Secp256k1;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use web3::Web3;
use web3::contract::{Contract, Options};
use web3::types::{H160, Address, TransactionParameters, CallRequest, U256, TransactionReceipt, H256, Transaction};

use crate::types::*;

#[derive(Debug, Clone)]
pub enum HDWallet {
    Ethereum(HDSeed),
    Tron(HDSeed),
    Stellar(HDSeed),
}
/* NTD proper errors
#[derive(Debug, Clone)]
pub enum Error {
    #[error("Web3 error: {0}")]
    Web3(#[from] web3::Error),
    #[error("Hex error: {0}")]
    Hex(#[from] rustc_hex::FromHexError),
}*/


#[derive(Debug, Clone) ]
pub struct HDSeed {
    pub mnemonic: Mnemonic,
}

impl HDSeed {
    pub fn new(phrase: &str) -> Self {
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        HDSeed { mnemonic }
    }
}

//NTD add funcion for save key to file
impl HDWallet {
    pub fn address(&self, index: i32) -> String {
        match self {
            HDWallet::Ethereum(seed) => eth_address_by_index(seed, index),
            HDWallet::Tron(seed) => tron_address_by_index(seed, index),
            HDWallet::Stellar(seed) => tron_address_by_index(seed, index),
        }
    }

    pub fn private(&self, index: i32) -> String {
        match self {
            HDWallet::Ethereum(seed) => eth_private_by_index(seed, index),
            HDWallet::Tron(seed) => tron_private_by_index(seed, index),
            HDWallet::Stellar(seed) => tron_private_by_index(seed, index),
        }
    }

    pub fn public(&self, index: i32) -> String {
        match self {
            HDWallet::Ethereum(seed) => eth_public_by_index(seed, index),
            HDWallet::Tron(seed) => tron_public_by_index(seed, index),
            HDWallet::Stellar(seed) => tron_public_by_index(seed, index),
        }
    }

    pub fn sign(&self, index: i32) -> String {
        match self {
            HDWallet::Ethereum(seed) => eth_sign(seed, index),
            HDWallet::Tron(seed) => tron_sign(seed, index),
            HDWallet::Stellar(seed) => stellar_sign(seed, index),
        }
    }

    pub async fn balance(&self, index: i32, provider: &str) -> (String, web3::types::U256) {
        match self {
            HDWallet::Ethereum(seed) => eth_balance(seed, index, provider).await.unwrap(),
            HDWallet::Tron(seed) => tron_balance(seed, index, provider).await.unwrap(),
            HDWallet::Stellar(seed) => eth_balance(seed, index, provider).await.unwrap(),
        }
    }

    pub async fn balance_token(&self, index: i32, addr: &str, provider: &str) -> (String, web3::types::U256) {
        match self {
            HDWallet::Ethereum(seed) => eth_balance_token(seed, index, addr, provider,Crypto::Eth).await.unwrap(),
            HDWallet::Tron(seed) => eth_balance_token(seed, index, addr, provider,Crypto::Tron).await.unwrap(), //NTD total rework 
            HDWallet::Stellar(seed) => eth_balance_token(seed, index, addr, provider,Crypto::Stellar).await.unwrap(),
        }
    }

    pub async fn sweep(&self, index: i32, to: &str, provider: &str) -> (String) {
        match self {
            HDWallet::Ethereum(seed) => eth_sweep_main(seed, index,to, provider).await.unwrap(),
            HDWallet::Tron(seed) => eth_sweep_main(seed, index,to, provider).await.unwrap(), //NTD total rework 
            HDWallet::Stellar(seed) => eth_sweep_main(seed, index,to, provider).await.unwrap(),
        }
    }

    pub async fn sweep_token(&self, index: i32, addr: &str,to: &str, provider: &str) -> (String) {
        match self {
            HDWallet::Ethereum(seed) => eth_sweep_token(seed, index, addr,to, provider, Crypto::Eth).await.unwrap(),
            HDWallet::Tron(seed) => eth_sweep_token(seed, index, addr,to, provider, Crypto::Tron).await.unwrap(), 
            HDWallet::Stellar(seed) => eth_sweep_token(seed, index, addr,to, provider, Crypto::Stellar).await.unwrap(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct EthAddr(String);

impl EthAddr {
    pub fn new(addr: &str) -> Self {
        let mut proper_addr = addr.to_owned();
        //check for 0x prefix
        if !addr.starts_with("0x") {
            proper_addr = format!("0x{}", addr);
        }
        //check that passed str is a hex string
        hex::decode(&proper_addr[2..])
            .map_err(|e| {
                println!("String passed into EthAddr is not hex.");
                e
            })
            .unwrap();
        //check length
        if proper_addr.len() != 42 {
            panic!(
                "String passed into EthAddr is {} hex chars long instead of 42.",
                proper_addr.len()
            );
        }
        //checksum and return
        let checksummed_addr = eth_checksum::checksum(&proper_addr);
        Self(checksummed_addr)
    }
    pub fn get(&self) -> &str {
        &self.0
    }
}

fn eth_address_by_index(seed: &HDSeed, index: i32) -> String {
    let hd_path_str = format!("m/44'/60'/0'/0/{index}");
    let seed_m = Seed::new(&seed.mnemonic, "");
    let (_pk, pubk) = get_extended_keypair(
        seed_m.as_bytes(),
        &DerivationPath::from_str(&hd_path_str).unwrap(),
    );
    let eth_addr = extended_pubk_to_addr(&pubk);

    eth_addr.get().to_owned()
}

fn tron_address_by_index(seed: &HDSeed, index: i32) -> String {
    let hd_path_str = format!("m/44'/195'/0'/0/{index}");
    let seed_m = Seed::new(&seed.mnemonic, "");
    let (_pk, pubk) = get_extended_keypair(
        seed_m.as_bytes(),
        &DerivationPath::from_str(&hd_path_str).unwrap(),
    );
    extended_pubk_to_addr_tron(&pubk)
}

fn tron_address_by_index_hex(seed: &HDSeed, index: i32) -> String {
    let hd_path_str = format!("m/44'/195'/0'/0/{index}");
    let seed_m = Seed::new(&seed.mnemonic, "");
    let (_pk, pubk) = get_extended_keypair(
        seed_m.as_bytes(),
        &DerivationPath::from_str(&hd_path_str).unwrap(),
    );
    extended_pubk_to_addr_tron_hex(&pubk)
}

fn stellar_address_by_index(seed: &HDSeed, index: i32) -> String {
    let hd_path_str = format!("m/44'/148'/0'/0/{index}");
    let seed_m = Seed::new(&seed.mnemonic, "");
    let (_pk, pubk) = get_extended_keypair(
        seed_m.as_bytes(),
        &DerivationPath::from_str(&hd_path_str).unwrap(),
    );
    extended_pubk_to_addr_stellar(&pubk)
}

fn eth_private_by_index(seed: &HDSeed, index: i32) -> String {
    let hd_path_str = format!("m/44'/60'/0'/0/{index}");
    let seed_m = Seed::new(&seed.mnemonic, "");
    let (pk, _) = get_extended_keypair(
        seed_m.as_bytes(),
        &DerivationPath::from_str(&hd_path_str).unwrap(),
    );
    pk.private_key.display_secret().to_string()
}

fn tron_private_by_index(seed: &HDSeed, index: i32) -> String {
    let hd_path_str = format!("m/44'/195'/0'/0/{index}");
    let seed_m = Seed::new(&seed.mnemonic, "");
    let (pk, _) = get_extended_keypair(
        seed_m.as_bytes(),
        &DerivationPath::from_str(&hd_path_str).unwrap(),
    );
    pk.private_key.display_secret().to_string()
}

fn eth_public_by_index(seed: &HDSeed, index: i32) -> String {
    let hd_path_str = format!("m/44'/60'/0'/0/{index}");
    let seed_m = Seed::new(&seed.mnemonic, "");
    let (_, pubk) = get_extended_keypair(
        seed_m.as_bytes(),
        &DerivationPath::from_str(&hd_path_str).unwrap(),
    );
    pubk.public_key.to_string()
}

fn tron_public_by_index(seed: &HDSeed, index: i32) -> String {
    let hd_path_str = format!("m/44'/195'/0'/0/{index}");
    let seed_m = Seed::new(&seed.mnemonic, "");
    let (_, pubk) = get_extended_keypair(
        seed_m.as_bytes(),
        &DerivationPath::from_str(&hd_path_str).unwrap(),
    );
    pubk.public_key.to_string()
}

fn get_extended_keypair(
    seed: &[u8],
    hd_path: &DerivationPath,
) -> (ExtendedPrivKey, ExtendedPubKey) {
    let secp = Secp256k1::new();
    let pk = ExtendedPrivKey::new_master(Network::Bitcoin, seed)
        // we convert HD Path to bitcoin lib format (DerivationPath)
        .and_then(|k| k.derive_priv(&secp, hd_path))
        .unwrap();
    let pubk = ExtendedPubKey::from_priv(&secp, &pk);
    (pk, pubk)
}

fn extended_pubk_to_addr(pubk: &ExtendedPubKey) -> EthAddr {
    //massage into the right format
    let pubk_str = pubk.public_key.to_string();
    let pubk_secp = secp256k1::PublicKey::from_str(&pubk_str).unwrap();
    //format as uncompressed key, remove "04" in the beginning
    let pubk_uncomp = &PublicKey::new_uncompressed(pubk_secp).to_string()[2..];
    //decode from hex and pass to keccak for hashing
    let pubk_bytes = hex::decode(pubk_uncomp).unwrap();
    let addr = &keccak_hash(&pubk_bytes);
    //keep last 20 bytes of the result
    let addr = &addr[(addr.len() - 40)..];
    //massage into domain unit
    EthAddr::new(addr)
}

pub fn partial_address_to_addr_tron(partial_address: &str) -> String {
    let hex_exp_addr = hex::decode(partial_address).unwrap();
    let s_hex_exp_addr = hex_exp_addr.as_slice();
    let val0 = digest(s_hex_exp_addr);
    let hex_val0 = hex::decode(val0).unwrap();
    let s_hex_val0 = hex_val0.as_slice();
    let val1 = digest(s_hex_val0);
    let check_sum_val1 = &val1[0..8];
    let final_addr = partial_address.to_owned() + check_sum_val1;
    let final_addr_bytes = hex::decode(final_addr).unwrap();

    base58::encode(&final_addr_bytes)

}

fn extended_pubk_to_addr_tron(pubk: &ExtendedPubKey) -> String {
    //massage into the right format
    let pubk_str = pubk.public_key.to_string();
    let pubk_secp = secp256k1::PublicKey::from_str(&pubk_str).unwrap();
    //format as uncompressed key, remove "04" in the beginning
    let pubk_uncomp = &PublicKey::new_uncompressed(pubk_secp).to_string()[2..];
    //decode from hex and pass to keccak for hashing
    let pubk_bytes = hex::decode(pubk_uncomp).unwrap();
    let k_addr = &keccak_hash(&pubk_bytes);
    //keep last 20 bytes of the result
    let experimental_addr = "41".to_owned() + &k_addr[24..];
    let hex_exp_addr = hex::decode(&experimental_addr).unwrap();
    let s_hex_exp_addr = hex_exp_addr.as_slice();
    let val0 = digest(s_hex_exp_addr);
    let hex_val0 = hex::decode(val0).unwrap();
    let s_hex_val0 = hex_val0.as_slice();
    let val1 = digest(s_hex_val0);
    let check_sum_val1 = &val1[0..8];
    let final_addr = experimental_addr + check_sum_val1;
    let final_addr_bytes = hex::decode(final_addr).unwrap();

    base58::encode(&final_addr_bytes)
}

fn extended_pubk_to_addr_tron_hex(pubk: &ExtendedPubKey) -> String {
    //massage into the right format
    let pubk_str = pubk.public_key.to_string();
    let pubk_secp = secp256k1::PublicKey::from_str(&pubk_str).unwrap();
    //format as uncompressed key, remove "04" in the beginning
    let pubk_uncomp = &PublicKey::new_uncompressed(pubk_secp).to_string()[2..];
    //decode from hex and pass to keccak for hashing
    let pubk_bytes = hex::decode(pubk_uncomp).unwrap();
    let k_addr = &keccak_hash(&pubk_bytes);
    //keep last 20 bytes of the result
    let experimental_addr = "41".to_owned() + &k_addr[24..];
    let hex_exp_addr = hex::decode(&experimental_addr).unwrap();
    let s_hex_exp_addr = hex_exp_addr.as_slice();
    let val0 = digest(s_hex_exp_addr);
    let hex_val0 = hex::decode(&val0).unwrap();
    let s_hex_val0 = hex_val0.as_slice();
    let val1 = digest(s_hex_val0);
    let check_sum_val1 = &val1[0..8];
    let final_addr = (&experimental_addr).to_owned() + check_sum_val1;
    let hex_addr = "0x".to_owned() + &k_addr[24..];
    println!("=========");
    println!("k_addr: {:?}",k_addr);
    println!("experimental_addr: {:?}",&experimental_addr);
    println!("val0: {:?}",&val0);
    println!("final: {:?}",&final_addr);
    println!("hex_addr: {:?}",&hex_addr);
    println!("=========");
    hex_addr
}

fn extended_pubk_to_addr_stellar(pubk: &ExtendedPubKey) -> String {
    //massage into the right format
    let pubk_str = pubk.public_key.to_string();
    let pubk_secp = secp256k1::PublicKey::from_str(&pubk_str).unwrap();
    //format as uncompressed key, remove "04" in the beginning
    let pubk_uncomp = &PublicKey::new_uncompressed(pubk_secp).to_string()[2..];
    //decode from hex and pass to keccak for hashing
    let pubk_bytes = hex::decode(pubk_uncomp).unwrap();
    let k_addr = &keccak_hash(&pubk_bytes);
    //keep last 20 bytes of the result
    let experimental_addr = "41".to_owned() + &k_addr[24..];
    let hex_exp_addr = hex::decode(&experimental_addr).unwrap();
    let s_hex_exp_addr = hex_exp_addr.as_slice();
    let val0 = digest(s_hex_exp_addr);
    let hex_val0 = hex::decode(val0).unwrap();
    let s_hex_val0 = hex_val0.as_slice();
    let val1 = digest(s_hex_val0);
    let check_sum_val1 = &val1[0..8];
    let final_addr = experimental_addr + check_sum_val1;
    let final_addr_bytes = hex::decode(final_addr).unwrap();

    base58::encode(&final_addr_bytes)
}

fn keccak_hash<T>(data: &T) -> String
where
    T: ?Sized + Serialize + AsRef<[u8]>,
{
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex::encode(result)
}


fn get_private(
    seed: &[u8],
    hd_path: &DerivationPath,
) -> (ExtendedPrivKey, ExtendedPubKey) {
    let secp = Secp256k1::new();
    let pk = ExtendedPrivKey::new_master(Network::Bitcoin, seed)
        // we convert HD Path to bitcoin lib format (DerivationPath)
        .and_then(|k| k.derive_priv(&secp, hd_path))
        .unwrap();
    let pubk = ExtendedPubKey::from_priv(&secp, &pk);
    (pk, pubk)
}



fn eth_sign(seed: &HDSeed, index: i32) -> String {
    let hd_path_str = format!("m/44'/60'/0'/0/{index}");
   // let transport = web3::transports::Http::new("https://rinkeby.infura.io/v3/XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")?;
    //let web3 = web3::Web3::new(transport);
   // let to = Address::from_str("0xXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX").unwrap();
    let seed_m = Seed::new(&seed.mnemonic, "");
    let (_privkey, pubk) = get_extended_keypair(
        seed_m.as_bytes(),
        &DerivationPath::from_str(&hd_path_str).unwrap(),
    );
    pubk.public_key.to_string()
}

fn tron_sign(seed: &HDSeed, index: i32) -> String {
    "lalala".to_owned()
}

fn stellar_sign(seed: &HDSeed, index: i32) -> String {
    "lalala".to_owned()
}

async fn eth_balance(seed: &HDSeed, index: i32, provider: &str) -> Result<(String,web3::types::U256),web3::Error> {
    let transport = web3::transports::Http::new(provider)?;
    let web3 = web3::Web3::new(transport);
    let addr_str = eth_address_by_index(seed, index);
    let addr = H160::from_str(&addr_str).unwrap();
    let bal = web3.eth().balance(addr, None).await.unwrap();
    Ok((addr_str, bal))
}

async fn tron_balance(seed: &HDSeed, index: i32, provider: &str) -> Result<(String,web3::types::U256),web3::Error> {
    let transport = web3::transports::Http::new(provider)?;
    let web3 = web3::Web3::new(transport);
    let addr_str = tron_address_by_index_hex(seed, index);
    let addr = H160::from_str(&addr_str).unwrap();
    let bal = web3.eth().balance(addr, None).await.unwrap();
    Ok((addr_str, bal))
}

async fn eth_sweep_main(seed: &HDSeed, index: i32,to_str : &str, provider: &str) -> Result<String,web3::Error> {
    let transport = web3::transports::Http::new(provider)?;
    let web3 = web3::Web3::new(transport);
    let addr_str = eth_address_by_index(seed, index);
    let prvk_str = eth_private_by_index(seed, index);
    let prvk = web3::signing::SecretKey::from_str(&prvk_str).unwrap();
    let addr = H160::from_str(&addr_str).unwrap();
    let to = Address::from_str(&to_str).unwrap();
    let gas_price = web3.eth().gas_price().await.unwrap();
    let bal = web3.eth().balance(addr, None).await.unwrap();
    let fee = gas_price*21000*5;
    let val_to_send = bal - &fee;
    let tx_call_req = CallRequest {
        to: Some(to),
        value: Some(bal),
        ..Default::default()
    };
    let est_gas = web3.eth().estimate_gas(tx_call_req, None).await.unwrap();
    println!("================");
    println!("gas_price: {:?}",&gas_price);
    println!("bal: {:?}",&bal);
    println!("fee: {:?}",&fee);
    println!("val_to_send: {:?}",&val_to_send);
    println!("est_gas: {:?}",&est_gas);
    let tx_object = TransactionParameters {
        to: Some(to),
        value: val_to_send,
        ..Default::default()
    };
    let signed = web3.accounts().sign_transaction(tx_object, &prvk).await?;
    let result = web3.eth().send_raw_transaction(signed.raw_transaction).await?;
    println!("Tx succeeded with hash: {}", result);
    Ok("lalala".to_owned())
}

async fn eth_balance_token(seed: &HDSeed, index: i32, token_addr: &str, provider: &str,crypto: Crypto) -> Result<(String,web3::types::U256),web3::Error> {
    let transport = web3::transports::Http::new(provider)?;
    let web3 = web3::Web3::new(transport);
    let addr_str = eth_address_by_index(seed, index);
    let addr = H160::from_str(&addr_str).unwrap();
    let token_address = H160::from_str(&token_addr).unwrap();
    let bal = web3.eth().balance(addr, None).await.unwrap();
    let contract = match crypto {
        Crypto::Tron => {Contract::from_json(web3.eth(), token_address, include_bytes!("../res/trc20.abi.json")).unwrap()},
        _ => {Contract::from_json(web3.eth(), token_address, include_bytes!("../res/erc20.abi.json")).unwrap()}, 
    }; 
    //let result = contract.query("balanceOf", (addr,), None, Options::default(), None);     
    //let balance_of: U256 = result.await.unwrap(); 
    let balance_of = U256::zero();
    Ok((addr_str, balance_of))
}


async fn eth_sweep_token(seed: &HDSeed, index: i32, token_addr: &str, to_str : &str, provider: &str, crypto: Crypto) -> Result<String,web3::Error> {
    let transport = web3::transports::Http::new(provider)?;
    let web3 = web3::Web3::new(transport);
    let addr_str = eth_address_by_index(seed, index);
    let prvk_str = eth_private_by_index(seed, index);
    let prvk = web3::signing::SecretKey::from_str(&prvk_str).unwrap();
    let addr = H160::from_str(&addr_str).unwrap();
    let to = Address::from_str(to_str).unwrap();

    let token_address = H160::from_str(&token_addr).unwrap();
    let contract = Contract::from_json(web3.eth(), token_address, include_bytes!("../res/erc20.abi.json")).unwrap();
    let result = contract.query("balanceOf", (addr,), None, Options::default(), None);     
    let balance_of: U256 = result.await.unwrap(); 
    println!("balance_of: {:?}",&balance_of);
    //let result : String = contract.query("transfer", (to, balance_of), None, Options::default(), None).await.unwrap();
    let gas_est = contract.estimate_gas("transfer", (to, balance_of), addr, Options::default()).await.unwrap();

    let gas_price = web3.eth().gas_price().await.unwrap();
    let fee = gas_est * gas_price;
    println!("================");
    println!("gas_price: {:?}",&gas_price);
    println!("gas_est: {:?}",&gas_est);
    println!("fee: {:?}", &fee);
    let token_call= contract.signed_call("transfer", (to, balance_of), Options::default(), &prvk).await.unwrap();
    println!("token_receipt: {:?}",token_call);
    //let signed = web3.accounts().sign_transaction(tx_object, &prvk).await?;
    //let result = web3.eth().send_raw_transaction(signed.raw_transaction).await?;
    //println!("Tx succeeded with hash: {}", result);
    Ok("lalala".to_owned())
}

fn trn_balance(seed: &HDSeed, index: i32) -> (String,web3::types::U256) {
    ("".to_owned(),web3::types::U256::zero())
}

fn stellar_balance(seed: &HDSeed, index: i32) -> (String,web3::types::U256) {
    ("".to_owned(),web3::types::U256::zero())
}

pub async fn gas_price(provider: &str) -> Result<U256,web3::Error> {
    let transport = web3::transports::Http::new(provider)?;
    let web3 = web3::Web3::new(transport);
    let gas_price = web3.eth().gas_price().await.unwrap();
    Ok(gas_price)
}

pub async fn tx_receipt(hash: H256, provider: &str) -> Result<TransactionReceipt, web3::Error> {
    let transport = web3::transports::Http::new(provider)?;
    let web3 = web3::Web3::new(transport);
    let receipt= web3.eth().transaction_receipt(hash).await.unwrap().unwrap();
    Ok(receipt)
}

pub async fn tx_info(hash: H256, provider: &str) -> Result<Transaction, web3::Error> {
    let transport = web3::transports::Http::new(provider)?;
    let web3 = web3::Web3::new(transport);
    let tx= web3.eth().transaction(web3::types::TransactionId::Hash(hash)).await.unwrap().unwrap();
    Ok(tx)
}

pub async fn send_main(prvk_str: &str, to_str: &str, val: U256, provider: &str) -> Result<H256,web3::Error> {
    let transport = web3::transports::Http::new(provider)?;
    let web3 = web3::Web3::new(transport);
    let prvk = web3::signing::SecretKey::from_str(&prvk_str).unwrap();
    let to = Address::from_str(&to_str).unwrap();
    let tx_object = TransactionParameters {
        to: Some(to),
        value: val,
        ..Default::default()
    };
    let signed = web3.accounts().sign_transaction(tx_object, &prvk).await?;
    let result = web3.eth().send_raw_transaction(signed.raw_transaction).await?;
    println!("Tx succeeded with hash: {}", result);
    Ok(result)
}
