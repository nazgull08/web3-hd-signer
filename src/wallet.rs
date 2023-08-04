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
use web3::types::H160;

use log::*;

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

    pub async fn balance(&self, index: i32) -> (String, web3::types::U256) {
        match self {
            HDWallet::Ethereum(seed) => eth_balance(seed, index).await.unwrap(),
            HDWallet::Tron(seed) => eth_balance(seed, index).await.unwrap(), //NTD total rework 
            HDWallet::Stellar(seed) => eth_balance(seed, index).await.unwrap(),
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

    info!("!!!!!!!!!!!!!!!");
    info!("{:?}",eth_addr);
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

async fn eth_balance(seed: &HDSeed, index: i32) -> Result<(String,web3::types::U256),web3::Error> {
    let transport = web3::transports::Http::new("https://rinkeby.infura.io/v3/62993b0fe3b2443794aae04c323b478d")?;
    let web3 = web3::Web3::new(transport);
    let addr_str = eth_address_by_index(seed, index);
    info!("=================");
    info!("lalalal");
    info!("{:?}", addr_str);
    info!("=================");
    let addr = H160::from_str(&addr_str).unwrap();
    let bal = web3.eth().balance(addr, None).await.unwrap();
    Ok((addr_str, bal))
}

fn trn_balance(seed: &HDSeed, index: i32) -> (String,web3::types::U256) {
    ("".to_owned(),web3::types::U256::zero())
}

fn stellar_balance(seed: &HDSeed, index: i32) -> (String,web3::types::U256) {
    ("".to_owned(),web3::types::U256::zero())
}
