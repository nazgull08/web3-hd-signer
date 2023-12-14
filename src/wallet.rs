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
use hex::ToHex;
use secp256k1::Secp256k1;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sha3::{Digest, Keccak256};
use std::sync::Arc;
use web3::contract::{Contract, Options};
use web3::types::{
    Address, CallRequest, Transaction, TransactionParameters, TransactionReceipt, H160, H256, U256,
};

use bdk::database::MemoryDatabase;
use bdk::electrum_client::{Client, ElectrumApi};
use bdk::{SignOptions, Wallet};

use crate::types::*;

use stellar_sdk::{utils::Endpoint, CallBuilder, Keypair, Server};

#[derive(Debug, Clone)]
pub enum HDWallet {
    Ethereum(HDSeed),
    Tron(HDSeed),
    Stellar(String),
}

#[derive(Debug, Clone)]
pub struct HDSeed {
    pub mnemonic: Mnemonic,
}

impl HDSeed {
    pub fn new(phrase: &str) -> Result<Self, Error> {
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English)
            .map_err(|_| Error::MnemonicError(phrase.to_owned()))?;
        Ok(HDSeed { mnemonic })
    }
}

//NTD add funcion for save key to file
impl HDWallet {
    pub fn address(&self, index: i32) -> Result<String, Error> {
        match self {
            HDWallet::Ethereum(seed) => eth_address_by_index(seed, index),
            HDWallet::Tron(seed) => tron_address_by_index(seed, index),
            HDWallet::Stellar(master_key) => stellar_address_by_index(master_key, index),
        }
    }

    pub fn private(&self, index: i32) -> Result<String, Error> {
        match self {
            HDWallet::Ethereum(seed) => eth_private_by_index(seed, index),
            HDWallet::Tron(seed) => tron_private_by_index(seed, index),
            HDWallet::Stellar(master_key) => stellar_address_by_index(master_key, index),
        }
    }

    pub fn keypair(&self, index: i32) -> Result<(ExtendedPrivKey, ExtendedPubKey), Error> {
        match self {
            HDWallet::Ethereum(seed) => eth_keypair_by_index(seed, index),
            HDWallet::Tron(seed) => tron_keypair_by_index(seed, index),
            HDWallet::Stellar(_master_key) => tron_keypair_by_index(&HDSeed::new("")?, index), //NTD
        }
    }

    pub fn public(&self, index: i32) -> Result<String, Error> {
        match self {
            HDWallet::Ethereum(seed) => eth_public_by_index(seed, index),
            HDWallet::Tron(seed) => tron_public_by_index(seed, index),
            HDWallet::Stellar(master_key) => stellar_address_by_index(master_key, index),
        }
    }

    pub fn sign(&self, index: i32) -> Result<String, Error> {
        match self {
            HDWallet::Ethereum(seed) => eth_sign(seed, index),
            HDWallet::Tron(seed) => tron_sign(seed, index),
            HDWallet::Stellar(master_key) => stellar_sign(master_key, index),
        }
    }

    pub async fn balance(&self, index: i32, provider: &str) -> Result<U256, Error> {
        match self {
            HDWallet::Ethereum(seed) => eth_balance(seed, index, provider).await,
            HDWallet::Tron(seed) => tron_balance(seed, index, provider).await,
            HDWallet::Stellar(master_key) => stellar_balance(master_key, index, provider).await,
        }
    }

    pub async fn balance_token(
        &self,
        index: i32,
        addr: &str,
        provider: &str,
    ) -> Result<TokenData, Error> {
        match self {
            HDWallet::Ethereum(seed) => eth_balance_token(seed, index, addr, provider).await,
            HDWallet::Tron(seed) => tron_balance_token(seed, index, addr, provider).await,
            HDWallet::Stellar(master_key) => {
                stellar_balance_token(master_key, index, addr, provider).await
            }
        }
    }

    pub async fn sweep(&self, index: i32, to: &str, provider: &str) -> Result<String, Error> {
        match self {
            HDWallet::Ethereum(seed) => eth_sweep_main(seed, index, to, provider).await,
            HDWallet::Tron(seed) => tron_sweep_main(seed, index, to, provider).await,
            HDWallet::Stellar(_master_key) => Ok("unimplemented".to_owned()),
        }
    }

    pub async fn sweep_token(
        &self,
        index: i32,
        addr: &str,
        to: &str,
        provider: &str,
    ) -> Result<H256, Error> {
        match self {
            HDWallet::Ethereum(seed) => {
                eth_sweep_token(seed, index, addr, to, provider, Crypto::Eth).await
            }
            HDWallet::Tron(seed) => {
                tron_sweep_token(seed, index, addr, to, provider, Crypto::Tron).await
            }
            HDWallet::Stellar(_seed) => Ok(H256::zero()),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct EthAddr(String);

impl EthAddr {
    pub fn new(addr: &str) -> Result<Self, Error> {
        let mut proper_addr = addr.to_owned();
        //check for 0x prefix
        if !addr.starts_with("0x") {
            proper_addr = format!("0x{}", addr);
        }
        //check that passed str is a hex string
        hex::decode(&proper_addr[2..]).map_err(|e| {
            println!("String passed into EthAddr is not hex.");
            e
        })?;
        //check length
        if proper_addr.len() != 42 {
            return Err(Error::EthAddrLengthError(proper_addr.len()));
        }
        //checksum and return
        let checksummed_addr = eth_checksum::checksum(&proper_addr);
        Ok(Self(checksummed_addr))
    }
    pub fn get(&self) -> &str {
        &self.0
    }
}

fn eth_address_by_index(seed: &HDSeed, index: i32) -> Result<String, Error> {
    let hd_path_str = format!("m/44'/60'/0'/0/{index}");
    let seed_m = Seed::new(&seed.mnemonic, "");
    let (_pk, pubk) =
        get_extended_keypair(seed_m.as_bytes(), &DerivationPath::from_str(&hd_path_str)?)?;
    let eth_addr = extended_pubk_to_addr(&pubk)?;

    Ok(eth_addr.get().to_owned())
}

fn tron_address_by_index(seed: &HDSeed, index: i32) -> Result<String, Error> {
    let hd_path_str = format!("m/44'/195'/0'/0/{index}");
    let seed_m = Seed::new(&seed.mnemonic, "");
    let (_pk, pubk) =
        get_extended_keypair(seed_m.as_bytes(), &DerivationPath::from_str(&hd_path_str)?)?;
    extended_pubk_to_addr_tron(&pubk)
}

fn tron_address_by_index_hex(seed: &HDSeed, index: i32) -> Result<String, Error> {
    let hd_path_str = format!("m/44'/195'/0'/0/{index}");
    let seed_m = Seed::new(&seed.mnemonic, "");
    let (_pk, pubk) =
        get_extended_keypair(seed_m.as_bytes(), &DerivationPath::from_str(&hd_path_str)?)?;
    extended_pubk_to_addr_tron_hex(&pubk)
}
//Add proper version with HD seed for Stellar wallet. But later...
fn stellar_address_by_index(seed: &str, index: i32) -> Result<String, Error> {
    let seed_m = Keypair::from_secret_master_key(seed, &index.to_string())
        .map_err(|e| Error::StellarSDKError(Arc::new(e)))?;
    Ok(seed_m.public_key())
}

fn eth_private_by_index(seed: &HDSeed, index: i32) -> Result<String, Error> {
    let hd_path_str = format!("m/44'/60'/0'/0/{index}");
    let seed_m = Seed::new(&seed.mnemonic, "");
    let (pk, _) =
        get_extended_keypair(seed_m.as_bytes(), &DerivationPath::from_str(&hd_path_str)?)?;
    Ok(pk.private_key.display_secret().to_string())
}

fn tron_private_by_index(seed: &HDSeed, index: i32) -> Result<String, Error> {
    let hd_path_str = format!("m/44'/195'/0'/0/{index}");
    let seed_m = Seed::new(&seed.mnemonic, "");
    let (pk, _) =
        get_extended_keypair(seed_m.as_bytes(), &DerivationPath::from_str(&hd_path_str)?)?;
    Ok(pk.private_key.display_secret().to_string())
}

fn eth_keypair_by_index(
    seed: &HDSeed,
    index: i32,
) -> Result<(ExtendedPrivKey, ExtendedPubKey), Error> {
    let hd_path_str = format!("m/44'/60'/0'/0/{index}");
    let seed_m = Seed::new(&seed.mnemonic, "");
    let (pk, pubk) =
        get_extended_keypair(seed_m.as_bytes(), &DerivationPath::from_str(&hd_path_str)?)?;
    Ok((pk, pubk))
}

fn tron_keypair_by_index(
    seed: &HDSeed,
    index: i32,
) -> Result<(ExtendedPrivKey, ExtendedPubKey), Error> {
    let hd_path_str = format!("m/44'/195'/0'/0/{index}");
    let seed_m = Seed::new(&seed.mnemonic, "");
    let (pk, pubk) =
        get_extended_keypair(seed_m.as_bytes(), &DerivationPath::from_str(&hd_path_str)?)?;
    Ok((pk, pubk))
}

fn eth_public_by_index(seed: &HDSeed, index: i32) -> Result<String, Error> {
    let hd_path_str = format!("m/44'/60'/0'/0/{index}");
    let seed_m = Seed::new(&seed.mnemonic, "");
    let (_, pubk) =
        get_extended_keypair(seed_m.as_bytes(), &DerivationPath::from_str(&hd_path_str)?)?;
    Ok(pubk.public_key.to_string())
}

fn tron_public_by_index(seed: &HDSeed, index: i32) -> Result<String, Error> {
    let hd_path_str = format!("m/44'/195'/0'/0/{index}");
    let seed_m = Seed::new(&seed.mnemonic, "");
    let (_, pubk) =
        get_extended_keypair(seed_m.as_bytes(), &DerivationPath::from_str(&hd_path_str)?)?;
    Ok(pubk.public_key.to_string())
}

fn get_extended_keypair(
    seed: &[u8],
    hd_path: &DerivationPath,
) -> Result<(ExtendedPrivKey, ExtendedPubKey), Error> {
    let secp = Secp256k1::new();
    let pk = ExtendedPrivKey::new_master(Network::Bitcoin, seed)
        // we convert HD Path to bitcoin lib format (DerivationPath)
        .and_then(|k| k.derive_priv(&secp, hd_path))?;
    let pubk = ExtendedPubKey::from_priv(&secp, &pk);
    Ok((pk, pubk))
}

fn extended_pubk_to_addr(pubk: &ExtendedPubKey) -> Result<EthAddr, Error> {
    //massage into the right format
    let pubk_str = pubk.public_key.to_string();
    let pubk_secp = secp256k1::PublicKey::from_str(&pubk_str)?;
    //format as uncompressed key, remove "04" in the beginning
    let pubk_uncomp = &PublicKey::new_uncompressed(pubk_secp).to_string()[2..];
    //decode from hex and pass to keccak for hashing
    let pubk_bytes = hex::decode(pubk_uncomp)?;
    let addr = &keccak_hash(&pubk_bytes);
    //keep last 20 bytes of the result
    let addr = &addr[(addr.len() - 40)..];
    //massage into domain unit
    EthAddr::new(addr)
}

pub fn partial_address_to_addr_tron(partial_address: &str) -> Result<String, Error> {
    let hex_exp_addr = hex::decode(partial_address)?;
    let s_hex_exp_addr = hex_exp_addr.as_slice();
    let val0 = digest(s_hex_exp_addr);
    let hex_val0 = hex::decode(val0)?;
    let s_hex_val0 = hex_val0.as_slice();
    let val1 = digest(s_hex_val0);
    let check_sum_val1 = &val1[0..8];
    let final_addr = partial_address.to_owned() + check_sum_val1;
    let final_addr_bytes = hex::decode(final_addr)?;

    Ok(base58::encode(&final_addr_bytes))
}

fn extended_pubk_to_addr_tron(pubk: &ExtendedPubKey) -> Result<String, Error> {
    //massage into the right format
    let pubk_str = pubk.public_key.to_string();
    let pubk_secp = secp256k1::PublicKey::from_str(&pubk_str)?;
    //format as uncompressed key, remove "04" in the beginning
    let pubk_uncomp = &PublicKey::new_uncompressed(pubk_secp).to_string()[2..];
    //decode from hex and pass to keccak for hashing
    let pubk_bytes = hex::decode(pubk_uncomp)?;
    let k_addr = &keccak_hash(&pubk_bytes);
    //keep last 20 bytes of the result
    let experimental_addr = "41".to_owned() + &k_addr[24..];
    let hex_exp_addr = hex::decode(&experimental_addr)?;
    let s_hex_exp_addr = hex_exp_addr.as_slice();
    let val0 = digest(s_hex_exp_addr);
    let hex_val0 = hex::decode(val0)?;
    let s_hex_val0 = hex_val0.as_slice();
    let val1 = digest(s_hex_val0);
    let check_sum_val1 = &val1[0..8];
    let final_addr = experimental_addr + check_sum_val1;
    let final_addr_bytes = hex::decode(final_addr)?;

    Ok(base58::encode(&final_addr_bytes))
}

fn extended_pubk_to_addr_tron_hex(pubk: &ExtendedPubKey) -> Result<String, Error> {
    //massage into the right format
    let pubk_str = pubk.public_key.to_string();
    let pubk_secp = secp256k1::PublicKey::from_str(&pubk_str)?;
    //format as uncompressed key, remove "04" in the beginning
    let pubk_uncomp = &PublicKey::new_uncompressed(pubk_secp).to_string()[2..];
    //decode from hex and pass to keccak for hashing
    let pubk_bytes = hex::decode(pubk_uncomp)?;
    let k_addr = &keccak_hash(&pubk_bytes);
    //keep last 20 bytes of the result
    Ok("0x".to_owned() + &k_addr[24..])
}

#[allow(dead_code)]
fn extended_pubk_to_addr_stellar(pubk: &ExtendedPubKey) -> Result<String, Error> {
    //massage into the right format
    let pubk_str = pubk.public_key.to_string();
    let pubk_secp = secp256k1::PublicKey::from_str(&pubk_str)?;
    //format as uncompressed key, remove "04" in the beginning
    let pubk_uncomp = &PublicKey::new_uncompressed(pubk_secp).to_string()[2..];
    //decode from hex and pass to keccak for hashing
    let pubk_bytes = hex::decode(pubk_uncomp)?;
    let k_addr = &keccak_hash(&pubk_bytes);
    //keep last 20 bytes of the result
    let experimental_addr = "41".to_owned() + &k_addr[24..];
    let hex_exp_addr = hex::decode(&experimental_addr)?;
    let s_hex_exp_addr = hex_exp_addr.as_slice();
    let val0 = digest(s_hex_exp_addr);
    let hex_val0 = hex::decode(val0)?;
    let s_hex_val0 = hex_val0.as_slice();
    let val1 = digest(s_hex_val0);
    let check_sum_val1 = &val1[0..8];
    let final_addr = experimental_addr + check_sum_val1;
    let final_addr_bytes = hex::decode(final_addr)?;

    Ok(base58::encode(&final_addr_bytes))
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

#[allow(dead_code)]
fn get_private(
    seed: &[u8],
    hd_path: &DerivationPath,
) -> Result<(ExtendedPrivKey, ExtendedPubKey), Error> {
    let secp = Secp256k1::new();
    let pk = ExtendedPrivKey::new_master(Network::Bitcoin, seed)
        .and_then(|k| k.derive_priv(&secp, hd_path))?;
    let pubk = ExtendedPubKey::from_priv(&secp, &pk);
    Ok((pk, pubk))
}

fn eth_sign(seed: &HDSeed, index: i32) -> Result<String, Error> {
    let hd_path_str = format!("m/44'/60'/0'/0/{index}");
    // let transport = web3::transports::Http::new("https://rinkeby.infura.io/v3/XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")?;
    //let web3 = web3::Web3::new(transport);
    // let to = Address::from_str("0xXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX").unwrap();
    let seed_m = Seed::new(&seed.mnemonic, "");
    let (_privkey, pubk) =
        get_extended_keypair(seed_m.as_bytes(), &DerivationPath::from_str(&hd_path_str)?)?;
    Ok(pubk.public_key.to_string())
}

fn tron_sign(_seed: &HDSeed, _index: i32) -> Result<String, Error> {
    Ok("lalala".to_owned())
}

fn stellar_sign(_seed: &str, _index: i32) -> Result<String, Error> {
    Ok("lalala".to_owned())
}

async fn eth_balance(
    seed: &HDSeed,
    index: i32,
    provider: &str,
) -> Result<web3::types::U256, Error> {
    let transport = web3::transports::Http::new(provider)?;
    let web3 = web3::Web3::new(transport);
    let addr_str = eth_address_by_index(seed, index)?;
    let addr = H160::from_str(&addr_str)?;
    let bal = web3.eth().balance(addr, None).await?;
    Ok(bal)
}

async fn tron_balance(
    seed: &HDSeed,
    index: i32,
    provider: &str,
) -> Result<web3::types::U256, Error> {
    let transport = web3::transports::Http::new(provider)?;
    let web3 = web3::Web3::new(transport);
    let addr_str = tron_address_by_index_hex(seed, index)?;
    let addr = H160::from_str(&addr_str)?;
    let bal = web3.eth().balance(addr, None).await?;
    Ok(bal)
}

async fn stellar_balance(seed: &str, index: i32, provider: &str) -> Result<U256, Error> {
    let server = Server::new(provider.to_owned());
    let addr = stellar_address_by_index(seed, index)?;
    let account = server
        .load_account(&addr)
        .map_err(|e| Error::StellarSDKError(Arc::new(e)));
    let mut bal = 0.0;
    let balances = match account {
        Ok(acc) => acc.balances,
        Err(_) => {
            vec![]
        }
    };
    for b in balances {
        if b.asset_type == "native" {
            bal = b.balance.parse::<f64>()?;
        }
    }
    println!("bal: {:?}", bal);
    Ok(U256::zero())
}

async fn eth_sweep_main(
    seed: &HDSeed,
    index: i32,
    to_str: &str,
    provider: &str,
) -> Result<String, Error> {
    let transport = web3::transports::Http::new(provider)?;
    let web3 = web3::Web3::new(transport);
    let addr_str = eth_address_by_index(seed, index)?;
    let prvk_str = eth_private_by_index(seed, index)?;
    let prvk = web3::signing::SecretKey::from_str(&prvk_str)?;
    let addr = H160::from_str(&addr_str)?;
    let to = Address::from_str(to_str)?;
    let gas_price = web3.eth().gas_price().await?;
    let bal = web3.eth().balance(addr, None).await?;
    let fee = gas_price * 21000 * 5;
    let val_to_send = bal - fee;
    let tx_call_req = CallRequest {
        to: Some(to),
        value: Some(bal),
        ..Default::default()
    };
    let est_gas = web3.eth().estimate_gas(tx_call_req, None).await?;
    println!("================");
    println!("gas_price: {:?}", &gas_price);
    println!("bal: {:?}", &bal);
    println!("fee: {:?}", &fee);
    println!("val_to_send: {:?}", &val_to_send);
    println!("est_gas: {:?}", &est_gas);
    let tx_object = TransactionParameters {
        to: Some(to),
        value: val_to_send,
        ..Default::default()
    };
    let signed = web3.accounts().sign_transaction(tx_object, &prvk).await?;
    let result = web3
        .eth()
        .send_raw_transaction(signed.raw_transaction)
        .await?;
    println!("Tx succeeded with hash: {}", result);
    Ok("lalala".to_owned())
}

async fn tron_sweep_main(
    seed: &HDSeed,
    index: i32,
    to_str: &str,
    provider: &str,
) -> Result<String, Error> {
    let transport = web3::transports::Http::new(provider)?;
    let web3 = web3::Web3::new(transport);
    let addr_str = tron_address_by_index_hex(seed, index)?;
    let prvk_str = eth_private_by_index(seed, index)?;
    let prvk = web3::signing::SecretKey::from_str(&prvk_str)?;
    let addr = H160::from_str(&addr_str)?;
    let to = H160::from_str(&tron_to_hex(to_str)?)?;
    let gas_price = web3.eth().gas_price().await?;
    let bal = web3.eth().balance(addr, None).await?;
    let fee = gas_price * 21000 * 5;
    let val_to_send = bal - fee;
    let tx_call_req = CallRequest {
        to: Some(to),
        value: Some(bal),
        ..Default::default()
    };
    let est_gas = web3.eth().estimate_gas(tx_call_req, None).await?;
    println!("================");
    println!("gas_price: {:?}", &gas_price);
    println!("bal: {:?}", &bal);
    println!("fee: {:?}", &fee);
    println!("val_to_send: {:?}", &val_to_send);
    println!("est_gas: {:?}", &est_gas);
    let tx_object = TransactionParameters {
        to: Some(to),
        value: val_to_send,
        nonce: Some(U256::from(11)),
        ..Default::default()
    };
    println!("all okay main 1");
    let signed = web3.accounts().sign_transaction(tx_object, &prvk).await?;
    let _tx_raw = "0a026ffa22086e06b4977c94304540908fb8e4a6315a67080112630a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412320a1541279f93bc1feb8af89d3253c5471b823c26671a92121541c90c049a15d5ef5af136653ccd6f26758b821e9018a08d0670c3c5b4e4a631";
    println!("all okay main 2");
    println!("signed: {:?}", signed.raw_transaction);
    println!("signed_hex: {:?}", "main2");
    Ok("aaaaaaaa".to_owned())
    //let result = web3
    //    .eth()
    //    .send_raw_transaction(signed.raw_transaction)
    //    .await?;
    //println!("Tx succeeded with hash: {}", result);
    //Ok(result.to_string())
}

async fn eth_balance_token(
    seed: &HDSeed,
    index: i32,
    token_addr: &str,
    provider: &str,
) -> Result<TokenData, Error> {
    let transport = web3::transports::Http::new(provider)?;
    let web3 = web3::Web3::new(transport);
    let addr_str = eth_address_by_index(seed, index)?;
    let addr = H160::from_str(&addr_str)?;
    let token_address = H160::from_str(token_addr)?;
    let contract = Contract::from_json(
        web3.eth(),
        token_address,
        include_bytes!("../res/erc20.abi.json"),
    )?;
    let balance = contract
        .query("balanceOf", (addr,), None, Options::default(), None)
        .await?;
    let decimals: u8 = contract
        .query("decimals", (), None, Options::default(), None)
        .await?;
    let symbol: String = contract
        .query("symbol", (), None, Options::default(), None)
        .await?;
    let balance_calced: U256 = (balance) / (U256::exp10((decimals - 2) as usize));
    let balance_f = (balance_calced.as_u128() as f64) * 0.01;
    let token_data = TokenData {
        balance,
        balance_f,
        decimals,
        symbol,
        address: token_addr.to_owned(),
    };
    Ok(token_data)
}

async fn tron_balance_token(
    seed: &HDSeed,
    index: i32,
    token_addr: &str,
    provider: &str,
) -> Result<TokenData, Error> {
    let transport = web3::transports::Http::new(provider)?;
    let web3 = web3::Web3::new(transport);
    let addr_str = tron_address_by_index_hex(seed, index)?;
    let addr = H160::from_str(&addr_str)?;
    let token_addr_v = base58::decode(token_addr)?;
    let token_addr_hex = hex::encode(&token_addr_v);
    let token_addr_hex_p = "0x".to_owned() + &token_addr_hex[2..token_addr_hex.len() - 8];
    let token_address = H160::from_str(&token_addr_hex_p)?;
    let contract = Contract::from_json(
        web3.eth(),
        token_address,
        include_bytes!("../res/erc20.abi.json"),
    )?;
    let result = contract.query("balanceOf", (addr,), None, Options::default(), None);
    let decimals: u8 = contract
        .query("decimals", (), None, Options::default(), None)
        .await?;
    let symbol: String = contract
        .query("symbol", (), None, Options::default(), None)
        .await?;
    let balance: U256 = result.await?;
    let balance_calced: U256 = (balance) / (U256::exp10((decimals - 2) as usize));
    let balance_f = (balance_calced.as_u128() as f64) * 0.01;
    let token_data = TokenData {
        balance,
        balance_f,
        decimals,
        symbol,
        address: token_addr_hex_p,
    };
    Ok(token_data)
}

async fn stellar_balance_token(
    seed: &str,
    index: i32,
    addr: &str,
    provider: &str,
) -> Result<TokenData, Error> {
    let server = Server::new(provider.to_owned());
    let acc = stellar_address_by_index(seed, index)?;
    let r_ops_resp = server
        .operations()
        .for_endpoint(Endpoint::Accounts(acc))
        .call();
    let mut balance = U256::zero();
    let mut balance_f = 0.0;
    let decimals = 8;
    let mut symbol = " ".to_owned();
    match r_ops_resp {
        Ok(ops_resp) => {
            let ops = ops_resp._embedded.records;
            for o in ops {
                let o_asset = o.asset;
                match o_asset {
                    None => {}
                    Some(asset) => {
                        if asset == addr {
                            symbol = (asset.split(':').next()).unwrap_or(" ").to_owned();
                            balance_f = match o.amount.clone() {
                                None => 0.,
                                Some(a) => a.parse()?,
                            };
                            balance = U256::from((balance_f * 100_000_000.0) as u128);
                        }
                    }
                }
            }
            let token_data = TokenData {
                balance,
                balance_f,
                decimals,
                symbol,
                address: addr.to_owned(),
            };
            Ok(token_data)
        }
        Err(_) => {
            let token_data = TokenData {
                balance,
                balance_f,
                decimals,
                symbol,
                address: addr.to_owned(),
            };
            Ok(token_data)
        }
    }
}

async fn eth_sweep_token(
    seed: &HDSeed,
    index: i32,
    token_addr: &str,
    to_str: &str,
    provider: &str,
    _: Crypto,
) -> Result<H256, Error> {
    let transport = web3::transports::Http::new(provider)?;
    let web3 = web3::Web3::new(transport);
    let addr_str = eth_address_by_index(seed, index)?;
    let prvk_str = eth_private_by_index(seed, index)?;
    let prvk = web3::signing::SecretKey::from_str(&prvk_str)?;
    let addr = H160::from_str(&addr_str)?;
    let to = Address::from_str(to_str)?;
    let token_address = H160::from_str(token_addr)?;
    let contract = Contract::from_json(
        web3.eth(),
        token_address,
        include_bytes!("../res/erc20.abi.json"),
    )?;
    let balance_of: U256 = contract
        .query("balanceOf", (addr,), None, Options::default(), None)
        .await?;
    println!("balance_of: {:?}", &balance_of);
    let gas_est = contract
        .estimate_gas("transfer", (to, balance_of), addr, Options::default())
        .await?;

    let gas_price = web3.eth().gas_price().await?;
    let fee = gas_est * gas_price;
    println!("================");
    println!("gas_price: {:?}", &gas_price);
    println!("gas_est: {:?}", &gas_est);
    println!("fee: {:?}", &fee);
    let token_call = contract
        .signed_call("transfer", (to, balance_of), Options::default(), &prvk)
        .await?;
    println!("token_receipt: {:?}", token_call);
    Ok(token_call)
}

async fn tron_sweep_token(
    seed: &HDSeed,
    index: i32,
    token_addr: &str,
    to_str: &str,
    provider: &str,
    _: Crypto,
) -> Result<H256, Error> {
    let transport = web3::transports::Http::new(provider)?;
    let web3 = web3::Web3::new(transport);
    //let addr_str = tron_address_by_index_hex(seed, index)?;
    let prvk_str = tron_private_by_index(seed, index)?;
    let prvk = web3::signing::SecretKey::from_str(&prvk_str)?;
    //let addr = H160::from_str(&addr_str)?;
    let addr_str = tron_address_by_index_hex(seed, index)?;
    let addr = H160::from_str(&addr_str)?;
    let to = H160::from_str(&tron_to_hex(to_str)?)?;
    let token_address = H160::from_str(token_addr)?;
    let contract = Contract::from_json(
        web3.eth(),
        token_address,
        include_bytes!("../res/erc20.abi.json"),
    )?;
    let balance_of: U256 = contract
        .query("balanceOf", (addr,), None, Options::default(), None)
        .await?;
    let gas_est = contract
        .estimate_gas("transfer", (to, balance_of), addr, Options::default())
        .await?;

    let gas_price = web3.eth().gas_price().await?;
    let fee = gas_est * gas_price;
    println!("================");
    println!("gas_price: {:?}", &gas_price);
    println!("gas_est: {:?}", &gas_est);
    println!("fee: {:?}", &fee);
    println!("all okay token 1");
    let token_call = contract
        .call(
            "transfer",
            (to, balance_of),
            addr,
            Options {
                nonce: Some(U256::from(10)),
                ..Default::default()
            },
        )
        .await?;
    println!("all okay token 2");
    println!("token_call: {:?}", token_call);
    let signed_token_call = web3.accounts().sign(token_call, &prvk);
    println!("all okay token 3");
    println!("signed token call: {:?}", signed_token_call);
    Err(Error::MnemonicError("aaa".to_owned()))
    //Ok(token_call)
}

pub async fn gas_price(provider: &str) -> Result<U256, Error> {
    let transport = web3::transports::Http::new(provider)?;
    let web3 = web3::Web3::new(transport);
    let gas_price = web3.eth().gas_price().await?;
    Ok(gas_price)
}

pub async fn tx_receipt(hash: H256, provider: &str) -> Result<TransactionReceipt, Error> {
    let transport = web3::transports::Http::new(provider)?;
    let web3 = web3::Web3::new(transport);
    let receipt = web3
        .eth()
        .transaction_receipt(hash)
        .await?
        .ok_or(Error::Web3NoTransactionError(hash))?;
    Ok(receipt)
}

pub async fn tx_info(hash: H256, provider: &str) -> Result<Transaction, Error> {
    let transport = web3::transports::Http::new(provider)?;
    let web3 = web3::Web3::new(transport);
    let tx = web3
        .eth()
        .transaction(web3::types::TransactionId::Hash(hash))
        .await?
        .ok_or(Error::Web3NoTransactionError(hash))?;
    Ok(tx)
}

pub async fn send_main(
    prvk_str: &str,
    to_str: &str,
    val: U256,
    provider: &str,
) -> Result<H256, Error> {
    let transport = web3::transports::Http::new(provider)?;
    let web3 = web3::Web3::new(transport);
    let prvk = web3::signing::SecretKey::from_str(prvk_str)?;
    let to = Address::from_str(to_str)?;
    let tx_object = TransactionParameters {
        to: Some(to),
        value: val,
        ..Default::default()
    };
    let signed = web3.accounts().sign_transaction(tx_object, &prvk).await?;
    let result = web3
        .eth()
        .send_raw_transaction(signed.raw_transaction)
        .await?;
    println!("Tx succeeded with hash: {:?}", result);
    Ok(result)
}

pub fn validate_tron_address(addr: String) -> bool {
    if addr.len() != 34 {
        false
    } else {
        let r_bytes = base58::decode(&addr);
        match r_bytes {
            Ok(mut bytes) => {
                let check = bytes.split_off(bytes.len() - 4);
                let mut hasher = Sha256::new();
                hasher.update(&bytes);
                let digest1 = hasher.finalize();
                let mut hasher = Sha256::new();
                hasher.update(digest1);
                let digest = hasher.finalize();
                check == digest[..4]
            }
            Err(_) => false,
        }
    }
}

pub fn tron_to_hex(addr: &str) -> Result<String, Error> {
    if addr.len() != 34 {
        Err(Error::TronToHexError(addr.to_owned()))
    } else {
        let mut bytes = base58::decode(addr)?;
        let _a = bytes.split_off(bytes.len() - 4);
        let hex_str: String = bytes.encode_hex();
        let hex = "0x".to_owned() + &hex_str[2..];
        Ok(hex)
    }
}

pub fn tron_to_hex_raw(addr: &str) -> Result<String, Error> {
    if addr.len() != 34 {
        Err(Error::TronToHexError(addr.to_owned()))
    } else {
        let mut bytes = base58::decode(addr)?;
        let _a = bytes.split_off(bytes.len() - 4);
        let hex_str: String = bytes.encode_hex();
        Ok(hex_str)
    }
}

fn bitcoin_address_by_index(_: &HDSeed, _: i32) -> Result<String, Error> {
    Ok("unimplemented".to_string())
}

#[allow(dead_code)]
async fn btc_sweep_main(
    _seed: &HDSeed,
    _index: i32,
    to_str: &str,
    provider: &str,
) -> Result<String, Error> {
    let client = Client::new(provider).unwrap();
    let external_descriptor = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/0/*)";
    let internal_descriptor = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/1/*)";
    //TODO -- descriptors should be created from HD seed.
    let wallet = Wallet::new(
        external_descriptor,
        Some(internal_descriptor),
        bdk::bitcoin::Network::Testnet,
        MemoryDatabase::default(),
    )
    .unwrap();
    let s_addr = bdk::bitcoin::Address::from_str(to_str).unwrap();
    let mut tx_builder = wallet.build_tx();
    tx_builder
        .add_recipient(s_addr.script_pubkey(), 10000)
        .enable_rbf();
    let mut psbt = tx_builder.finish().unwrap();
    let finalized = wallet.sign(&mut psbt.0, SignOptions::default()).unwrap();
    assert!(finalized);
    let tx = psbt.0.extract_tx();
    client.transaction_broadcast(&tx).unwrap();
    println!("Tx broadcasted! Txid: {}", tx.txid());
    Ok(tx.txid().to_string())
}
