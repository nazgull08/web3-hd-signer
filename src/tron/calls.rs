use bitcoin::base58;
use crate::tron::abi::ABI;
use crate::tron::{crypto, private};
use crate::tron_grpc::{EmptyMessage, self};
use crate::tron_grpc::wallet_client::WalletClient;
use ethers::abi::{Abi, Address, Detokenize, Tokenize};
use ethers::types::U256;
use hex::FromHex;
use prost::Message;
use tonic::transport::Channel;

use super::private::Private;

async fn get_client()->WalletClient<Channel>{
    tron_grpc::wallet_client::WalletClient::connect("grpc://grpc.nile.trongrid.io:50051".to_string()).await.expect("connect error")
}

pub async fn test_transfer_trx(c_from: &str, c_to: &str, priv_key: &str) -> (){
    let from=hex::decode( c_from).expect("decode error");
    let to=hex::decode( c_to).expect("decode error");
    let amount=12345; // 2个
    let secret_obj= Private::from_hex(priv_key).expect("decode error");

    println!("============================================");
    println!("from: {:?}",from);
    println!("to: {:?}",to);
    println!("sec: {:?}",secret_obj);
    println!("============================================");

}
pub async fn transfer_trx(c_from: &str, c_to: &str, priv_key: &str, amount: i64){
    let mut client =  get_client().await;
    let from=hex::decode( c_from).expect("decode error");
    let to=hex::decode( c_to).expect("decode error");
    let secret_obj= Private::from_hex(priv_key).expect("decode error");

    let now_block= client.get_now_block2(EmptyMessage{}).await.expect("get block error");
    let now_block= now_block.into_inner();

    let contract_type=tron_grpc::transaction::contract::ContractType::TransferContract;
    let transfer_tx = tron_grpc::TransferContract{
        owner_address: from,
        to_address: to,
        amount
    };

    let mut raw_bytes:Vec<u8>=Vec::new();
    transfer_tx.encode(&mut raw_bytes);
    let tx_any= prost_types::Any{
        type_url: format!("type.googleapis.com/protocol.{:?}", &contract_type),
        value: raw_bytes
    };

    let contract=tron_grpc::transaction::Contract{
        r#type: contract_type.clone() as i32 ,
        parameter: Some(tx_any),
        provider: vec![],
        contract_name: vec![],
        permission_id: 0
    };

    let block_num=now_block.block_header.expect("get header error") .raw_data.expect("get raw data error") .number;

    let now=chrono::Utc::now().timestamp_millis();
    let mut raw= tron_grpc::transaction::Raw{
        ref_block_bytes: vec![
            ((block_num & 0xff00) >> 8) as u8,
            (block_num & 0xff) as u8,
        ],
        ref_block_num:block_num ,
        ref_block_hash: now_block.blockid[8..16].to_owned(),
        expiration: now+61*1000, 
        auths: vec![],
        data: vec![],
        contract: vec![contract],
        scripts: vec![],
        timestamp:now,
        fee_limit: 0
    };

    let mut raw_bytes:Vec<u8>=Vec::new();
    raw.encode(&mut raw_bytes);

    let txid = crypto::sha256(&raw_bytes);
    println!("txid:{}",hex::encode(&txid));

    let sign_val = secret_obj.sign_digest(txid.as_slice()).expect("sign error");

    let req=tron_grpc::Transaction{
        raw_data: Some(raw),
        signature: vec![
            sign_val.to_vec()
        ],
        ret: vec![]
    };

    let result= client.broadcast_transaction(req).await.expect("broadcast error");
    println!("result: {:?}",&result);
}

pub async fn transfer_trc20(c_from: &str, c_to: &str, priv_key: &str, amount: i64, contract_addr: &str){
    let mut client =  get_client().await;
    let from=hex::decode(c_from).expect("decode error");
    let to=hex::decode( c_to).expect("decode error");
    let amount:ethers::types::U256 =U256::from(amount);
    let secret_obj=private::Private::from_hex (priv_key).expect("decode error");
    let mut contract_addr_bytes =  base58::decode(contract_addr).expect("decode error");
    println!("contract addr:{}",hex::encode(&contract_addr_bytes[..contract_addr_bytes.len()-4].to_vec()));

    let now_block= client.get_now_block2(EmptyMessage{}).await.expect("get block error");
    let now_block= now_block.into_inner();

    let fn_obj= ABI.function("transfer").expect("get fn error");
    let param_data= ethers::contract::encode_function_data(fn_obj,(Address::from_slice(&to[1..]),amount)).expect("encode fn param error");
    println!("param data:{}",hex::encode( param_data.as_ref()));

    let contract_type=tron_grpc::transaction::contract::ContractType::TriggerSmartContract;
    let transfer_tx = tron_grpc::TriggerSmartContract{
        owner_address: from,
        contract_address: contract_addr_bytes[..contract_addr_bytes.len()-4].to_vec(),
        call_value: 0,
        data: param_data.to_vec(),
        call_token_value: 0,
        token_id: 0
    };

    let mut raw_bytes:Vec<u8>=Vec::new();
    transfer_tx.encode(&mut raw_bytes);
    let tx_any= prost_types::Any{
        type_url: format!("type.googleapis.com/protocol.{:?}", &contract_type),
        value: raw_bytes
    };

    let contract=tron_grpc::transaction::Contract{
        r#type: contract_type.clone() as i32 ,
        parameter: Some(tx_any),
        provider: vec![],
        contract_name: vec![],
        permission_id: 0
    };

    let block_num=now_block.block_header.expect("get header error") .raw_data.expect("get raw data error") .number;

    let now=chrono::Utc::now().timestamp_millis();
    let mut raw= tron_grpc::transaction::Raw{
        ref_block_bytes: vec![
            ((block_num & 0xff00) >> 8) as u8,
            (block_num & 0xff) as u8,
        ],
        ref_block_num:block_num ,
        ref_block_hash: now_block.blockid[8..16].to_owned(),
        expiration: now+61*1000,
        auths: vec![],
        data: vec![],
        contract: vec![contract],
        scripts: vec![],
        timestamp:now,
        fee_limit: 60000000
    };

    //prost::Message::encode()
    let mut raw_bytes:Vec<u8>=Vec::new();
    raw.encode(&mut raw_bytes);

    let txid = crypto::sha256(&raw_bytes);
    println!("txid:{}",hex::encode(&txid));

    let sign_val = secret_obj.sign_digest(txid.as_slice()).expect("sign error");

    let req=tron_grpc::Transaction{
        raw_data: Some(raw),
        signature: vec![
            sign_val.to_vec()
        ],
        ret: vec![]
    };

    let mut raw_bytes:Vec<u8>=Vec::new();
    req.encode(&mut raw_bytes);
    println!("req len:{}",raw_bytes.len());

        let result= client.broadcast_transaction(req).await.expect("broadcast error");
        println!("result: {:?}",&result);
        let result=result.into_inner();
        println!("message:{}",   String::from_utf8(result.message).expect("decode message error"));
}