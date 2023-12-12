mod abi;
mod crypto;
mod error;
mod private;
mod signature;

use crate::tron_grpc;
use crate::tron_grpc::wallet_client::WalletClient;
use crate::tron_grpc::EmptyMessage;
use tonic::transport::Channel;
use hex::FromHex;
use prost::Message;


async fn get_client()->WalletClient<Channel>{
    tron_grpc::wallet_client::WalletClient::connect("grpc://grpc.nile.trongrid.io:50051".to_string()).await.expect("connect error")
}

pub async fn transfer_trx(){
    let mut client =  get_client().await;
    let from=hex::decode( ADDR_HEX_1).expect("decode error");
    let to=hex::decode( ADDR_HEX_2).expect("decode error");
    let amount=12345; // 2个
    let secret_obj=private::Private::from_hex (PRIVATE_KEY_1).expect("decode error");

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
