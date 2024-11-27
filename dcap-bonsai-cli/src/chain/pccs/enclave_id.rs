use anyhow::Result;

use crate::constants::{DEFAULT_RPC_URL, ENCLAVE_ID_DAO_ADDRESS};
use crate::remove_prefix_if_found;

use alloy::{
    primitives::{Address, U256},
    providers::ProviderBuilder,
    sol,
};

sol! {
    #[sol(rpc)]
    interface IEnclaveIdentityDao {
        #[derive(Debug)]
        struct EnclaveIdentityJsonObj {
            string identityStr;
            bytes signature;
        }

        #[derive(Debug)]
        function getEnclaveIdentity(uint256 id, uint256 version) returns (EnclaveIdentityJsonObj memory enclaveIdObj);
    }
}

#[derive(Debug)]
pub enum EnclaveIdType {
    QE,
    QVE,
    TDQE,
}

pub async fn get_enclave_identity(id: EnclaveIdType, version: u32) -> Result<Vec<u8>> {
    let rpc_url = DEFAULT_RPC_URL.parse().expect("Failed to parse RPC URL");
    let provider = ProviderBuilder::new().on_http(rpc_url);

    let enclave_id_dao_address_slice =
        hex::decode(ENCLAVE_ID_DAO_ADDRESS).expect("Invalid address hex");

    let enclave_id_dao_contract = IEnclaveIdentityDao::new(
        Address::from_slice(&enclave_id_dao_address_slice),
        &provider,
    );

    let enclave_id_type_uint256;
    match id {
        EnclaveIdType::QE => enclave_id_type_uint256 = U256::from(0),
        EnclaveIdType::QVE => enclave_id_type_uint256 = U256::from(1),
        EnclaveIdType::TDQE => enclave_id_type_uint256 = U256::from(2),
    }

    let call_builder =
        enclave_id_dao_contract.getEnclaveIdentity(enclave_id_type_uint256, U256::from(version));

    let call_return = call_builder.call().await?;

    let identity_str = call_return.enclaveIdObj.identityStr;
    let signature_bytes = call_return.enclaveIdObj.signature;

    if identity_str.len() == 0 || signature_bytes.len() == 0 {
        return Err(anyhow::Error::msg(format!(
            "QEIdentity for ID: {:?}; Version: {} is missing and must be upserted to on-chain pccs",
            id, version
        )));
    }

    let signature = signature_bytes.to_string();

    let ret_str = format!(
        "{{\"enclaveIdentity\": {}, \"signature\": \"{}\"}}",
        identity_str,
        remove_prefix_if_found(signature.as_str())
    );

    let ret = ret_str.into_bytes();
    Ok(ret)
}
