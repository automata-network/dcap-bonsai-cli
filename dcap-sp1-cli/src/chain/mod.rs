pub mod attestation;
pub mod pccs;

use alloy::{
    network::{EthereumWallet, TransactionBuilder},
    primitives::{Address, Bytes},
    providers::{Provider, ProviderBuilder},
    rpc::types::{TransactionReceipt, TransactionRequest},
    signers::{k256::ecdsa::SigningKey, local::PrivateKeySigner, utils::secret_key_to_address},
};
use anyhow::Result;

pub struct TxSender {
    rpc_url: String,
    wallet: EthereumWallet,
    contract: Address,
}

impl TxSender {
    /// Creates a new `TxSender`.
    pub fn new(rpc_url: &str, contract: &str) -> Result<Self> {
        let contract = contract.parse::<Address>()?;

        Ok(TxSender {
            rpc_url: rpc_url.to_string(),
            wallet: EthereumWallet::default(),
            contract,
        })
    }

    pub fn set_wallet(&mut self, private_key: &str) -> Result<()> {
        let signer_key =
            SigningKey::from_slice(&hex::decode(private_key).unwrap()).expect("Invalid key");
        let wallet = EthereumWallet::from(PrivateKeySigner::from_signing_key(signer_key));

        self.wallet = wallet;

        Ok(())
    }

    /// Sends the transaction
    pub async fn send(&self, calldata: Vec<u8>) -> Result<TransactionReceipt> {
        let rpc_url = self.rpc_url.parse()?;
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(&self.wallet)
            .on_http(rpc_url);

        let tx = TransactionRequest::default()
            .with_to(self.contract)
            .with_input(calldata);

        let receipt = provider
            .send_transaction(tx.clone())
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    /// Makes a staticcall with the given transaction request
    pub async fn call(&self, calldata: Vec<u8>) -> Result<Bytes> {
        let rpc_url = self.rpc_url.parse()?;
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(&self.wallet)
            .on_http(rpc_url);

        let tx = TransactionRequest::default()
            .with_to(self.contract)
            .with_input(calldata);

        let call_output = provider.call(&tx).await?;

        Ok(call_output)
    }
}

pub fn get_evm_address_from_key(key: &str) -> String {
    let key_slice = hex::decode(key).unwrap();
    let signing_key = SigningKey::from_slice(&key_slice).expect("Invalid key");
    let address = secret_key_to_address(&signing_key);
    address.to_checksum(None)
}
