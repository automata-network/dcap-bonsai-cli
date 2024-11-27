use alloy::{
    primitives::Bytes,
    sol,
    sol_types::{SolInterface, SolValue},
};

sol! {
    interface IAttestation {
        function verifyAndAttestWithZKProof(bytes calldata journal, uint8 zkCoProcessor, bytes calldata seal) returns (bool success, bytes memory output);
    }
}

pub fn generate_attestation_calldata(output: &[u8], seal: &[u8]) -> Vec<u8> {
    let calldata = IAttestation::IAttestationCalls::verifyAndAttestWithZKProof(
        IAttestation::verifyAndAttestWithZKProofCall {
            journal: Bytes::from(output.to_vec()),
            zkCoProcessor: 1, // RiscZero
            seal: Bytes::from(seal.to_vec()),
        },
    )
    .abi_encode();

    calldata
}

pub fn decode_attestation_ret_data(ret: Vec<u8>) -> (bool, Vec<u8>) {
    let (verified, journal) = <(bool, Bytes)>::abi_decode_params(&ret, true).unwrap();
    (verified, journal.to_vec())
}
