use alloy::{
    primitives::Bytes,
    sol,
    sol_types::{SolInterface, SolValue},
};

sol! {
    interface IAttestation {
        function verifyAndAttestWithZKProof(bytes calldata output, uint8 zk_coprocessor_type, bytes calldata proof) returns (bool success, bytes memory output);
    }
}

pub fn generate_attestation_calldata(output: &[u8], proof: &[u8]) -> Vec<u8> {
    let calldata = IAttestation::IAttestationCalls::verifyAndAttestWithZKProof(
        IAttestation::verifyAndAttestWithZKProofCall {
            output: Bytes::from(output.to_vec()),
            zk_coprocessor_type: 2,
            proof: Bytes::from(proof.to_vec()),
        },
    )
    .abi_encode();

    calldata
}

pub fn decode_attestation_ret_data(ret: Vec<u8>) -> (bool, Vec<u8>) {
    let (verified, output) = <(bool, Bytes)>::abi_decode_params(&ret, true).unwrap();
    (verified, output.to_vec())
}
