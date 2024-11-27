// Ref https://github.com/risc0/risc0-ethereum/blob/667482a6fffef6b952c735842b4b555fb56865f8/contracts/src/groth16.rs

use alloy::{primitives::U256, sol_types::SolValue};
use alloy::sol;
use anyhow::{ensure, Result};
use risc0_zkvm::Groth16Seal;

sol! {
    /// Groth16 seal construction from [RiscZeroGroth16Verifier.sol].
    ///
    /// [RiscZeroGroth16Verifier.sol]: https://github.com/risc0/risc0/blob/v0.20.1/bonsai/ethereum/contracts/groth16/RiscZeroGroth16Verifier.sol#L76-L81
    #[derive(Debug)]
    struct Seal {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
    }
}

impl Seal {
    /// ABI encoding of the seal.
    pub fn abi_encode(seal: Groth16Seal) -> Result<Vec<u8>> {
        let seal = Seal::try_from(seal)?;
        Ok(seal.abi_encode())
    }
}

impl TryFrom<Groth16Seal> for Seal {
    type Error = anyhow::Error;

    fn try_from(seal: Groth16Seal) -> Result<Self> {
        ensure!(
            seal.a.len() == 2,
            "seal.a has invalid length: {}",
            seal.a.len()
        );
        ensure!(
            seal.b.len() == 2,
            "seal.b has invalid length: {}",
            seal.b.len()
        );
        ensure!(
            seal.b[0].len() == 2,
            "seal.b[0] has invalid length: {}",
            seal.b[0].len()
        );
        ensure!(
            seal.b[1].len() == 2,
            "seal.b[0] has invalid length: {}",
            seal.b[1].len()
        );
        ensure!(
            seal.c.len() == 2,
            "seal.c has invalid length: {}",
            seal.c.len()
        );

        let a0 = U256::from_be_slice(seal.a[0].as_slice());
        let a1 = U256::from_be_slice(seal.a[1].as_slice());
        let b00 = U256::from_be_slice(seal.b[0][0].as_slice());
        let b01 = U256::from_be_slice(seal.b[0][1].as_slice());
        let b10 = U256::from_be_slice(seal.b[1][0].as_slice());
        let b11 = U256::from_be_slice(seal.b[1][1].as_slice());
        let c0 = U256::from_be_slice(seal.c[0].as_slice());
        let c1 = U256::from_be_slice(seal.c[1].as_slice());

        Ok(Seal {
            a: [a0, a1],
            b: [[b00, b01], [b10, b11]],
            c: [c0, c1],
        })
    }
}