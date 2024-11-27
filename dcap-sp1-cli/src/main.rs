use std::fs::read_to_string;
use std::path::PathBuf;

use dcap_sp1_cli::chain::attestation::{
    decode_attestation_ret_data, generate_attestation_calldata,
};
use dcap_sp1_cli::chain::pccs::{
    enclave_id::{get_enclave_identity, EnclaveIdType},
    fmspc_tcb::get_tcb_info,
    pcs::{get_certificate_by_id, IPCSDao::CA},
};
use dcap_sp1_cli::chain::TxSender;
use dcap_sp1_cli::constants::*;
use dcap_sp1_cli::parser::get_pck_fmspc_and_issuer;
use dcap_sp1_cli::remove_prefix_if_found;

use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};
use dcap_rs::constants::{SGX_TEE_TYPE, TDX_TEE_TYPE};
use dcap_rs::types::{collaterals::IntelCollateral, VerifiedOutput};
use sp1_sdk::{utils, HashableKey, ProverClient, SP1Stdin};

pub const DCAP_ELF: &[u8] = include_bytes!("../elf/riscv32im-succinct-zkvm-elf");

#[derive(Parser)]
#[command(name = "DcapSP1App")]
#[command(version = "1.0")]
#[command(about = "Gets SP1 Proof for DCAP Quote Verification and submits on-chain")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Fetches proof from SP1 and sends them on-chain to verify DCAP quote
    Prove(DcapArgs),

    /// De-serializes and prints information about the Output
    Deserialize(OutputArgs),
}

/// Enum representing the available proof systems
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum ProofSystem {
    Groth16,
    Plonk,
}

#[derive(Args)]
struct DcapArgs {
    /// The input quote provided as a hex string, this overwrites the --quote-path argument
    #[arg(short = 'q', long = "quote-hex")]
    quote_hex: Option<String>,

    /// Optional: The path to a quote.hex file. Default: /data/quote.hex or overwritten by the --quote-hex argument if provided.
    #[arg(short = 'p', long = "quote-path")]
    quote_path: Option<PathBuf>,

    #[arg(
        short = 's',
        long = "prove-system",
        value_enum,
        default_value = "groth16"
    )]
    proof_system: Option<ProofSystem>,
}

#[derive(Args)]
struct OutputArgs {
    #[arg(short = 'o', long = "output")]
    output: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    utils::setup_logger();

    let cli = Cli::parse();

    match &cli.command {
        Commands::Prove(args) => {
            // Step 0: Read quote
            println!("Begin reading quote and fetching the necessary collaterals...");
            let quote = get_quote(&args.quote_path, &args.quote_hex).expect("Failed to read quote");

            // Step 1: Determine quote version and TEE type
            let quote_version = u16::from_le_bytes([quote[0], quote[1]]);
            let tee_type = u32::from_le_bytes([quote[4], quote[5], quote[6], quote[7]]);

            println!("Quote version: {}", quote_version);
            println!("TEE Type: {}", tee_type);

            if quote_version < 3 || quote_version > 4 {
                panic!("Unsupported quote version");
            }

            if tee_type != SGX_TEE_TYPE && tee_type != TDX_TEE_TYPE {
                panic!("Unsupported tee type");
            }

            // Step 2: Load collaterals
            println!("Quote read successfully. Begin fetching collaterals from the on-chain PCCS");

            let (root_ca, root_ca_crl) = get_certificate_by_id(CA::ROOT).await?;
            if root_ca.is_empty() || root_ca_crl.is_empty() {
                panic!("Intel SGX Root CA is missing");
            } else {
                println!("Fetched Intel SGX RootCA and CRL");
            }

            let (fmspc, pck_type, pck_issuer) =
                get_pck_fmspc_and_issuer(&quote, quote_version, tee_type);

            let tcb_type: u8;
            if tee_type == TDX_TEE_TYPE {
                tcb_type = 1;
            } else {
                tcb_type = 0;
            }
            let tcb_version: u32;
            if quote_version < 4 {
                tcb_version = 2
            } else {
                tcb_version = 3
            }
            let tcb_info = get_tcb_info(tcb_type, fmspc.as_str(), tcb_version).await?;

            println!("Fetched TCBInfo JSON for FMSPC: {}", fmspc);

            let qe_id_type: EnclaveIdType;
            if tee_type == TDX_TEE_TYPE {
                qe_id_type = EnclaveIdType::TDQE
            } else {
                qe_id_type = EnclaveIdType::QE
            }
            let qe_identity = get_enclave_identity(qe_id_type, quote_version as u32).await?;
            println!("Fetched QEIdentity JSON");

            let (signing_ca, _) = get_certificate_by_id(CA::SIGNING).await?;
            if signing_ca.is_empty() {
                panic!("Intel TCB Signing CA is missing");
            } else {
                println!("Fetched Intel TCB Signing CA");
            }

            let (_, pck_crl) = get_certificate_by_id(pck_type).await?;
            if pck_crl.is_empty() {
                panic!("CRL for {} is missing", pck_issuer);
            } else {
                println!("Fetched Intel PCK CRL for {}", pck_issuer);
            }

            let mut intel_collaterals = IntelCollateral::new();
            println!("set_tcbinfo_bytes: {:?}", tcb_info);
            intel_collaterals.set_tcbinfo_bytes(&tcb_info);
            println!("set_qeidentity_bytes: {:?}", qe_identity);
            intel_collaterals.set_qeidentity_bytes(&qe_identity);
            println!("set_intel_root_ca_der: {:?}", root_ca);
            intel_collaterals.set_intel_root_ca_der(&root_ca);
            println!("set_sgx_tcb_signing_der: {:?}", signing_ca);
            intel_collaterals.set_sgx_tcb_signing_der(&signing_ca);
            println!("set_sgx_intel_root_ca_crl_der: {:?}", root_ca_crl);
            intel_collaterals.set_sgx_intel_root_ca_crl_der(&root_ca_crl);
            println!("set_sgx_platform_crl_der: {:?}", pck_crl);
            intel_collaterals.set_sgx_platform_crl_der(&pck_crl);

            let intel_collaterals_bytes = intel_collaterals.to_bytes();

            // Step 3: Generate the input to upload to SP1 Proving Server
            let input = generate_input(&quote, &intel_collaterals_bytes);

            println!("All collaterals found! Begin uploading input to SP1 Proving Server...");

            let mut stdin = SP1Stdin::new();
            stdin.write_slice(&input);

            let client = ProverClient::new();

            // Execute the program first
            let (ret, report) = client.execute(DCAP_ELF, stdin.clone()).run().unwrap();
            println!(
                "executed program with {} cycles",
                report.total_instruction_count()
            );
            // println!("{:?}", report);

            // Generate the proof
            let (pk, vk) = client.setup(DCAP_ELF);
            println!("ProofSystem: {:?}", args.proof_system);
            let proof = if let Some(proof_system) = args.proof_system {
                if proof_system == ProofSystem::Groth16 {
                    client.prove(&pk, stdin.clone()).groth16().run().unwrap()
                } else {
                    client.prove(&pk, stdin.clone()).plonk().run().unwrap()
                }
            } else {
                client.prove(&pk, stdin.clone()).groth16().run().unwrap()
            };

            // Verify proof
            client.verify(&proof, &vk).expect("Failed to verify proof");
            println!("Successfully verified proof.");

            let ret_slice = ret.as_slice();
            let output_len = u16::from_be_bytes([ret_slice[0], ret_slice[1]]) as usize;
            let mut output = Vec::with_capacity(output_len);
            output.extend_from_slice(&ret_slice[2..2 + output_len]);

            println!("Execution Output: {}", hex::encode(ret_slice));
            println!(
                "Proof pub value: {}",
                hex::encode(proof.public_values.as_slice())
            );
            println!("VK: {}", vk.bytes32().to_string().as_str());
            println!("Proof: {}", hex::encode(proof.bytes()));

            let parsed_output = VerifiedOutput::from_bytes(&output);
            println!("{:?}", parsed_output);

            // Send the calldata to Ethereum.
            println!("Submitting proofs to on-chain DCAP contract to be verified...");
            let calldata = generate_attestation_calldata(&ret_slice, &proof.bytes());
            println!("Calldata: {}", hex::encode(&calldata));

            let tx_sender = TxSender::new(DEFAULT_RPC_URL, DEFAULT_DCAP_CONTRACT)
                .expect("Failed to create txSender");

            // staticcall to the DCAP verifier contract to verify proof
            let call_output = (tx_sender.call(calldata.clone()).await?).to_vec();
            let (chain_verified, chain_raw_verified_output) =
                decode_attestation_ret_data(call_output);

            if chain_verified && output == chain_raw_verified_output {
                println!("On-chain verification succeed.");
            } else {
                println!("On-chain verification fail!");
            }
        }
        Commands::Deserialize(args) => {
            let output_vec =
                hex::decode(remove_prefix_if_found(&args.output)).expect("Failed to parse output");
            let deserialized_output = VerifiedOutput::from_bytes(&output_vec);
            println!("Deserialized output: {:?}", deserialized_output);
        }
    }

    println!("Job completed!");

    Ok(())
}

fn get_quote(path: &Option<PathBuf>, hex: &Option<String>) -> Result<Vec<u8>> {
    let error_msg: &str = "Failed to read quote from the provided path";
    match hex {
        Some(h) => {
            let quote_hex = hex::decode(h)?;
            Ok(quote_hex)
        }
        _ => match path {
            Some(p) => {
                let quote_string = read_to_string(p).expect(error_msg);
                let processed = remove_prefix_if_found(&quote_string);
                let quote_hex = hex::decode(processed)?;
                Ok(quote_hex)
            }
            _ => {
                let default_path = PathBuf::from(DEFAULT_QUOTE_PATH);
                let quote_string = read_to_string(default_path).expect(error_msg);
                let processed = remove_prefix_if_found(&quote_string);
                let quote_hex = hex::decode(processed)?;
                Ok(quote_hex)
            }
        },
    }
}

fn generate_input(quote: &[u8], collaterals: &[u8]) -> Vec<u8> {
    // get current time in seconds since epoch
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let current_time_bytes = current_time.to_le_bytes();

    let quote_len = quote.len() as u32;
    let intel_collaterals_bytes_len = collaterals.len() as u32;
    let total_len = 8 + 4 + 4 + quote_len + intel_collaterals_bytes_len;

    let mut input = Vec::with_capacity(total_len as usize);
    input.extend_from_slice(&current_time_bytes);
    input.extend_from_slice(&quote_len.to_le_bytes());
    input.extend_from_slice(&intel_collaterals_bytes_len.to_le_bytes());
    input.extend_from_slice(&quote);
    input.extend_from_slice(&collaterals);

    input.to_owned()
}
