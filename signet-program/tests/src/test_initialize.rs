use std::str::FromStr;

use anchor_client::{
    solana_sdk::{
        commitment_config::CommitmentConfig, pubkey::Pubkey, signature::read_keypair_file,
        signer::Signer,
    },
    Client, Cluster,
};

#[test]
fn test_initialize() {
    // Use the program ID from the generated ID constant
    let program_id = signet::ID;
    let anchor_wallet = std::env::var("ANCHOR_WALLET").unwrap();
    let payer = read_keypair_file(&anchor_wallet).unwrap();

    let client = Client::new_with_options(Cluster::Localnet, &payer, CommitmentConfig::confirmed());
    let program = client.program(program_id).unwrap();

    // Derive the PDA for program_state
    let (program_state, _bump) = Pubkey::find_program_address(&[b"program-state"], &program_id);
    let admin = payer.pubkey();
    let system_program = Pubkey::from_str("11111111111111111111111111111111").unwrap();

    let tx = program
        .request()
        .accounts(signet::accounts::Initialize {
            program_state,
            admin,
            system_program,
        })
        .args(signet::instruction::Initialize {
            signature_deposit: 1,
            network_id: "solana:localnet".to_string(),
        })
        .send()
        .expect("");

    println!("Your transaction signature {}", tx);
}
