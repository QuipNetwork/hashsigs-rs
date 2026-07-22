// Copyright (C) 2026 quip.network
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
use hashsigs_rs_solana::processor::process_instruction;
use solana_program_test::*;
use solana_sdk::signature::Keypair;

pub mod wotsplus_solana_test {
    use borsh::{BorshDeserialize, BorshSerialize};
    use hashsigs_rs::{constants, PublicKey, WOTSPlus};
    use hashsigs_rs_solana::processor::{self, PublicKeyWrapper};
    use solana_sdk::{instruction::{AccountMeta, Instruction}, msg, pubkey::Pubkey, signer::Signer, transaction::Transaction};

    use super::*;

    async fn setup_test() -> (ProgramTest, Keypair) {
        let program_id = Keypair::new();
        let mut program_test = ProgramTest::new(
            "hashsigs_rs_solana",
            program_id.pubkey(),
            processor!(process_instruction),
        );
        
        // Increase compute units significantly
        let compute_max_units = 1_400_000;  // Increased from 200,000
        program_test.set_compute_max_units(compute_max_units);
        // With SBF_OUT_DIR set (cargo-build-sbf output), run the compiled .so
        // under the real SBF VM instead of the native in-process handler, so
        // compute units and the 32 KiB heap are actually enforced.
        program_test.prefer_bpf(std::env::var_os("SBF_OUT_DIR").is_some());

        (program_test, program_id)
    }

    async fn execute_transaction(
        context: &mut ProgramTestContext,
        program_id: &Pubkey,
        data: Vec<u8>,
    ) -> Result<Transaction, BanksClientError> {
        let instruction = Instruction {
            program_id: *program_id,
            accounts: vec![],
            data,
        };

        let transaction = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&context.payer.pubkey()),
            &[&context.payer],
            context.last_blockhash,
        );

        Ok(transaction)
    }

    #[tokio::test]
    async fn test_generate_key_pair() {
        let (program_test, program_id) = setup_test().await;
        let mut context = program_test.start_with_context().await;
        
        let private_seed = [1u8; 32];
        
        let instruction = processor::WOTSPlusInstruction::GenerateKeyPair {
            private_seed,
        };

        let mut instruction_data: Vec<u8> = Vec::new();
        instruction.serialize(&mut instruction_data).unwrap();
        
        // Execute the instruction on-chain
        let transaction = execute_transaction(
            &mut context,
            &program_id.pubkey(),
            instruction_data,
        ).await.unwrap();

        // Process the transaction and get the return data
        let transaction_result = context.banks_client.process_transaction_with_metadata(transaction).await.unwrap();
        let metadata = transaction_result.metadata.unwrap();
        let compute_units = metadata.compute_units_consumed;
        let return_data = metadata.return_data;

        msg!("Generate key pair compute units: {}", compute_units);

        // Create a mutable slice for deserialization
        let binding = return_data.unwrap();
        let mut return_data_slice = binding.data.as_slice();
        
        // Deserialize the return data into (PublicKey, [u8; 32])
        let (on_chain_public_key, on_chain_private_key): (PublicKeyWrapper, [u8; 32]) = 
            borsh::BorshDeserialize::deserialize(&mut return_data_slice).unwrap();
        
        // Convert wrapper to PublicKey
        let on_chain_public_key = PublicKey::from(on_chain_public_key);
        
        // Verify the results match local execution
        let wots = WOTSPlus::new(processor::keccak256);
        let (local_public_key, local_private_key) = wots.generate_key_pair(&private_seed);
        
        assert_eq!(on_chain_public_key.to_bytes(), local_public_key.to_bytes());
        assert_eq!(on_chain_private_key, local_private_key);
        
        // Additional validation
        assert_eq!(on_chain_public_key.to_bytes().len(), constants::PUBLIC_KEY_SIZE);
        assert!(on_chain_private_key.iter().any(|&x| x != 0));
    }

    #[tokio::test]
    async fn test_sign() {
        let (program_test, program_id) = setup_test().await;
        let context = program_test.start_with_context().await;
        
        let wots = WOTSPlus::new(processor::keccak256);
        let private_seed = [1u8; 32];
        let (_public_key, private_key) = wots.generate_key_pair(&private_seed);

        let message = (0..constants::MESSAGE_LEN).map(|i| i as u8).collect::<Vec<u8>>();
        
        // Create PDA for signature storage
        let (signature_pda, _bump_seed) = Pubkey::find_program_address(
            &[
                b"signature",
                context.payer.pubkey().as_ref(),
                message.as_ref(),
            ],
            &program_id.pubkey()
        );

        msg!("Program ID: {:?}", program_id.pubkey());
        msg!("Payer pubkey: {:?}", context.payer.pubkey());
        msg!("PDA: {:?}", signature_pda);

        let instruction = Instruction {
            program_id: program_id.pubkey(),
            accounts: vec![
                AccountMeta::new(context.payer.pubkey(), true),
                AccountMeta::new(signature_pda, false),
                AccountMeta::new_readonly(solana_program::system_program::id(), false),
            ],
            data: {
                let mut instruction_data = Vec::new();
                processor::WOTSPlusInstruction::Sign {
                    private_key,
                    message: message.clone(),
                }
                .serialize(&mut instruction_data)
                .unwrap();
                instruction_data
            }
        };

        let transaction = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&context.payer.pubkey()),
            &[&context.payer],
            context.last_blockhash,
        );

        let result = context.banks_client.process_transaction_with_metadata(transaction).await;
        match result {
            Ok(result) => {
                let metadata = result.metadata.unwrap();
                let compute_units = metadata.compute_units_consumed;
                msg!("Sign compute units: {}", compute_units);
            }
            Err(err) => {
                msg!("Transaction failed: {:?}", err);
                panic!("Transaction should have succeeded");
            }
        }

        // Verify the signature was stored correctly
        let signature_account = context
            .banks_client
            .get_account(signature_pda)
            .await
            .unwrap()
            .unwrap();

        // Verify locally
        let local_signature = wots.sign(&private_key, &message).expect("valid length");

        let stored_data = processor::SignatureAccount::deserialize(&mut &signature_account.data[..])
            .expect("Failed to deserialize signature data");

        assert_eq!(stored_data.signature, local_signature);
    }

    #[tokio::test]
    async fn test_sign_and_verify_empty_signature() {
        let (program_test, program_id) = setup_test().await;
        let mut context = program_test.start_with_context().await;
        
        let message = (0..constants::MESSAGE_LEN).map(|i| i as u8).collect::<Vec<u8>>();
        
        let wots = WOTSPlus::new(processor::keccak256);
        let private_seed = [1u8; 32];
        let (public_key, _) = wots.generate_key_pair(&private_seed);
        
        let empty_signature = vec![0u8; constants::HASH_LEN * constants::NUM_SIGNATURE_CHUNKS];
        let empty_signature_chunks: Vec<[u8; constants::HASH_LEN]> = empty_signature
            .chunks(constants::HASH_LEN)
            .map(|chunk| {
                let mut arr = [0u8; constants::HASH_LEN];
                arr.copy_from_slice(chunk);
                arr
            })
            .collect();

        let instruction = processor::WOTSPlusInstruction::Verify {
            public_key: PublicKeyWrapper::from(public_key),
            message: message.clone(),
            signature: empty_signature_chunks
        };
    
        let mut instruction_data: Vec<u8> = Vec::new();
        instruction.serialize(&mut instruction_data).unwrap();

        let transaction = execute_transaction(
            &mut context,
            &program_id.pubkey(),
            instruction_data,
        ).await.unwrap();

        let result = context.banks_client.process_transaction_with_metadata(transaction).await;

        match result {
            Ok(result) => {
                let metadata = result.metadata.unwrap();
                let compute_units = metadata.compute_units_consumed;
                msg!("Verify Empty Signature compute units: {}", compute_units);
                msg!("Verify Empty Signature return data: {:?}", metadata.return_data);
                let binding = metadata.return_data.unwrap();
                assert_eq!(binding.data, vec![0]);
            }
            Err(err) => {
                msg!("Transaction failed: {:?}", err);
                panic!("Transaction should have succeeded");
            }
        }
    }

    #[tokio::test]
    async fn test_verify_valid_signature() {
        let (program_test, program_id) = setup_test().await;
        let mut context = program_test.start_with_context().await;
        
        // Generate key pair and signature locally first
        let wots = WOTSPlus::new(processor::keccak256);
        let private_seed = [1u8; 32];
        let (public_key, private_key) = wots.generate_key_pair(&private_seed);
        let message = (0..constants::MESSAGE_LEN).map(|i| i as u8).collect::<Vec<u8>>();
        let signature = wots.sign(&private_key, &message).expect("valid length");
        
        let instruction = processor::WOTSPlusInstruction::Verify {
            public_key: PublicKeyWrapper::from(public_key),
            message: message.clone(),
            signature: signature.to_vec(),
        };
        
        let mut instruction_data = Vec::new();
        instruction.serialize(&mut instruction_data).unwrap();
              
        let transaction = execute_transaction(
            &mut context,
            &program_id.pubkey(),
            instruction_data,
        ).await.unwrap();
       
        let transaction_result = context.banks_client.process_transaction_with_metadata(transaction).await.unwrap();
        let metadata = transaction_result.metadata.unwrap();
        let compute_units = metadata.compute_units_consumed;
        let return_data = metadata.return_data;

        msg!("Verify compute units: {}", compute_units);
        msg!("Verify return data: {:?}", return_data);

        // Check return data indicates success
        let binding = return_data.unwrap();
        assert_eq!(binding.data, vec![1]);
    }

    #[tokio::test]
    async fn test_verify_with_randomization_elements() {
        let (program_test, program_id) = setup_test().await;
        let mut context = program_test.start_with_context().await;
        
        // Generate key pair and signature locally first
        let wots = WOTSPlus::new(processor::keccak256);
        let private_seed = [1u8; 32];
        let (public_key, private_key) = wots.generate_key_pair(&private_seed);
        let message = (0..constants::MESSAGE_LEN).map(|i| i as u8).collect::<Vec<u8>>();
        let randomization_elements = wots.generate_randomization_elements(&public_key.public_seed);
        let signature = wots.sign(&private_key, &message).expect("valid length");
        
        let instruction = processor::WOTSPlusInstruction::VerifyWithRandomization {
            public_key_hash: public_key.public_key_hash,
            message: message.clone(),
            signature: signature.to_vec(),
            randomization_elements: randomization_elements.to_vec(),
        };
        
        let mut instruction_data = Vec::new();
        instruction.serialize(&mut instruction_data).unwrap();
        
        let transaction = execute_transaction(
            &mut context,
            &program_id.pubkey(),
            instruction_data,
        ).await.unwrap();
     
        let transaction_result = context.banks_client.process_transaction_with_metadata(transaction).await.unwrap();
        let metadata = transaction_result.metadata.unwrap();
        let compute_units = metadata.compute_units_consumed;
        let return_data = metadata.return_data;
        
        msg!("Verify with randomization compute units: {}", compute_units);
        msg!("Verify with randomization return data: {:?}", return_data);

        // Check return data indicates success
        let binding = return_data.unwrap();
        assert_eq!(binding.data, vec![1]);
    }

    #[tokio::test]
    async fn test_verify_many() {
        let (program_test, program_id) = setup_test().await;
        let mut context = program_test.start_with_context().await;
        let wots = WOTSPlus::new(processor::keccak256);
        let mut compute_units_total: u64 = 0;   
        let num_runs = 10;
        for i in 1..num_runs {
            let mut private_seed = [0u8; 32];
            private_seed[0] = i as u8;
            
            let (public_key, private_key) = wots.generate_key_pair(&private_seed);
            let message = processor::keccak256(format!("Hello World{}", i).as_bytes()).to_vec();
            let signature = wots.sign(&private_key, &message).expect("valid length");

            let instruction = processor::WOTSPlusInstruction::Verify {
                public_key: PublicKeyWrapper::from(public_key),
                message: message.clone(),
                signature: signature.to_vec(),
            };
            
            let mut instruction_data = Vec::new();
            instruction.serialize(&mut instruction_data).unwrap();
                  
            let transaction = execute_transaction(
                &mut context,
                &program_id.pubkey(),
                instruction_data,
            ).await.unwrap();
           
            let transaction_result = context.banks_client.process_transaction_with_metadata(transaction).await.unwrap();
            let metadata = transaction_result.metadata.unwrap();
            let compute_units = metadata.compute_units_consumed;
            compute_units_total += compute_units;
            let return_data = metadata.return_data;
       
            // Check return data indicates success
            let binding = return_data.unwrap();
            assert_eq!(binding.data, vec![1]);
            
        }

        msg!("Verify many average compute units: {}", compute_units_total as f64 / num_runs as f64);
    }

    #[tokio::test]
    async fn test_verify_many_with_randomization_elements() {
        let (program_test, program_id) = setup_test().await;
        let mut context = program_test.start_with_context().await;
        let wots = WOTSPlus::new(processor::keccak256);
        let mut compute_units_total: u64 = 0;
        let num_runs = 10;
        for i in 1..num_runs {
            let mut private_seed = [0u8; 32];
            private_seed[0] = i as u8;
            
            let (public_key, private_key) = wots.generate_key_pair(&private_seed);
            let message = processor::keccak256(format!("Hello World{}", i).as_bytes()).to_vec();
            let signature = wots.sign(&private_key, &message).expect("valid length");
            let randomization_elements = wots.generate_randomization_elements(&public_key.public_seed);
            
            let instruction = processor::WOTSPlusInstruction::VerifyWithRandomization {
                public_key_hash: public_key.public_key_hash,
                message: message.clone(),
                signature: signature.to_vec(),
                randomization_elements: randomization_elements.to_vec(),
            };
            
            let mut instruction_data = Vec::new();
            instruction.serialize(&mut instruction_data).unwrap();
            
            let transaction = execute_transaction(
                &mut context,
                &program_id.pubkey(),
                instruction_data,
            ).await.unwrap();
           
            let transaction_result = context.banks_client.process_transaction_with_metadata(transaction).await.unwrap();
            let metadata = transaction_result.metadata.unwrap();
            let compute_units = metadata.compute_units_consumed;
            compute_units_total += compute_units;
            let return_data = metadata.return_data;
       
            // Check return data indicates success
            let binding = return_data.unwrap();
            assert_eq!(binding.data, vec![1]);
        }

        msg!("Verify many with randomization average compute units: {}", compute_units_total as f64 / num_runs as f64);
    }

}

pub mod sphincs_plus_c_solana_test {
    use borsh::BorshSerialize;
    use hashsigs_rs::{sphincs_plus_c_keygen, sphincs_plus_c_sign, SphincsPlusCSigningKey};
    use hashsigs_rs_solana::processor::WOTSPlusInstruction;
    use hashsigs_rs_solana::sphincs_plus_c::StatelessSignatureDto;
    use solana_sdk::{instruction::Instruction, msg, pubkey::Pubkey, signer::Signer, transaction::Transaction};

    use super::*;

    async fn setup_test() -> (ProgramTest, Keypair) {
        let program_id = Keypair::new();
        let mut program_test = ProgramTest::new(
            "hashsigs_rs_solana",
            program_id.pubkey(),
            processor!(process_instruction),
        );
        program_test.set_compute_max_units(1_400_000);
        // Same SBF opt-in as the legacy suite above.
        program_test.prefer_bpf(std::env::var_os("SBF_OUT_DIR").is_some());
        (program_test, program_id)
    }

    async fn execute_transaction(
        context: &mut ProgramTestContext,
        program_id: &Pubkey,
        data: Vec<u8>,
    ) -> Transaction {
        let instruction = Instruction {
            program_id: *program_id,
            accounts: vec![],
            data,
        };
        Transaction::new_signed_with_payer(
            &[instruction],
            Some(&context.payer.pubkey()),
            &[&context.payer],
            context.last_blockhash,
        )
    }

    // Deterministic test-only seed derivation via solana_program's keccak
    // (an independent oracle already used elsewhere in this crate), not the
    // library under test.
    fn derive32(domain: &[u8], seed: &[u8]) -> [u8; 32] {
        solana_program::keccak::hashv(&[domain, seed]).to_bytes()
    }

    /// Independent SPHINCS+C keypair (256s default profile) + ERC-7913 key
    /// bytes (`pk_seed || hypertree_root`), derived through the public
    /// `hashsigs_rs` API only.
    fn test_keypair(seed: &[u8]) -> (SphincsPlusCSigningKey, [u8; 64]) {
        let stateless_sk_seed = derive32(b"sphincs-plus-c-solana-sk-seed", seed);
        let stateless_prf_seed = derive32(b"sphincs-plus-c-solana-prf-seed", seed);
        let pk_seed = derive32(b"sphincs-plus-c-solana-pk-seed", seed);
        let (signing_key, public_key) =
            sphincs_plus_c_keygen(stateless_sk_seed, stateless_prf_seed, pk_seed);
        let mut key = [0u8; 64];
        key[..32].copy_from_slice(&public_key.pk_seed);
        key[32..].copy_from_slice(&public_key.hypertree_root);
        (signing_key, key)
    }

    #[tokio::test]
    async fn test_sphincs_plus_c_verify_valid_signature() {
        let (program_test, program_id) = setup_test().await;
        let mut context = program_test.start_with_context().await;

        let (signing_key, key) = test_keypair(b"sphincs-plus-c solana happy path");
        let hash = derive32(b"sphincs-plus-c-solana-message", b"happy path");
        let signature = sphincs_plus_c_sign(&signing_key, &hash).expect("sign");

        let instruction = WOTSPlusInstruction::SphincsPlusCVerify {
            key,
            hash,
            signature: StatelessSignatureDto::from(signature),
        };
        let mut instruction_data = Vec::new();
        instruction.serialize(&mut instruction_data).unwrap();

        let transaction =
            execute_transaction(&mut context, &program_id.pubkey(), instruction_data).await;
        let transaction_result = context
            .banks_client
            .process_transaction_with_metadata(transaction)
            .await
            .unwrap();
        let metadata = transaction_result.metadata.unwrap();
        msg!(
            "SPHINCS+C verify (256s) compute units: {}",
            metadata.compute_units_consumed
        );

        let return_data = metadata.return_data.unwrap();
        assert_eq!(return_data.data, vec![1]);
    }

    #[tokio::test]
    async fn test_sphincs_plus_c_verify_rejects_tampered_hash() {
        let (program_test, program_id) = setup_test().await;
        let mut context = program_test.start_with_context().await;

        let (signing_key, key) = test_keypair(b"sphincs-plus-c solana tampered");
        let hash = derive32(b"sphincs-plus-c-solana-message", b"tampered");
        let signature = sphincs_plus_c_sign(&signing_key, &hash).expect("sign");

        let mut tampered_hash = hash;
        tampered_hash[0] ^= 0xff;

        let instruction = WOTSPlusInstruction::SphincsPlusCVerify {
            key,
            hash: tampered_hash,
            signature: StatelessSignatureDto::from(signature),
        };
        let mut instruction_data = Vec::new();
        instruction.serialize(&mut instruction_data).unwrap();

        let transaction =
            execute_transaction(&mut context, &program_id.pubkey(), instruction_data).await;
        let transaction_result = context
            .banks_client
            .process_transaction_with_metadata(transaction)
            .await
            .unwrap();
        let metadata = transaction_result.metadata.unwrap();
        msg!(
            "SPHINCS+C verify (tampered hash) compute units: {}",
            metadata.compute_units_consumed
        );

        let return_data = metadata.return_data.unwrap();
        assert_eq!(return_data.data, vec![0]);
    }

    #[tokio::test]
    async fn test_shrincs_verify_stateless_valid_signature() {
        use hashsigs_rs::shrincs::{ActionContext, ShrincsSigner, ShrincsVerifier};
        use hashsigs_rs_solana::sphincs_plus_c::{ActionContextDto, ShrincsPublicKeyDto};

        let (program_test, program_id) = setup_test().await;
        let mut context = program_test.start_with_context().await;

        let (signing_key, public_key) =
            ShrincsSigner::keygen(b"shrincs solana hybrid stateless", 4096).expect("keygen");
        let commitment: [u8; 32] = public_key
            .public_key_commitment
            .clone()
            .try_into()
            .expect("commitment is 32 bytes");
        let action_context = ActionContext {
            domain_separator: derive32(b"shrincs-solana-domain", b"1"),
            nonce: derive32(b"shrincs-solana-nonce", b"1"),
            key_version: [0u8; 32],
            action_type: derive32(b"shrincs-solana-action", b"1"),
            payload_hash: derive32(b"shrincs-solana-payload", b"1"),
        };
        let verifier = ShrincsVerifier::new();
        let message = verifier.stateless_action_message_hash(commitment, &action_context);
        let signature =
            ShrincsSigner::sign_stateless_raw(&signing_key, &message).expect("sign");

        let instruction = WOTSPlusInstruction::ShrincsVerifyStateless {
            expected_public_key_commitment: commitment,
            public_key: ShrincsPublicKeyDto::from(public_key),
            context: ActionContextDto::from(action_context),
            signature: StatelessSignatureDto::from(signature),
        };
        let mut instruction_data = Vec::new();
        instruction.serialize(&mut instruction_data).unwrap();

        let transaction =
            execute_transaction(&mut context, &program_id.pubkey(), instruction_data).await;
        let transaction_result = context
            .banks_client
            .process_transaction_with_metadata(transaction)
            .await
            .unwrap();
        let metadata = transaction_result.metadata.unwrap();
        msg!(
            "SHRINCS hybrid stateless verify (256s) compute units: {}",
            metadata.compute_units_consumed
        );

        let return_data = metadata.return_data.unwrap();
        assert_eq!(return_data.data, vec![1]);
    }
}
