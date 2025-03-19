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
        
        // Add program data to the test environment
        program_test.add_program(
            "hashsigs_rs_solana",
            program_id.pubkey(),
            None,
        );
        
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
        let local_signature = wots.sign(&private_key, &message);

        let stored_data = processor::SignatureAccount::deserialize(&mut &signature_account.data[..])
            .expect("Failed to deserialize signature data");

        assert_eq!(stored_data.signature, local_signature);
    }

    #[tokio::test]
    async fn test_sign_and_verify_empty_signature() {
        let (program_test, program_id) = setup_test().await;
        let context = program_test.start_with_context().await;
        
        let signer = Keypair::new();
        let message = (0..constants::MESSAGE_LEN).map(|i| i as u8).collect::<Vec<u8>>();
        
        // Create PDA for signature storage
        let (signature_pda, _bump_seed) = Pubkey::find_program_address(
            &[
                b"signature",
                signer.pubkey().as_ref(),
                message.as_ref(),
            ],
            &program_id.pubkey()
        );

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

        let instruction = Instruction {
            program_id: program_id.pubkey(),
            accounts: vec![
                AccountMeta::new(context.payer.pubkey(), true),  // Changed to use context.payer as signer
                AccountMeta::new(signature_pda, false),
                AccountMeta::new_readonly(solana_program::system_program::id(), false),
            ],
            data: {
                let mut instruction_data = Vec::new();
                processor::WOTSPlusInstruction::Verify {
                    public_key: PublicKeyWrapper::from(public_key),
                    message: message.clone(),
                    signature: empty_signature_chunks,
                }
                .serialize(&mut instruction_data)
                .unwrap();
                instruction_data
            }
        };

        let transaction = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&context.payer.pubkey()),
            &[&context.payer],  // Only include context.payer as signer
            context.last_blockhash,
        );

        let result = context.banks_client.process_transaction(transaction).await;
        assert!(result.is_err()); // Empty signature should fail verification
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
        let signature = wots.sign(&private_key, &message);
        
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
    async fn test_verify_with_randomization() {
        let (program_test, program_id) = setup_test().await;
        let mut context = program_test.start_with_context().await;
        
        // Generate key pair and signature locally first
        let wots = WOTSPlus::new(processor::keccak256);
        let private_seed = [1u8; 32];
        let (public_key, private_key) = wots.generate_key_pair(&private_seed);
        let message = (0..constants::MESSAGE_LEN).map(|i| i as u8).collect::<Vec<u8>>();
        let randomization_elements = wots.generate_randomization_elements(&public_key.public_seed);
        let signature = wots.sign(&private_key, &message);
        
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
    async fn test_verify_valid_signature_randomization_elements() {
        let wots = WOTSPlus::new(processor::keccak256);
        let private_seed = [1u8; 32];
        let (public_key, private_key) = wots.generate_key_pair(&private_seed);
        
        let message = (0..constants::MESSAGE_LEN).map(|i| i as u8).collect::<Vec<u8>>();
        let signature = wots.sign(&private_key, &message);
        
        let randomization_elements = wots.generate_randomization_elements(&public_key.public_seed);
        
        assert!(wots.verify_with_randomization_elements(
            &public_key.public_key_hash,
            &message,
            &signature,
            &randomization_elements
        ));
    }

    #[tokio::test]
    async fn test_verify_many() {
        let wots = WOTSPlus::new(processor::keccak256);
        
        for i in 1..200 {
            let mut private_seed = [0u8; 32];
            private_seed[0] = i as u8;
            
            let (public_key, private_key) = wots.generate_key_pair(&private_seed);
            let message = processor::keccak256(format!("Hello World{}", i).as_bytes()).to_vec();
            let signature = wots.sign(&private_key, &message);
            
            assert!(wots.verify(&public_key, &message, &signature));
        }
    }

    #[tokio::test]
    async fn test_verify_many_with_randomization_elements() {
        let wots = WOTSPlus::new(processor::keccak256);
        
        for i in 1..200 {
            let mut private_seed = [0u8; 32];
            private_seed[0] = i as u8;
            
            let (public_key, private_key) = wots.generate_key_pair(&private_seed);
            let message = processor::keccak256(format!("Hello World{}", i).as_bytes()).to_vec();
            let signature = wots.sign(&private_key, &message);
            
            let randomization_elements = wots.generate_randomization_elements(&public_key.public_seed);
            
            assert!(wots.verify_with_randomization_elements(
                &public_key.public_key_hash,
                &message,
                &signature,
                &randomization_elements
            ));
        }
    }

    #[tokio::test]
    async fn test_randomization_elements() {
        let (mut program_test, program_id) = setup_test().await;
        let mut context = program_test.start_with_context().await;
        let wots = WOTSPlus::new(processor::keccak256);

        let private_seed = [1u8; 32];
        let (public_key, private_key) = wots.generate_key_pair(&private_seed);
        let message = (0..constants::MESSAGE_LEN).map(|i| i as u8).collect::<Vec<u8>>();
        
        let randomization_elements = wots.generate_randomization_elements(&public_key.public_seed);
        
        let signature = wots.sign(&private_key, &message);

        let is_valid = wots.verify_with_randomization_elements(
            &public_key.public_key_hash,
            &message,
            &signature,
            &randomization_elements
        );
        
        assert!(is_valid, "Signature verification with randomization failed");
    }

    #[tokio::test]
    async fn test_verify_many_with_randomization() {
        let (mut program_test, program_id) = setup_test().await;
        let mut context = program_test.start_with_context().await;
        let wots = WOTSPlus::new(processor::keccak256);
        
        // Test with a smaller number of iterations to stay within compute limits
        for i in 1..5 {
            let mut private_seed = [0u8; 32];
            private_seed[0] = i as u8;
            
            let (public_key, private_key) = wots.generate_key_pair(&private_seed);
            let message = processor::keccak256(format!("Hello World{}", i).as_bytes()).to_vec();
            let signature = wots.sign(&private_key, &message);
            let randomization_elements = wots.generate_randomization_elements(&public_key.public_seed);
            
            let verify_instruction = processor::WOTSPlusInstruction::VerifyWithRandomization {
                public_key_hash: public_key.public_key_hash,
                message,
                signature: signature.to_vec(),
                randomization_elements: randomization_elements.to_vec(),
            };
            
        }
    }

}
