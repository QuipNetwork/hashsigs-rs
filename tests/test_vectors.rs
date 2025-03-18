use hashsigs_rs::{WOTSPlus, PublicKey};
use serde_json::Value;
use solana_program::keccak::hash as keccak256_hash;
use std::fs;

fn keccak256(data: &[u8]) -> [u8; 32] {
    keccak256_hash(data).to_bytes()
}

fn hex_to_bytes(hex: &str) -> [u8; 32] {
    let hex = hex.trim_start_matches("0x");
    let mut result = [0u8; 32];
    for i in 0..32 {
        let byte_str = &hex[i*2..i*2+2];
        result[i] = u8::from_str_radix(byte_str, 16).unwrap();
    }
    result
}

#[test]
fn test_wotsplus_keccak256_vectors() {
    // Read the test vectors file
    let test_vectors = fs::read_to_string("tests/test_vectors/wotsplus_keccak256.json")
        .expect("Failed to read test vectors file");
    let vectors: Value = serde_json::from_str(&test_vectors)
        .expect("Failed to parse test vectors JSON");

    let wots = WOTSPlus::new(keccak256);

    // Iterate through each test vector
    for (vector_name, vector) in vectors.as_object().unwrap() {
        println!("Testing {}", vector_name);

        // Convert hex strings to bytes
        let private_key = hex_to_bytes(vector["privateKey"].as_str().unwrap());
        let message = hex_to_bytes(vector["message"].as_str().unwrap());
        let expected_public_key_hex = vector["publicKey"].as_str().unwrap();
        let expected_public_key_hex = expected_public_key_hex.trim_start_matches("0x");
        
        // Split into public seed and public key hash
        let mut public_seed = [0u8; 32];
        let mut public_key_hash = [0u8; 32];
        
        for i in 0..32 {
            let byte_str = &expected_public_key_hex[i*2..i*2+2];
            public_seed[i] = u8::from_str_radix(byte_str, 16).unwrap();
            
            let byte_str = &expected_public_key_hex[(i+32)*2..(i+32)*2+2];
            public_key_hash[i] = u8::from_str_radix(byte_str, 16).unwrap();
        }
        
        let expected_public_key = PublicKey {
            public_seed,
            public_key_hash,
        };

        // Convert signature segments to bytes
        let expected_signature: Vec<[u8; 32]> = vector["signature"]
            .as_array()
            .unwrap()
            .iter()
            .map(|seg| hex_to_bytes(seg.as_str().unwrap()))
            .collect();

        // Generate key pair and verify it matches expected public key
        let public_key = wots.get_public_key(&private_key);
        assert_eq!(
            public_key.to_bytes(),
            expected_public_key.to_bytes(),
            "Public key mismatch for {}",
            vector_name
        );

        // Sign message and verify signature matches expected signature
        let signature = wots.sign(&private_key, &message);
        assert_eq!(
            signature.to_vec(),
            expected_signature,
            "Signature mismatch for {}",
            vector_name
        );

        // Verify signature
        let is_valid = wots.verify(&public_key, &message, &signature);
        assert!(is_valid, "Signature verification failed for {}", vector_name);
    }
}
