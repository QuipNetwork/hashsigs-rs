//! WOTS+ (Winternitz One-Time Signature Plus) implementation

/// Hash function type for WOTS+
type HashFn = fn(&[u8]) -> [u8; 32];

/// Constants from the WOTS+ implementation
pub mod constants {
    /// HashLen: The WOTS+ `n` security parameter which is the size 
    /// of the hash function output in bytes.
    /// This is 32 for keccak256 (256 / 8 = 32)
    pub const HASH_LEN: usize = 32;

    /// MessageLen: The WOTS+ `m` parameter which is the size 
    /// of the message to be signed in bytes 
    /// (and also the size of our hash function)
    ///
    /// This is 32 for keccak256 (256 / 8 = 32)
    ///
    /// Note that this is not the message length itself as, like 
    /// with most signatures, we hash the message and then compute
    /// the signature on the hash of the message.
    pub const MESSAGE_LEN: usize = HASH_LEN;

    /// ChainLen: The WOTS+ `w`(internitz) parameter. 
    /// This corresponds to the number of hash chains for each public
    /// key segment and the base-w representation of the message
    /// and checksum.
    /// 
    /// A larger value means a smaller signature size but a longer
    /// computation time.
    /// 
    /// For XMSS (rfc8391) this value is limited to 4 or 16 because
    /// they simplify the algorithm and offer the best trade-offs.
    pub const CHAIN_LEN: usize = 16;

    /// lg(ChainLen) so we don't calculate it (lg(16) == 4)
    pub const LG_CHAIN_LEN: usize = {
        // Using const fn ilog2 to calculate log2(CHAIN_LEN) at compile time
        CHAIN_LEN.ilog2() as usize
    };

    /// NumMessageChunks: the `len_1` parameter which is the number of
    /// message chunks. This is 
    /// ceil(8n / lg(w)) -> ceil(8 * HASH_LEN / lg(CHAIN_LEN))
    /// or ceil(32*8 / lg(16)) -> 256 / 4 = 64
    /// Python:  math.ceil(32*8 / math.log(16,2))
    pub const NUM_MESSAGE_CHUNKS: usize = {
        // Since HASH_LEN = 32, CHAIN_LEN = 16 (2^4), we know:
        // 32*8 = 256, log2(16) = 4
        // 256/4 = 64
        (8 * HASH_LEN).div_ceil(LG_CHAIN_LEN)
    };

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_num_message_chunks() {
            assert_eq!(NUM_MESSAGE_CHUNKS, 64);
        }
    }

    /// NumChecksumChunks: the `len_2` parameter which is the number of
    /// checksum chunks. This is
    /// floor(lg(len_1 * (w - 1)) / lg(w)) + 1
    /// -> floor(lg(NUM_MESSAGE_CHUNKS * (CHAIN_LEN - 1)) / lg(CHAIN_LEN)) + 1
    /// -> floor(lg(64 * 15) / lg(16)) + 1 = 3
    /// Python: math.floor(math.log(64 * 15, 2) / math.log(16, 2)) + 1
    pub const NUM_CHECKSUM_CHUNKS: usize = {
        // Since NUM_MESSAGE_CHUNKS = 64, CHAIN_LEN = 16:
        // 64 * 15 = 960
        // log2(960) ≈ 9.907
        // log2(16) = 4
        // floor(9.907 / 4) + 1 = floor(2.477) + 1 = 3
        ((NUM_MESSAGE_CHUNKS * (CHAIN_LEN - 1)).ilog2() as usize / LG_CHAIN_LEN) + 1
    };

    pub const NUM_SIGNATURE_CHUNKS: usize = NUM_MESSAGE_CHUNKS + NUM_CHECKSUM_CHUNKS;
    /// Size of signature in bytes
    pub const SIGNATURE_SIZE: usize = NUM_SIGNATURE_CHUNKS * HASH_LEN;
    /// Size of public key in bytes
    pub const PUBLIC_KEY_SIZE: usize = HASH_LEN * 2;
    /// PRF input size (prefix + seed + index)
    pub const PRF_INPUT_SIZE: usize = 1 + HASH_LEN + 2;
}

/// PublicKey consists of two parts:
/// 1. The public seed used to generate randomization elements
/// 2. The hash of all public key segments concatenated together
#[derive(Debug, Clone, Copy)]
pub struct PublicKey {
    pub public_seed: [u8; constants::HASH_LEN],
    pub public_key_hash: [u8; constants::HASH_LEN],
}

impl PublicKey {
    /// Convert the public key to bytes
    /// Returns a byte array of size PUBLIC_KEY_SIZE containing the public seed followed by the public key hash
    pub fn to_bytes(&self) -> [u8; constants::PUBLIC_KEY_SIZE] {
        let mut result = [0u8; constants::PUBLIC_KEY_SIZE];
        result[..constants::HASH_LEN].copy_from_slice(&self.public_seed);
        result[constants::HASH_LEN..].copy_from_slice(&self.public_key_hash);
        result
    }

    /// Create a PublicKey from bytes
    /// Returns None if the input is not of the correct length
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != constants::PUBLIC_KEY_SIZE {
            return None;
        }
        let mut public_seed = [0u8; constants::HASH_LEN];
        let mut public_key_hash = [0u8; constants::HASH_LEN];
        
        public_seed.copy_from_slice(&bytes[..constants::HASH_LEN]);
        public_key_hash.copy_from_slice(&bytes[constants::HASH_LEN..]);
        
        Some(PublicKey {
            public_seed,
            public_key_hash,
        })
    }
}

pub struct WOTSPlus {
    hash_fn: HashFn,
}

impl WOTSPlus {
    /// Create a new WOTS+ instance with the specified hash function
    pub fn new(hash_fn: HashFn) -> Self {
        Self { hash_fn }
    }

    /// Generate randomization elements from seed and index
    /// Similar to XMSS RFC 8391 section 5.1
    /// Uses a prefix byte (0x03) to domain separate the PRF
    fn prf(&self, seed: &[u8; constants::HASH_LEN], index: u16) -> [u8; constants::HASH_LEN] {
        let mut input = [0u8; constants::PRF_INPUT_SIZE];
        input[0] = 0x03; // prefix to domain separate
        input[1..33].copy_from_slice(seed); // the seed input
        input[33..].copy_from_slice(&index.to_be_bytes()); // the index/position
        (self.hash_fn)(&input)
    }

    /// Generate randomization elements from public seed
    /// These elements are used in the chain function to randomize each hash
    pub fn generate_randomization_elements(
        &self,
        public_seed: &[u8; constants::HASH_LEN]
    ) -> Vec<[u8; constants::HASH_LEN]> {
        (0..constants::NUM_SIGNATURE_CHUNKS)
            .map(|i| self.prf(public_seed, i as u16))
            .collect()
    }

    /// XOR two 32-byte arrays
    fn xor(a: &[u8; constants::HASH_LEN], b: &[u8; constants::HASH_LEN]) -> [u8; constants::HASH_LEN] {
        let mut result = [0u8; constants::HASH_LEN];
        for i in 0..constants::HASH_LEN {
            result[i] = a[i] ^ b[i];
        }
        result
    }

    /// Chain function (c_k^i function)
    /// This is the core of WOTS+, implementing the hash chain with randomization
    /// The chain function takes the previous chain output, XORs it with a randomization element,
    /// and then hashes the result. This is repeated 'steps' times.
    fn chain(
        &self,
        prev_chain_out: &[u8; constants::HASH_LEN],
        randomization_elements: &[[u8; constants::HASH_LEN]],
        index: u16,
        steps: u16,
    ) -> [u8; constants::HASH_LEN] {
        let mut chain_out = *prev_chain_out;
        for i in 1..=steps {
            let xored = Self::xor(&chain_out, &randomization_elements[(i + index) as usize]);
            chain_out = (self.hash_fn)(&xored);
        }
        chain_out
    }

    /// Compute message hash chain indexes
    /// This function performs two main tasks:
    /// 1. Convert the message to base-w representation (or base of CHAIN_LEN representation)
    /// 2. Compute and append the checksum in base-w representation
    /// 
    /// These numbers are used to index into each hash chain which is rooted at a secret key segment
    /// and produces a public key segment at the end of the chain. Verification of a signature means
    /// using these indexes into each hash chain to recompute the corresponding public key segment.
    fn compute_message_hash_chain_indexes(&self, message: &[u8]) -> Vec<u8> {
        if message.len() != constants::MESSAGE_LEN {
            panic!("Message length must be {} bytes", constants::MESSAGE_LEN);
        }

        let mut chain_segments_indexes = Vec::with_capacity(constants::NUM_SIGNATURE_CHUNKS);
        let mut idx = 0;
        
        // Convert message to base-w representation
        for byte in message {
            chain_segments_indexes[idx] = byte >> 4;
            chain_segments_indexes[idx + 1] = byte & 0x0f;
            idx += 2;
        }

        // Compute checksum
        let mut checksum: u32 = 0;
        for &value in &chain_segments_indexes[..constants::NUM_MESSAGE_CHUNKS] {
            checksum += constants::CHAIN_LEN as u32 - 1 - value as u32
        }

        // Convert checksum to base-w and append
        // This is left-shifting the checksum to ensure proper alignment when
        // converting to base-w representation
        for i in (0..constants::NUM_CHECKSUM_CHUNKS).rev() {
            let shift = i * constants::LG_CHAIN_LEN as usize;
            chain_segments_indexes[idx] = ((checksum >> shift) & (constants::CHAIN_LEN as u32 - 1)) as u8;
            idx += 1;
        }

        chain_segments_indexes
    }

    /// Generate public key from a private key
    pub fn get_public_key(&self, private_key: &[u8; constants::HASH_LEN]) -> PublicKey {
        let public_seed = self.prf(private_key, 0);
        let randomization_elements = self.generate_randomization_elements(&public_seed);
        let function_key = randomization_elements[0];

        let mut public_key_segments = Vec::with_capacity(constants::SIGNATURE_SIZE);

        for i in 0..constants::NUM_SIGNATURE_CHUNKS {
            let mut to_hash = vec![0u8; constants::HASH_LEN * 2];
            to_hash[..constants::HASH_LEN].copy_from_slice(&function_key);
            to_hash[constants::HASH_LEN..].copy_from_slice(&self.prf(private_key, (i + 1) as u16));
            
            let secret_key_segment = (self.hash_fn)(&to_hash);
            let segment = self.chain(
                &secret_key_segment,
                &randomization_elements,
                0,
                (constants::CHAIN_LEN - 1) as u16,
            );
            
            public_key_segments.extend_from_slice(&segment);
        }

        let public_key_hash = (self.hash_fn)(&public_key_segments);
        
        PublicKey {
            public_seed,
            public_key_hash,
        }
    }


    /// Generate a WOTS+ key pair
    /// The process works as follows:
    /// 1. Generate private key from seed
    /// 2. Generate public seed from private key
    /// 3. Generate randomization elements from public seed
    /// 4. For each signature chunk:
    ///    a. Generate a secret key segment
    ///    b. Run the chain function to the end to get the public key segment
    /// 5. Hash all public key segments together to get the final public key
    pub fn generate_key_pair(&self, private_seed: &[u8; constants::HASH_LEN]) -> (PublicKey, [u8; constants::HASH_LEN]) {
        let private_key = (self.hash_fn)(private_seed);
        let public_key = self.get_public_key(&private_key);
        (public_key, private_key)
    }

    /// Sign a message with a WOTS+ private key
    /// The process works as follows:
    /// 1. Generate public seed from private key
    /// 2. Generate randomization elements from public seed
    /// 3. Convert message to chain indexes (including checksum)
    /// 4. For each chain index:
    ///    a. Generate the secret key segment
    ///    b. Run the chain function to the index position
    pub fn sign(&self, private_key: &[u8; constants::HASH_LEN], message: &[u8]) -> Vec<[u8; constants::HASH_LEN]> {
        if message.len() != constants::MESSAGE_LEN {
            panic!("Message length must be {} bytes", constants::MESSAGE_LEN);
        }

        let public_seed = self.prf(private_key, 0);
        let randomization_elements = self.generate_randomization_elements(&public_seed);
        let function_key = randomization_elements[0];
        
        let chain_segments = self.compute_message_hash_chain_indexes(message);
        let mut signature = Vec::with_capacity(constants::NUM_SIGNATURE_CHUNKS);

        for (i, &chain_idx) in chain_segments.iter().enumerate() {
            let mut to_hash = vec![0u8; constants::HASH_LEN * 2];
            to_hash[..constants::HASH_LEN].copy_from_slice(&function_key);
            to_hash[constants::HASH_LEN..].copy_from_slice(&self.prf(private_key, (i + 1) as u16));
            
            let secret_key_segment = (self.hash_fn)(&to_hash);
            let sig_segment = self.chain(
                &secret_key_segment,
                &randomization_elements,
                0,
                chain_idx as u16,
            );
            signature.push(sig_segment);
        }

        signature
    }

    /// Verify a WOTS+ signature
    /// The verification process works as follows:
    /// 1. The first part of the publicKey is a public seed used to regenerate the randomization elements
    /// 2. The second part of the publicKey is the hash of the NumMessageChunks + NumChecksumChunks public key segments
    /// 3. Convert the Message to "base-w" representation (or base of ChainLen representation)
    /// 4. Compute and add the checksum
    /// 5. Run the chain function on each segment to reproduce each public key segment
    /// 6. Hash all public key segments together to recreate the original public key
    pub fn verify(&self, public_key: &PublicKey, message: &[u8], signature: &Vec<[u8; constants::HASH_LEN]>) -> bool {
        
        if message.len() != constants::MESSAGE_LEN {
            return false;
        }
        if signature.len() != constants::NUM_SIGNATURE_CHUNKS {
            return false;
        }

        let randomization_elements = self.generate_randomization_elements(&public_key.public_seed);
        
        let chain_segments = self.compute_message_hash_chain_indexes(message);
        
        let mut public_key_segments = Vec::with_capacity(constants::SIGNATURE_SIZE);

        // Compute each public key segment. These are done by taking the signature, which is prevChainOut at chainIdx,
        // and completing the hash chain via the chain function to recompute the public key segment.
        for (i, &chain_idx) in chain_segments.iter().enumerate() {
            let num_iterations = (constants::CHAIN_LEN - 1 - chain_idx as usize) as u16;
            let segment = self.chain(
                &signature[i],
                &randomization_elements,
                chain_idx as u16,
                num_iterations,
            );
            
            public_key_segments.extend_from_slice(&segment);
        }

        // Hash all public key segments together to recreate the original public key
        let computed_hash = (self.hash_fn)(&public_key_segments);
        
        // Compare computed hash with stored public key hash
        computed_hash == public_key.public_key_hash
    }

    /// Verify a WOTS+ signature using pre-computed randomization elements
    /// This is an optimization that allows reusing the randomization elements
    /// when verifying multiple signatures with the same public seed
    pub fn verify_with_randomization_elements(
        &self,
        public_key_hash: &[u8; constants::HASH_LEN],
        message: &[u8],
        signature: &Vec<[u8; constants::HASH_LEN]>,
        randomization_elements: &Vec<[u8; constants::HASH_LEN]>,
    ) -> bool {
        if message.len() != constants::MESSAGE_LEN {
            return false;
        }
        if signature.len() != constants::NUM_SIGNATURE_CHUNKS {
            return false;
        }
        if randomization_elements.len() != constants::NUM_SIGNATURE_CHUNKS {
            return false;
        }

        let chain_segments = self.compute_message_hash_chain_indexes(message);
        let mut public_key_segments = [0u8; constants::SIGNATURE_SIZE];
        
        // Compute each public key segment using the pre-computed randomization elements
        for (i, &chain_idx) in chain_segments.iter().enumerate() {
            let num_iterations = (constants::CHAIN_LEN - 1 - chain_idx as usize) as u16;
            let segment = self.chain(
                &signature[i],
                randomization_elements,
                chain_idx as u16,
                num_iterations,
            );
            
            let offset = i * constants::HASH_LEN;
            public_key_segments[offset..offset + constants::HASH_LEN].copy_from_slice(&segment);
        }

        // Hash all public key segments together and compare with the provided hash
        let computed_hash = (self.hash_fn)(&public_key_segments);
        computed_hash == *public_key_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock hash function for testing
    fn mock_hash(data: &[u8]) -> [u8; 32] {
        let mut output = [0u8; 32];
        for (i, &byte) in data.iter().enumerate().take(32) {
            output[i] = byte;
        }
        output
    }

    #[test]
    fn test_constants() {
        assert_eq!(constants::HASH_LEN, 32);
        assert_eq!(constants::MESSAGE_LEN, 32);
        assert_eq!(constants::CHAIN_LEN, 16);
        assert_eq!(constants::NUM_MESSAGE_CHUNKS, 64);
        assert_eq!(constants::NUM_CHECKSUM_CHUNKS, 3);
        assert_eq!(constants::NUM_SIGNATURE_CHUNKS, 67);
    }

    #[test]
    fn test_key_generation_and_signing() {
        let wots = WOTSPlus::new(mock_hash);
        let private_seed = [1u8; 32];
        let (public_key, private_key) = wots.generate_key_pair(&private_seed);
        
        let message = [2u8; constants::MESSAGE_LEN];
        let signature = wots.sign(&private_key, &message);
        
        assert!(wots.verify(&public_key, &message, &signature));
    }

    #[test]
    fn test_invalid_message_length() {
        let wots = WOTSPlus::new(mock_hash);
        let private_seed = [1u8; 32];
        let (public_key, _) = wots.generate_key_pair(&private_seed);
        
        let invalid_message = [2u8; constants::MESSAGE_LEN + 1];
        let signature: Vec<[u8; 32]> = vec![[0u8; 32]; constants::NUM_SIGNATURE_CHUNKS];
        assert!(!wots.verify(&public_key, &invalid_message, &signature));
    }

    #[test]
    fn test_invalid_signature_length() {
        let wots = WOTSPlus::new(mock_hash);
        let private_seed = [1u8; 32];
        let (public_key, _) = wots.generate_key_pair(&private_seed);
        
        let message = [2u8; constants::MESSAGE_LEN];
        let signature: Vec<[u8; 32]> = vec![[0u8; 32]; constants::NUM_SIGNATURE_CHUNKS];
        assert!(!wots.verify(&public_key, &message, &signature));
    }

    #[test]
    fn test_public_key_serialization() {
        let public_key = PublicKey {
            public_seed: [1u8; constants::HASH_LEN],
            public_key_hash: [2u8; constants::HASH_LEN],
        };
        
        let bytes = public_key.to_bytes();
        let recovered = PublicKey::from_bytes(&bytes).unwrap();
        
        assert_eq!(recovered.public_seed, public_key.public_seed);
        assert_eq!(recovered.public_key_hash, public_key.public_key_hash);
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_num_message_chunks() {
            assert_eq!(constants::NUM_MESSAGE_CHUNKS, 64);
        }

        #[test]
        fn test_num_checksum_chunks() {
            assert_eq!(constants::NUM_CHECKSUM_CHUNKS, 3);
        }
    }
}
