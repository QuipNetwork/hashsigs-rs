# hashsig

Repository| Field | Value |
|-------|-------|-------|
|hashsig-ts| **Clone** | `git clone git@gitlab.com:piqued/hashsigs-ts.git` |
| | **URL** | https://gitlab.com/piqued/hashsigs-ts.git |
|hashsig-solidity| **Clone** | `git clone git@gitlab.com:piqued/hashsigs-solidity.git` |
| | **URL** | https://gitlab.com/piqued/hashsigs-solidity.git |
|hashsig-rs| **Clone** | `git clone git@gitlab.com:piqued/hashsigs-rs.git` |
| | **URL** | https://gitlab.com/piqued/hashsigs-rs.git |
|hashsig-cpp| **Clone** | `git clone git@gitlab.com:piqued/hashsigs-cpp.git` |
| | **URL** | https://gitlab.com/piqued/hashsigs-cpp.git |
|hashsig-py| **Clone** | `git clone git@gitlab.com:piqued/hashsigs-py.git` |
| | **URL** | https://gitlab.com/piqued/hashsigs-py.git |

## Description

The hashsig project provides a family of consistent WOTS+ implementations across multiple languages (TypeScript, Solidity, Rust, C++, and Python), with the TypeScript version serving as the reference implementation. While inspired by the standardized WOTS+ construction in RFC 8391 (as used in XMSS), these implementations intentionally follow a lighter-weight design closer to the original 2017 WOTS+ paper, simplifying PRF inputs, address handling, and mask derivation to better fit practical constraints such as smart contracts and cross-platform portability, while preserving the core cryptographic structure and correctness of WOTS+ signing and verification.


## Table of Contents


- [1. Overview](#1-overview)

- [2. Entities](#2-entities)
  - [2.1. Constants](#21-constants)
  - [2.2. PublicKey](#22-publickey)
  - [2.3. WOTSPlus](#23-wotsplus)
    - [`prf(seed, index)`](#prfseed-index---u8-constants-hash_len)
    - [`xor(a, b)`](#xora-b)
    - [`chain(prev_chain_out, randomization_elements, index, step)`](#chainprev_chain_out-randomization_elements-index-step)
    - [`compute_message_hash_chain_indexes(message)`](#compute_message_hash_chain_indexesmessage---chain_segment_indexes)
    - [`generate_key_pair(private_seed)`](#generate_key_pairprivate_seed)
    - [`get_public_key(private_key)`](#get_public_keyprivate_key---publickey)
    - [`get_public_key_with_public_seed(private_key, public_seed)`](#get_public_key_with_public_seedprivate_key-public_seed)
    - [`generate_randomization_elements(public_seed)`](#generate_randomization_elementspublic_seed---randomization_elements)
    - [`sign(private_key, message)`](#signprivate_key-message---signature)
    - [`verify()`](#verify)
    - [`verify_with_randomization_elements()`](#verify_with_randomization_elements)

- [3. Comparison](#3-comparison)
  - [3.1. Constants](#31-constants)
  - [3.2. Message Processing (Base-w conversion)](#32-message-processing-base-w-conversion)
  - [3.3. PRF](#33-prf)
  - [3.4. Randomization Elements (Masks)](#34-randomization-elements-masks)
  - [3.5. Chain Function](#35-chain-function)
  - [3.6. Public Key Construction](#36-public-key-construction)
  - [3.7. Signature Generation & Verification](#37-signature-generation--verification)

- [4. Future Improvements](#4-future-improvements)
  - [4.1. Synchronization and Cleanup](#41-synchronization-and-cleanup)
  - [4.2. Toward a Formal Proof](#42-toward-a-formal-proof)
  - [4.3. Replay Attack Prevention in Blockchain Contexts](#43-replay-attack-prevention-in-blockchain-contexts)
    - [Scenario 1](#scenario-1)
    - [Scenario 2](#scenario-2)
    - [Scenario 3](#scenario-3)
    - [Scenario 4](#scenario-4)

- [5. References](#5-references)

---

## 1. Overview

Winternitz One-Time Signature Plus (WOTS+) [2] is a hash-based, post-quantum digital signature scheme that achieves security solely from the assumed one-wayness and collision resistance of cryptographic hash functions. It operates by encoding a message into base-w digits, extending it with a checksum, and signing each digit using truncated hash chains derived from a secret seed; verification recompletes the remaining steps of each chain to reconstruct the public key. 

In this document, we describe the core entities and design choices underlying the hashsig implementations and provide a detailed comparison against the RFC 8391 specification [3]. We conclude by outlining potential future improvements aimed at strengthening formal security guarantees, improving cross-implementation consistency, and mitigating corner-case replay attacks in practical deployment scenarios.

---

## 2. Entities

### 2.1. Constants

This module set the constraints to default Winternitz+ parameters mentioned in the RFC-8391 document.

### 2.2. PublicKey
```
    pub public_seed: [u8; constants::HASH_LEN],
    pub public_key_hash: [u8; constants::HASH_LEN],
```

provides serialization/deserialization functions. ```to_byte()``` and ```from_byte()```.

### 2.3. WOTSPlus

The main flow of the Winternitz protocol happens here.

#### ```prf(seed, index) -> [u8; constants::HASH_LEN]```

Given a ```seed``` and ```index``` generates an input in the form of 

```
input[0] = 0x03; // prefix to domain separate
input[1..33].copy_from_slice(seed); // the seed input
input[33..].copy_from_slice(&index.to_be_bytes());
```
and then will hash it and returns

```
out <- H(input)
```

#### ```xor(a,b)```

+ Outputs the element-wise binary XOR of two Vec with the size ```HASH_LEN```.

#### ```chain(prev_chain_out, randomization_elements, index, step)```

" 
This is the core of WOTS+, implementing the hash chain with randomization
The chain function takes the previous chain output, XORs it with a randomization element, and then hashes the result. This is repeated 'steps' times.
"
The flow of this function has been described in ```sign()``` function. 

#### ```compute_message_hash_chain_indexes(message) -> chain_segment_indexes```

Given the message

+ converts message into base-CHAIN_LEN ```chain_segment_indexes```

+ Computes ```checksum``` of the ```chain_segment_indexes``` by

```
    checksum = SUM(CHAIN_LEN - 1 - chain_segment_indexes[i])
```

+ Converts the checksum to base-CHAIN_LEN

+ Append ```checksum``` to ```chain_segment_indexes```

#### ```generate_key_pair(private_seed)```

+ Generates ```private_key``` from ```private_seed```.
```
    private_key = H(private_seed)
```

#### ```get_public_key(private_key) -> PublicKey```

+ Generates ```public_seed``` from ```private_key```:

```
    public_seed = prf(private_key, 0)
``` 

+ Generates ```public_key``` by 
```
    public_key = get_public_key_with_public_seed(private_key, public_seed)
```

#### ```get_public_key_with_public_seed(private_key, public_seed)```
+ Generates randomization elements by
```
    elements = generate_randomization_elements(public_seed)
```

+ Assigns ```function_key``` to the first element of ```elements```.
```
    function_key = elements[0]
```

+ Creates ```public_key_segments``` with the capacity of signature size.

+ Converts message to chain indexes including checksum.

+ For each chain index
    + Generates the secret key segment
    + Run the function to the index position.

#### ```generate_randomization_elements(public_seed) -> randomization_elements```

+ Creates a Vec with the size of number of signature chucks (```NUM_SIGNATURE_CHUNKS```)

+ Fills out each element with 

```
    randomization_elements[i] = prf(public_seed, i)
```

#### ```sign(private_key, message) -> signature```

+ Generates ```public_seed``` from ```private_key``` by

```
    public_seed = prf(private_key, 0)
```

+ Generates randomization_elements from ```public_seed``` by
```
    randomization_elements[i] = prf(public_seed, i)
```
+ Computes the indexes on the chains given the message by

```
    chain_segments = compute_message_hash_chain_indexes(message)
```

+ Iterates through ```chain_segments```

    + Constructs ```to_hash``` by
    ```
        to_hash[0:HASH_LEN] = prf(public_seed, 0)
        to_hash[HASH_LEN: 2 * HASH_LEN] = prf(private_key, i + 1)
    ```

    + Constructs ```secret_key_segment```, first element of i-th hash chain

    + Traverse through the chain ```chain_segments[i]``` times, by 
    ```
        next_item = H(prev_item XOR prf(public_seed, j))
    ```
    where ```j``` is in ```[0, chain_segments[i]]```.

    + append the last item to ```signature```

+ Returns the ```signature```

#### ```verify(public_key, message, signature)```

+ Reconstructs ```randomization_elements``` based on ```public_seed```
+ Reconstructs ```public_key``` based on ```message_chunks``` and ```signature_chunks``` by
```
pk_i = chain(sig_i, w−1−a_i)
```

+ Exactly mirroring signing flow and checking if it matches
```
computed_hash = H(pk_0 || pk_1 || ... || pk_(len−1))
```
-----------------

## 3. Comparison

There are a few modifications to the standardized version of Winternitz+ that has been described in RFC-8391.

### 3.1. Constants 
🟢 Complete Match

##### RFC 8391

```
    n = hash output length (commonly 32 bytes)
    w in {4, 16} (Winternitz parameter)
    len_1 = ceil(8n / log₂(w))
    len_2 = floor(log₂(len_1 (w−1)) / log₂(w)) + 1
    len = len_1 + len_2
```
##### Quip

```
    HASH_LEN = 32
    CHAIN_LEN = 16 (w = 16)
    LG_CHAIN_LEN = 4
    NUM_MESSAGE_CHUNKS = 64
    NUM_CHECKSUM_CHUNKS = 3
    NUM_SIGNATURE_CHUNKS = 67
```

### 3.2. Message Processing (Base-w conversion)
+ 🟢 Correct base-16 expansion
+ 🟢 Correct checksum definition
+ 🟢 Correct left-aligned checksum expansion

##### RFC 8391
Message digest M is converted to base-w representation
```
Each symbol in [0, w−1]
Checksum = Sum(w − 1 − msg[i])
```
Checksum is also base-w encoded, most significant digit first

##### Quip
```
chain_segments_indexes[idx]     = byte >> 4;
chain_segments_indexes[idx + 1] = byte & 0x0f;
```

### 3.3. PRF 
🟡 We rely on W-OTS+ 2017 paper [2] proofs and constructions.


|Aspect            |RFC 8391                | Quip      |
|------------------|------------------------|-----------|
|PRF input         |(SK_seed, ADRS)         | (private_key, index)|
|Domain separation | Stronger (ADRS types)  | Weaker (single prefix byte + function_key)|
|Key derivation    | One PRF per segment    | PRF + hash mixing|

##### RFC 8391
Each WOTS+ secret key element is derived as:
```
sk[i] = PRF(SK_seed, ADRS)
```
Where ```PRF``` is a keyed hash, ```ADRS``` is a structured address containing:
```
{chain index, hash index}
```
##### Quip 

In Quip we have:
```
secret_key_segment = H(
    function_key || PRF(private_key, i+1)
)
```

### 3.4. Randomization Elements (Masks)
+ 🟢 provides basic masking
+ 🟡 loses collision resistance guarantees expected by XMSS proofs

##### RFC 8391

For each chain step:
```
tmp = F(tmp ⊕ bitmask)
```
Where:
```
bitmask = PRF(PUB_seed, ADRS)
```
and ```ADRS``` includes chain index and hash index

##### Quip
```
randomization_elements[i] = PRF(public_seed, i)
```
Used as:

```
xored = chain_out ⊕ randomization_elements[i + index]
```

### 3.5. Chain Function

+ 🟢 Functionally equivalent hash-chain behavior.
+ 🟡 Mask derivation is weaker than XMSS proofs.

##### RFC 8391
```
c_k^i(x) = F(x ⊕ bitmask(i,k))
```
##### Quip
```
for i in 1..=steps {
    xored = chain_out ⊕ randomization_elements[i + index]
    chain_out = H(xored)
}
```

### 3.6. Public Key Construction
+ 🟢 Correct structure
+ 🟢 Publickey construction matches WOTS+ 2017 paper [2]

##### RFC 8391

+ Each chain runs to w−1
+ All chain outputs are concatenated
+ Final public key = H(concat(pk_i))

#### Quip
```
segment = chain(sk_i, ..., w-1)
public_key_hash = H(all_segments)
```

### 3.7. Signature Generation & Verification
+ 🟢 Matching Message encoding
+ 🟢 Mathematically correct
+ 🟢 Verifies correctly

##### RFC 8391

+ Converts M into base-w digits and appends a checksum:

```
a_0, a_1, ..., a_(len−1)   where each a_i ∈ [0, w−1]
```
+ Each secret key element is derived as:
```
sk_i = PRF(SK_seed, ADRS(chain=i))
```

+ Each signature element is computed as:
```
sig_i = chain(sk_i, a_i)
```
Where the chain function is:
```
chain(x, t):
    for j = 0 to t−1:
        x = F(x ⊕ PRF(PUB_seed, ADRS(chain=i, hash=j)))
    return x
```
##### Quip

+ Message encoding

Same as RFC:
```
a_0, a_1, ..., a_(len−1)
```

+ Secret key element derivation
```
public_seed = PRF(private_key, 0)
function_key = randomization_elements[0]

sk_i = H(
    function_key || PRF(private_key, i+1)
)
```

+ Signature generation

```
sig_i = chain(sk_i, a_i)
```
Where:
```
chain(x, t):
    for j = 1..t:
        x = H(x ⊕ randomization_elements[j])
```

---
## 4. Future improvements

### 4.1. Synchronization and cleanup
Hashsig codebase has a few similar but not identical implementations of WOTS+ [2] specifically
+ relations between ```private_key``` and ```public_seed``` and ```public_key```.
+ parameter encoding in ```prf``` across our multiple implementations of ```hashsig``` library. 

It is recommended to 
+ have a ground truth implementation and sync all the other implementation with it
+ add more comments throughout the code
+ Make module encapsulation match the WOTS+ 2017 paper.

### 4.2. Toward a Formal Proof
|It is important to note that the current implementation is conceptually based on the original WOTS+ construction introduced in the 2017 WOTS+ paper, rather than being a strict implementation of the RFC 8391 instantiation used in XMSS. While the core ideas such as hash chains, base-w message encoding, and checksums are preserved, some proof-oriented design constraints introduced in RFC 8391 are not fully carried over.|

The security proof of RFC 8391 (WOTS+/XMSS) relies on a small set of well-defined assumptions:
+ One-wayness of the hash function
+ Security of the PRF
+ Strict address (domain) separation

Under these assumptions, the proof can reduce existential forgery to standard cryptographic primitives. In RFC 8391, the ```PRF``` is invoked as:
```
PRF(seed, ADRS)
```
where ADRS is a structured address encoding: the role (e.g., chain, mask, key derivation), the chain index, and the hash step index. This structure guarantees that each PRF call is unique and role-separated, allowing the proof to treat PRF outputs as independent random values.

In the current implementation:
+ We do not have this addressing format, however, we are using simpler and more efficient version that has been described in WOTS+ 2017. Additionally the same PRF construction is reused across different roles.

+ PRF outputs are chained into the same hash function:
```
sk_i = H(function_key || PRF(private_key, i))
```
This coupling prevents the standard hybrid argument used in RFC 8391, where PRF outputs can be replaced by random values without affecting the adversary’s view.

To go toward a a formal proof, it is recommended to
+ Introduce a structured address format (ADRS) with explicit role, chain, and step separation suitable to out WOTS+ implementation.
+ Apply strict domain separation for all PRF and hash invocations.
+ Ensure that masks and PRF outputs are NEVER reused across logical domains.
+ Avoid feeding PRF outputs directly into the same hash oracle without separation.

### 4.3. Replay Attack Prevention in Blockchain Contexts
When used in Quip, Web3, or smart contract contexts, the same considerations discussed above can lead to potential replay attacks. While the current implementation makes reasonable security trade-offs, we document them here and note that there is clear room for improvement to better align the security guarantees with the proofs in [2], [4].

#### scenario 1
Same signature valid across:

+ Different chains
+ Different contracts
+ Different message domains

This behavior is intentional for certain flows, such as the swap protocol. In the swap protocol, we explicitly want the same signatures to be valid across different chains. However, it may still be desirable to restrict their validity to the swap context only, rather than allowing them to be reused arbitrarily.

#### scenario 2
1. Same private key signs two different messages M₁, M₂
2. Attacker observes two signatures
3. For each chain index i, attacker sees:
```
sig_i(M₁) = c^a(sk_i)
sig_i(M₂) = c^b(sk_i)
```

If a ≠ b, attacker can compute:
```
c^max(a,b)(sk_i)
```

4. Over enough indices, attacker reconstructs full public key chains

5. Attacker forges a signature on arbitrary messages

#### scenario 3
1. Developer reuses the same private seed for:

    + This WOTS+ scheme
    + Another hash-based construction (e.g., PRF, commitment, MAC)

2. Attacker observes outputs from both protocols.

3. Attacker correlates:
    + PRF(seed, i) ↔ H(seed || i)

Cross-protocol leakage reduces entropy of secret material

#### scenario 4
1. Attacker collects many signatures
2. Observes that:
    + Same mask reused across different chains
    + Same mask reused across different messages

3. Attacker computes:
```
H(x ⊕ m) ⊕ H(y ⊕ m)
```

It leads to structural relations leak:

+ Relative chain positions
+ Differences between secret key segments

and eventually and through time it will reduced security margin and enables future cryptanalysis.

To mitigate these problems, it is recommended to

+ Introduce a structured address format (ADRS) with explicit role, chain, and step separation.
+ Apply strict domain separation for all PRF and hash invocations.
+ Ensure that masks and PRF outputs are NEVER reused across logical domains.
+ Avoid feeding PRF outputs directly into the same hash oracle without separation.

## 5. References

1. **XMSS — A Practical Forward-Secure Signature Scheme Based on Minimal Security Assumptions (2011)**  
   Johannes Buchmann, Erik Dahmen, Andreas Hülsing.  
   *Post-Quantum Cryptography (PQCrypto 2011)*.  

2. **W-OTS+ — Shorter Signatures for Hash-Based Signature Schemes (2017)**  
   Andreas Hülsing.  

3. **RFC 8391 — XMSS: eXtended Merkle Signature Scheme (2018)**  
   Andreas Hülsing, Denis Butin, Shay Gueron, et al.  
   *IETF RFC 8391*, May 2018.  

4. **A Tight Security Proof for SPHINCS+, Formally Verified (2024)**
  Manuel Barbosa, François Dupressoir, Andreas Hülsing, Matthias Meijers, and Pierre-Yves Strub.  
