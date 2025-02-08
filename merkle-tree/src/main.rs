// strictly for tests!
// uncomment any of the main functions to test either Attack System or Normal ZKP verification
// c.  Blessed Tosin-Oyinbo

#![allow(unused_variables)]
#![allow(dead_code)]

use sha2::{Digest, Sha256};
use std::fmt;
// use rand::Rng;
use std::convert::TryInto;

// Merkle hash size
const HASH_SIZE: usize = 32;

// Define a struct for Hash
#[derive(Clone, PartialEq)]
pub struct Hash([u8; HASH_SIZE]);

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

impl Hash {
    pub fn from(data: [u8; HASH_SIZE]) -> Hash {
        Hash(data)
    }

    pub fn compute_hash(data: &[u8]) -> Hash {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();

        let mut result = [0u8; HASH_SIZE];
        result.copy_from_slice(&hash);
        Hash(result)
    }
}

// Merkle tree hash function for branches
fn compute_hash_of_branch(left: &Hash, right: &Hash) -> Hash {
    let mut combined = [0u8; HASH_SIZE * 2];
    combined[..HASH_SIZE].copy_from_slice(&left.0);
    combined[HASH_SIZE..].copy_from_slice(&right.0);
    Hash::compute_hash(&combined)
}

// Generate Merkle Root from Leaf Hashes
pub fn gen_root_hash(hashed_data: &[Hash]) -> Hash {
    let mut nodes = hashed_data.to_vec();

    while nodes.len() > 1 {
        let mut parent_nodes = Vec::new();

        for i in (0..nodes.len()).step_by(2) {
            let left = &nodes[i];
            let right = if i + 1 < nodes.len() { &nodes[i + 1] } else { &nodes[i] };
            parent_nodes.push(compute_hash_of_branch(left, right));
        }

        nodes = parent_nodes;
    }

    nodes[0].clone()
}

// Compute Merkle Proof for a given leaf
pub fn compute_merkle_proof(leaf: &Hash, leaves: &[Hash]) -> Vec<Hash> {
    let mut proof = Vec::new();
    let mut index = leaves.iter().position(|h| h == leaf).unwrap();
    let mut nodes = leaves.to_vec();

    while nodes.len() > 1 {
        let mut parent_nodes = Vec::new();

        for i in (0..nodes.len()).step_by(2) {
            let left = &nodes[i];
            let right = if i + 1 < nodes.len() { &nodes[i + 1] } else { &nodes[i] };

            if i == index || i + 1 == index {
                if i == index {
                    proof.push(right.clone());
                } else {
                    proof.push(left.clone());
                }
            }

            parent_nodes.push(compute_hash_of_branch(left, right));
        }

        nodes = parent_nodes;
        index /= 2;
    }

    proof
}
// We are employing classic interactive zk proofs, but using Fiat-Shamir based challenge to create
// a deterministic fault-proof challenge instead of the regular ones (non-deterministic) that would
// require us to get challenge from verifier



// We'll need to generate a commitment first
fn generate_commitment(leaf: &Hash, proof: &[Hash], merkle_root: &Hash) -> Hash {
    let mut data = Vec::new();
    data.extend_from_slice(&leaf.0);
    for p in proof {
        data.extend_from_slice(&p.0);
    }
    data.extend_from_slice(&merkle_root.0); // include merkle root
    Hash::compute_hash(&data)
}

// Fiat-Shamir Challenge (A deterministic but also unpredictable means to introduce
// non-intercativity)
fn generate_challenge(commitment: &Hash, merkle_root: &Hash) -> u64 {
    let mut data = Vec::new();
    data.extend_from_slice(&commitment.0);
    data.extend_from_slice(&merkle_root.0); // Include merkle root
    let hash_bytes = Sha256::digest(&commitment.0);
    u64::from_be_bytes(hash_bytes[..8].try_into().unwrap())
}

// Prover Function, also add the merkle root here too, any chnage to the original transaction batch
// would alter the merkle root, which creates an alternate merkle root against the original valid
// proof 
fn prover(leaf: &Hash, proof: &[Hash], merkle_root: &Hash) -> (Hash, u64, Hash) {
    let commitment = generate_commitment(leaf, proof, &merkle_root);
    let challenge = generate_challenge(&commitment, &merkle_root);

    let mut combined = Vec::new();
    combined.extend_from_slice(&commitment.0);
    combined.extend_from_slice(&challenge.to_be_bytes());
    
    let response = Hash::compute_hash(&combined);
    (commitment, challenge, response)
}

// Verifier Function, we need to include merkle root, as some kind of public value against forgery
// atacks
fn verifier(leaf: &Hash, proof: &[Hash], commitment: &Hash, challenge: u64, response: &Hash, merkle_root: &Hash) -> bool {
    // Recompute Merkle root from proof and leaf
    let mut computed_hash = leaf.clone();

    for (i, sibling) in proof.iter().enumerate() {
        if i % 2 == 0 {
            computed_hash = compute_hash_of_branch(&computed_hash, sibling);
        } else {
            computed_hash = compute_hash_of_branch(sibling, &computed_hash);
        }
    }

    if computed_hash != *merkle_root {
        return false;
    }

    let expected_commitment = generate_commitment(leaf, proof, merkle_root);
    if expected_commitment != *commitment {
        return false;
    }

    let expected_challenge = generate_challenge(&expected_commitment, merkle_root);
    if expected_challenge != challenge {
        return false;
    }

    let mut combined = Vec::new();
    combined.extend_from_slice(&commitment.0);
    combined.extend_from_slice(&challenge.to_be_bytes());

    let expected_response = Hash::compute_hash(&combined);
    expected_response == *response
}

fn attack_system() {
    // Generate a valid transaction set
    let transactions: Vec<Hash> = vec![
        Hash::compute_hash(b"Transaction 1"),
        Hash::compute_hash(b"Transaction 2"),
        Hash::compute_hash(b"Transaction 3"),
        Hash::compute_hash(b"Transaction 4"),
    ];
    
    // Compute Merkle root
    let merkle_root = gen_root_hash(&transactions);
    println!("Original Merkle Root: {:?}", merkle_root);

    // Pick a legitimate transaction and get proof
    let valid_leaf = &transactions[0];
    let valid_proof = compute_merkle_proof(valid_leaf, &transactions);
    
    // Generate a foreign (fake) transaction
    let fake_transaction = Hash::compute_hash(b"Fake Transaction");

    // Try to use a valid proof with the fake transaction
    let (fake_commitment, fake_challenge, fake_response) = prover(&fake_transaction, &valid_proof, &merkle_root);
    
    // Attempt verification (we should be expecting rejection)
    let verification_result = verifier(&fake_transaction, &valid_proof, &fake_commitment, fake_challenge, &fake_response, &merkle_root);

    if verification_result {
        println!("⚠️ ATTACK SUCCESSFUL: The system accepted a foreign transaction!");
    } else {
        println!("✅ ATTACK FAILED: The system correctly rejected the foreign transaction.");
    }
}

// Test the attack sysrem
fn main() {
    attack_system();
}

// Test the general functionality

/*fn main() {
    // Sample Transactions
    let transaction_data = vec![
        b"tx1".to_vec(),
        b"tx2".to_vec(),
        b"tx3".to_vec(),
        b"tx4".to_vec(),
        b"tx5".to_vec(),
        b"tx6".to_vec(),
    ];

    // Hash the transactions
    let leaf_hashes: Vec<Hash> = transaction_data
        .into_iter()
        .map(|d| Hash::compute_hash(&d))
        .collect();
    
    // uncomment any println parts for debugging or confirmation
    // Compute Merkle Root
    let merkle_root = gen_root_hash(&leaf_hashes);
    // println!("Merkle Root: {:?}", merkle_root);

    // Pick a leaf (e.g., third transaction)
    let leaf = &leaf_hashes[2];

    // Compute Merkle Proof for that leaf
    // Merkle proof or the Sibling leafs should not be known by the verifier
    let proof = compute_merkle_proof(leaf, &leaf_hashes);
    // println!("Merkle Proof: {:?}", proof);

    // Prover Generates Proof
    let (commitment, challenge, response) = prover(leaf, &proof, &merkle_root);
    println!("Commitment: {:?}", commitment);
    println!("Challenge: {}", challenge);
    println!("Response: {:?}", response);

    // Verifier Checks the Proof
    let is_valid = verifier(leaf, &proof, &commitment, challenge, &response, &merkle_root);
    println!("ZKP Verification: {}", is_valid);
} */
