#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]

use curv::arithmetic::Converter;
use curv::elliptic::curves::{Secp256k1, Point, Scalar};
use sha2::{Digest, Sha256};
use rand::{Rng, SeedableRng};
use curv::BigInt;
use std::fmt;

const HASH_SIZE: usize = 32;

// The prover calculates the merkle root and merkle proof (Vec<Hash>) and trasforms it into
// Scalar<Secp256k1> so we can feed it to the Sigma Prover Algoritm can run.
#[derive(Debug, Clone, PartialEq)]
pub struct Hash([u8; HASH_SIZE]);

#[derive(Clone)]
struct SigmaProtocol {
    g: Point<Secp256k1>,
    x: Point<Secp256k1>,
    w: Scalar<Secp256k1>,
}

fn safe_scalar_from_hash(hash: &[u8]) -> Scalar<Secp256k1> {
    let mut hash_fixed = [0u8; 32];
    hash_fixed.copy_from_slice(&hash[..32]);
    Scalar::<Secp256k1>::from_bytes(&hash_fixed).unwrap_or_else(|_| Scalar::<Secp256k1>::random())
}

fn multiply_points(p1: &Point<Secp256k1>, p2: &Point<Secp256k1>) -> Point<Secp256k1> {
    // Convert points to scalars (hashing x-coordinates)
    let s1 = Scalar::<Secp256k1>::from_bytes(&p1.x_coord().unwrap().to_bytes()).unwrap();
    let s2 = Scalar::<Secp256k1>::from_bytes(&p2.x_coord().unwrap().to_bytes()).unwrap();

    // Multiply scalars
    let scalar_product = s1 * s2;

    // Map back to a point using generator multiplication
    Point::<Secp256k1>::generator() * scalar_product
}

fn compute_merkle_product(transac_data: Vec<Vec<u8>>) -> Scalar<Secp256k1> {
    let leaf_hashes: Vec<Hash> = transac_data
        .into_iter()
        .map(|d| Hash::compute_hash(&d))
        .collect();

    let (merkle_tree, merkle_root) = build_merkle_tree(&leaf_hashes);
    
    let mt_scalar = safe_scalar_from_hash(&merkle_tree.concat());
    let mp_scalar = safe_scalar_from_hash(&merkle_root);

    let mt_point = Point::<Secp256k1>::generator() * mt_scalar;
    let mp_point = Point::<Secp256k1>::generator() * mp_scalar;

    let point_of_merkle_product = multiply_points(&mt_point, &mp_point);

    point_to_scalar(&point_of_merkle_product)
}

fn point_to_scalar(point: &Point<Secp256k1>) -> Scalar<Secp256k1> {
    let hash = Sha256::digest(point.to_bytes(false));
    Scalar::<Secp256k1>::from_bytes(&hash[..32]).unwrap()
}

impl Hash {
    pub fn compute_hash(data: &[u8]) -> Hash {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let sha_256_hash = hasher.finalize();
        let mut hash = [0u8; HASH_SIZE];
        hash.copy_from_slice(&sha_256_hash);
        Hash(hash)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

fn compute_hash_of_branch(left: &Hash, right: &Hash) -> Hash {
    let mut hash_combined = [0u8; HASH_SIZE * 2];
    hash_combined[..HASH_SIZE].copy_from_slice(left.as_bytes());
    hash_combined[HASH_SIZE..].copy_from_slice(right.as_bytes());
    Hash::compute_hash(&hash_combined)
}

pub fn build_merkle_tree(hashed_data: &[Hash]) -> (Vec<Vec<u8>>, [u8; HASH_SIZE]) {
    let mut tree: Vec<Vec<Hash>> = vec![hashed_data.to_vec()];
    let mut nodes = hashed_data.to_vec();
    while nodes.len() > 1 {
        let mut parent_nodes = Vec::new();
        for i in (0..nodes.len()).step_by(2) {
            let left = &nodes[i];
            let right = if i + 1 < nodes.len() { &nodes[i + 1] } else { &nodes[i] };
            parent_nodes.push(compute_hash_of_branch(left, right));
        }
        tree.push(parent_nodes.clone());
        nodes = parent_nodes;
    }
    let merkle_root = nodes[0].clone();
    (
        tree.into_iter().map(|level| level.into_iter().flat_map(|h| h.0).collect()).collect(),
        merkle_root.0,
    )
}

impl SigmaProtocol {
    fn new(w: &Scalar<Secp256k1>) -> Self{
        let g = Point::<Secp256k1>::generator();
        let x = g * w;

        Self { g: g.into(), x, w: w.clone() }
    }

    fn commit(&self) -> (Point<Secp256k1>, Scalar<Secp256k1>) {
        let r = Scalar::<Secp256k1>::random();
        let t = &self.g * &r;

        (t, r)
    }

    fn challenge() -> Scalar<Secp256k1> {
        let mut hasher = Sha256::new();
        let mut rng = rand::thread_rng();
        let val: u64 = rng.gen();
        hasher.update(val.to_le_bytes());
        let hash = hasher.finalize();
        Scalar::<Secp256k1>::from_bytes(&hash[..32]).unwrap()
    }

    fn response(&self, r: &Scalar<Secp256k1>, e: &Scalar<Secp256k1>) -> Scalar<Secp256k1> {
        r.clone() + e.clone() * self.w.clone()
    }

    fn verify(&self, t: &Point<Secp256k1>, e: &Scalar<Secp256k1>, z: &Scalar<Secp256k1>) -> bool {
        let lhs = self.g.clone() * z;
        let rhs = t.clone() + self.x.clone() * e;
        lhs == rhs
            
    }
}

fn main() {
    let some_random_transaction_data = vec![
        b"some_random_data1".to_vec(),
        b"some_random_data2".to_vec(),
        b"some_random_data3".to_vec(),
        b"some_random_data4".to_vec(),
        b"some_random_data5".to_vec(),
        b"some_random_data5".to_vec(),
    ];

    let merkle_product = compute_merkle_product(some_random_transaction_data);
    
    // println!("Merkle Product (Secret Key): {:?}", merkle_product);

	

    let sigma = SigmaProtocol::new(&merkle_product);

    let (t, r) = sigma.commit();

    let e = SigmaProtocol::challenge();

    let z = sigma.response(&r, &e);

    let is_valid = sigma.verify(&t, &e, &z);

    println!("Proof is {}", is_valid);
}
