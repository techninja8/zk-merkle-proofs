use curv::elliptic::curves::{Secp256k1, Point, Scalar};
use sha2::{Digest, Sha256};
use crate::merkle::{Hash, build_merkle_tree, compute_merkle_proof};
use curv::arithmetic::Converter;

pub fn safe_scalar_from_hash(hash: &[u8]) -> Scalar<Secp256k1> {
    let mut hash_fixed = [0u8; 32];
    hash_fixed.copy_from_slice(&hash[..32]);
    Scalar::<Secp256k1>::from_bytes(&hash_fixed).unwrap_or_else(|_| Scalar::<Secp256k1>::random())
}

pub fn multiply_points(p1: &Point<Secp256k1>, p2: &Point<Secp256k1>) -> Point<Secp256k1> {
    let s1 = Scalar::<Secp256k1>::from_bytes(&p1.x_coord().unwrap().to_bytes()).unwrap();
    let s2 = Scalar::<Secp256k1>::from_bytes(&p2.x_coord().unwrap().to_bytes()).unwrap();

    let scalar_product = s1 * s2;
    Point::<Secp256k1>::generator() * scalar_product
}

pub fn point_to_scalar(point: &Point<Secp256k1>) -> Scalar<Secp256k1> {
    let hash = Sha256::digest(point.to_bytes(false));
    Scalar::<Secp256k1>::from_bytes(&hash[..32]).unwrap()
}

pub fn compute_merkle_product(transac_data: Vec<Vec<u8>>, index: usize) -> Scalar<Secp256k1> {
    let leaf_hashes: Vec<Hash> = transac_data.into_iter().map(|d| Hash::compute_hash(&d)).collect();
    let (merkle_tree, merkle_root) = build_merkle_tree(&leaf_hashes);
    let merkle_proof = compute_merkle_proof(&merkle_tree, index);

    let mt_scalar = safe_scalar_from_hash(&merkle_proof.concat());
    let mp_scalar = safe_scalar_from_hash(&merkle_root);

    let mt_point = Point::<Secp256k1>::generator() * mt_scalar;
    let mp_point = Point::<Secp256k1>::generator() * mp_scalar;

    let point_of_merkle_product = multiply_points(&mt_point, &mp_point);
    point_to_scalar(&point_of_merkle_product)
}

