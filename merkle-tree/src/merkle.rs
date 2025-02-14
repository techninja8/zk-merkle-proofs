use sha2::{Digest, Sha256};

const HASH_SIZE: usize = 32;

#[derive(Debug, Clone, PartialEq)]
pub struct Hash([u8; HASH_SIZE]);

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

pub fn compute_merkle_proof(tree: &Vec<Vec<u8>>, index: usize) -> Vec<[u8; HASH_SIZE]> {
    let mut proof = Vec::new();
    let mut node_index = index;

    for level in 0..tree.len() - 1 {
        let level_hashes = &tree[level];

        let chunk_size = HASH_SIZE;
        let num_nodes = level_hashes.len() / chunk_size;

        if num_nodes <= node_index {
            break;
        }

        let sibling_index = if node_index % 2 == 0 { node_index + 1 } else { node_index - 1 };

        if sibling_index < num_nodes {
            let start = sibling_index * chunk_size;
            let end = start + chunk_size;
            let mut sibling_hash = [0u8; HASH_SIZE];
            sibling_hash.copy_from_slice(&level_hashes[start..end]);
            proof.push(sibling_hash);
        }

        node_index /= 2;
    }

    proof
}

