# Sigma Protocol for Merkle Tree Membership Proof (Semi-ZK)

UPDATED README.md

## Overview
This Rust program implements a **Sigma Protocol** to prove membership in a **Merkle Tree** using **Elliptic Curve Cryptography (ECC)** over **Secp256k1**. The protocol enables a prover to demonstrate that a given transaction belongs to a Merkle tree without revealing any other transactions or any information related to the Merkle tree at all (including merkle proof and merkle root), ensuring privacy and efficiency.

## Features
- **Merkle Tree Construction**: Builds a Merkle tree from a set of hashed transaction data, returns the merkle root.
- **Merkle Proof Computation**: Extracts the Merkle proof path for a given transaction.
- **Elliptic Curve Mapping**: Maps Merkle proofs and roots to ECC scalars and sets them as Sigma-Secrets (merkle-product).
- **Sigma Protocol Implementation**: Implements the three steps of a Sigma protocol:
  1. **Commitment** (`commit()`) - Generates a random elliptic curve commitment.
  2. **Challenge** (`challenge()`) - Computes a challenge hash.
  3. **Response** (`response()`) - Computes a proof response.
- **Proof Verification**: Checks if the proof is valid using elliptic curve operations and returns a boolean indicating validity.

## How It Works
1. **Construct the Merkle Tree**:
   - The program generates a Merkle tree from sample transactions.
   - Computes the Merkle root and extracts a Merkle proof for a given leaf.
   
2. **Map Merkle Proof and Merkle Root to Elliptic Curve To Employ Them As Secret Keys**:
   - Converts the Merkle proof into a scalar.
   - Maps the scalar to an elliptic curve point.
   - Then Transform Them To Scalar (I honestly don't know why I did this 😂).
   
3. **Generate and Verify a Sigma Proof**:
   - The prover generates a **commitment** (`t = g * r`).
   - A **challenge** (`e`) is computed using SHA-256.
   - The prover computes a **response** (`z = r + e * w`).
   - The verifier checks `g * z == t + x * e`.
   - The verifier learns nothing about `w`, so they cannot know the proof, the root or anything about the tree.
   
4. **Validate Membership**:
   - If the equation holds to be true, the proof is valid, and the transaction is part of the Merkle tree.
   - Otherwise, the proof fails, indicating the prover did not actually present a merkle proof with the correct path and the correct root.

## Installation
### **Prerequisites**
- Install [Rust](https://www.rust-lang.org/)
- Install Cargo package manager (mine came with Rust, so, I'm pretty sure your's will too!)

### **Clone the Repository**
```sh
git clone <repo-url>
cd <repo-folder>
```

### **Dependencies**
Check `Cargo.toml` file for the list of dependencies

### **Run the Program**
```sh
cargo run
```

## Expected Output
If verification succeeds, the output will be:
```
The Proof is Valid, Thus Leaf at 4 is a Member of The Tree
```
Otherwise, it prints:
```
The Proof is Invalid
```

## Some Things I Should Note
This program does not make use of ZK-SNARKS or ZK-STARKS, it's still very experimental and definitely not production-ready. It works by transforming a the merkle proof and merkle roots (two fundamental parts for proving inclusion) and hides it from the verifier, this property, I fell gives the design a considerate (but not efficient) zero knowledge. Yh, and to make use of the Sigma protocol, I employed ECCs for computing sigma's parameters, making the Merkle proof and Merkle roots secret keys. This allowed the program to compute the proof correctly.

## License
This project is open-source and licensed under the MIT License. Feel Free To Expand Or Experiment with it too!

## Author
Developed by Blessed Tosin-Oyinbo (tnxl)


