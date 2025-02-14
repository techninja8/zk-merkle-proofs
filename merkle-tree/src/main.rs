mod merkle;
mod verification;
mod crypto_utils;

use crypto_utils::compute_merkle_product;
use verification::SigmaProtocol;

fn main() {
    let some_random_transaction_data = vec![
        vec![1, 2, 3],
        vec![1, 4, 5],
        vec![6, 7, 8],
        vec![9, 10, 11],
    ];

    let index: usize = 2;

    let merkle_product = compute_merkle_product(some_random_transaction_data, index);

    let sigma = SigmaProtocol::new(&merkle_product);

    let (t, r) = sigma.commit();
    let e = SigmaProtocol::challenge();
    let z = sigma.response(&r, &e);
    let is_valid = sigma.verify(&t, &e, &z);

    if is_valid {
        println!("The Proof is Valid, Thus Leaf at {index} is a Member of The Tree");
    } else {
        println!("The Proof is Invalid");
    }
}

