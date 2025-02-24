#![allow(semicolon_in_expressions_from_macros)]

mod merkle;
mod verification;
mod crypto_utils;

use crypto_utils::compute_merkle_product;
use verification::SigmaProtocol;

macro_rules!  get_input {
    ($x:ident) => {
        let mut $x = String::new();
        std::io::stdin()
            .read_line(&mut $x)
            .expect("Failed to read line");
        let $x = $x.trim();
    };
}
fn main() {
    let some_random_transaction_data = vec![
        vec![1, 2, 3],
        vec![1, 4, 5],
        vec![6, 7, 8],
        vec![9, 10, 11],
        vec![12, 13, 14],
        vec![15, 16, 17],
        vec![18, 19, 20],
        vec![21, 22, 23],
        vec![1, 2, 3],
        vec![1, 4, 5],
        vec![6, 7, 8],
        vec![9, 10, 11],
        vec![12, 13, 14],
        vec![15, 16, 17],
        vec![18, 19, 20],
        vec![21, 22, 23],
    ];

    let index: usize = 0;

    get_input!(name);

    println!("{}", name);

    let merkle_product = compute_merkle_product(some_random_transaction_data, index);

    let sigma = SigmaProtocol::new(&merkle_product);

    let (t, r) = sigma.commit();
    let e = SigmaProtocol::challenge();
    let z = sigma.response(&r, &e);
    let is_valid = sigma.verify(&t, &e, &z);

    if is_valid {
        println!("Valid at {}", index+1);
    } else {
        println!("Invalid at {}", index+1);
    }
}

