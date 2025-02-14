use curv::elliptic::curves::{Secp256k1, Point, Scalar};
use sha2::{Digest, Sha256};
use rand::Rng;

pub struct SigmaProtocol {
    g: Point<Secp256k1>,
    x: Point<Secp256k1>,
    w: Scalar<Secp256k1>,
}

impl SigmaProtocol {
    pub fn new(w: &Scalar<Secp256k1>) -> Self {
        let g = Point::<Secp256k1>::generator();
        let x = g * w;

        Self { g: g.into(), x, w: w.clone() }
    }

    pub fn commit(&self) -> (Point<Secp256k1>, Scalar<Secp256k1>) {
        let r = Scalar::<Secp256k1>::random();
        let t = &self.g * &r;
        (t, r)
    }

    pub fn challenge() -> Scalar<Secp256k1> {
        let mut hasher = Sha256::new();
        let mut rng = rand::thread_rng();
        let val: u64 = rng.gen();
        hasher.update(val.to_le_bytes());
        let hash = hasher.finalize();
        Scalar::<Secp256k1>::from_bytes(&hash[..32]).unwrap()
    }

    pub fn response(&self, r: &Scalar<Secp256k1>, e: &Scalar<Secp256k1>) -> Scalar<Secp256k1> {
        r.clone() + e.clone() * self.w.clone()
    }

    pub fn verify(&self, t: &Point<Secp256k1>, e: &Scalar<Secp256k1>, z: &Scalar<Secp256k1>) -> bool {
        let lhs = self.g.clone() * z;
        let rhs = t.clone() + self.x.clone() * e;
        lhs == rhs
    }
}

