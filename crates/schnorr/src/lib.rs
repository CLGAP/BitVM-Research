use ark_ec::{CurveGroup, Group};
use ark_ff::{PrimeField, BigInteger};
use ark_secp256k1::{Fr, Projective, Affine, Fq};
use ark_std::{rand::Rng, UniformRand};
use sha2::{Sha256, Digest};

pub type PrivateKey = Fr;
pub type PublicKey = Projective;

pub struct Signature {
    pub r: Projective, // R = [k]G
    pub s: Fr,         // s = k + e * x 
}

#[derive(PartialEq, Debug)]
pub struct KeyPair {
    pub private: PrivateKey, 
    pub public: PublicKey,
}

impl KeyPair {
    pub fn generate<R: Rng>(rng: &mut R) -> Self {
        Self::from_private(Fr::rand(rng))        
    }

    pub fn from_private(x: PrivateKey) -> Self {
        let public = Projective::generator() * x;
        Self { private: x, public}
    }
}

pub fn to_bytes(sig: &Signature) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&x_only_bytes(&sig.r));
    out[32..].copy_from_slice(&sig.s.into_bigint().to_bytes_be());
    out
}

pub fn sig_from_bytes(b: &[u8;64]) -> Option<Signature> {
    let x = Fq::from_be_bytes_mod_order(&b[..32]);
    let a = Affine::get_point_from_x_unchecked(x, false)?;
    let p: Projective = a.into(); 
    let r = if even_y(&p) { p } else { -p };
    let s = Fr::from_be_bytes_mod_order(&b[32..]);
    Some(Signature { r, s })
}

pub fn sign<R: Rng>(x: &PrivateKey, m: &[u8], rng: &mut R) -> Signature {
    sign_with_nonce(x, m, Fr::rand(rng))
}

pub fn even_y(p: &Projective) -> bool {
    (p.into_affine().y.into_bigint().to_bytes_le()[0] & 1) == 0
}

pub fn normalize_parity(d: Fr) -> (Fr, Projective) {
    let p = Projective::generator() * d;
    if even_y(&p) { (d, p) } else { (-d, -p) }
}

pub fn verify(p: &PublicKey, m: &[u8], sig: &Signature) -> bool {
    let g = Projective::generator();
    let e = challenge(&sig.r, p, m);
    let p = if even_y(p) { *p } else { -*p };
    g * sig.s == sig.r + p * e && even_y(&sig.r)
}

// e = Hash( R || P || m) as a scalar in field.
pub fn challenge(r: &Projective, p: &Projective, m: &[u8]) -> Fr {
    let tag = Sha256::digest(b"BIP0340/challenge"); // message hashed
    let mut h = Sha256::new(); 
    h.update(tag); // update appends stream
    h.update(tag); // appneded twice so it files 64-byte SHA-256 block
    h.update(x_only_bytes(r));
    h.update(x_only_bytes(p));
    h.update(m);
    Fr::from_be_bytes_mod_order(&h.finalize())
}

pub fn x_only_bytes(p: &Projective) -> [u8; 32] {
    p.into_affine().x.into_bigint().to_bytes_be().try_into().unwrap()
}

// show slashable security with reuse
pub fn sign_with_nonce(x: &PrivateKey, m: &[u8], k: Fr) -> Signature {
    let (k, r) = normalize_parity(k);
    let (d, p) = normalize_parity(*x);
    let e = challenge(&r, &p, m);
    let s = k + e * d;
    Signature { r, s }
}


#[cfg(test)]
mod tests {
    use crate::{KeyPair, PrivateKey, sign, verify};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use super::*;

    #[test]
    fn schnorr_roundtrip() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let kp = KeyPair::generate(&mut rng);
        let m= b"Emirates";
        let sig = sign(&kp.private, m, &mut rng);
        assert!(verify(&kp.public, m, &sig))
    }

    #[test]
    fn rejects_wrong_message() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let kp = KeyPair::generate(&mut rng);
        let m= b"Emirates";
        let sig = sign(&kp.private, m, &mut rng);
        assert!(!verify(&kp.public, &[1u8], &sig))
    }

    #[test]
    fn rejects_wrong_key() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let kp1 = KeyPair::generate(&mut rng);
        let m= b"Emirates";
        let sig = sign(&kp1.private, m, &mut rng);
        let kp2 = KeyPair::generate(&mut rng);
        assert_ne!(kp1, kp2);
        assert!(!verify(&kp2.public, m, &sig));
    }

    #[test]
    fn rejects_tampered_sig() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let kp = KeyPair::generate(&mut rng);
        let m= b"Emirates";
        let mut sig = sign(&kp.private, m, &mut rng);
        assert!(verify(&kp.public, m, &sig));
        sig.s += PrivateKey::from(1u32);
        assert!(!verify(&kp.public, m, &sig))
    }

    #[test]
    fn key_recovery_from_reuse() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let k = Fr::rand(&mut rng);
        let kp = KeyPair::generate(&mut rng);
        let m1 = b"message one";
        let m2 = b"message two";
        let sig1 = sign_with_nonce (&kp.private, m1, k);
        let sig2 = sign_with_nonce(&kp.private, m2, k);
        let e1 = challenge(&sig1.r, &kp.public, m1);
        let e2 = challenge(&sig2.r, &kp.public, m2);
        let x = (sig1.s - sig2.s) / (e1 - e2);
        assert_eq!(x, kp.private)
    }

    #[test]
    fn bip340_matches_secp() {
        use secp256k1::{Secp256k1, XOnlyPublicKey, Message, schnorr::Signature as SecpSig};
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let kp = KeyPair::generate(&mut rng);
        let m = [7u8; 32];
        let sig = sign(&kp.private, &m, &mut rng);
        let pk = XOnlyPublicKey::from_slice(&x_only_bytes(&kp.public)).unwrap();
        let ssig = SecpSig::from_slice(&to_bytes(&sig)).unwrap();
        let secp = Secp256k1::verification_only();
        assert!(secp.verify_schnorr(&ssig, &Message::from_digest(m), &pk).is_ok());
    }

    #[test]
    fn from_bytes_must_lift_even_y() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let kp = KeyPair::generate(&mut rng);
        let m = b"deserialization boundary";
        let sig = sign(&kp.private, m, &mut rng);

        let errant_root = Signature { r: -sig.r, s: sig.s };
        assert_eq!(to_bytes(&sig), to_bytes(&errant_root));
        assert!(!verify(&kp.public, m, &errant_root));
        
        let parsed = sig_from_bytes(&to_bytes(&sig)).unwrap();
        assert!(verify(&kp.public, m, &parsed));
    }
}
