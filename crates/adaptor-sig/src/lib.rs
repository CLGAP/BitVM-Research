use ark_secp256k1::{Fr, Projective};
use ark_ec::{Group};
use ark_std::{rand::Rng, UniformRand};
use schnorr::Signature;
// statement/witness pair fo relation: T = [t]G
pub type Statement = Projective; // T
pub type Witness = Fr;           // t, secret the signature will reveal

#[derive(PartialEq, Debug)]
pub struct PreSignature {
    pub r: Projective,
    pub s_t: Fr
}

pub fn pre_sign_with_nonce(x: &Fr, m: &[u8], t: &Statement, k: &Fr) -> PreSignature {
    let g = Projective::generator();
    let r = g * k;
    let (d, p ) = schnorr::normalize_parity(*x);
    let e = schnorr::challenge(&(r + t), &p, m);
    let s_t =  *k + e * d;
    PreSignature { r, s_t }
}

pub fn pre_sign<R: Rng>(x: &Fr, m: &[u8], t: &Statement, rng: &mut R) -> PreSignature {
    let g = Projective::generator();
    let k = loop {
        let k = Fr::rand(rng);
        if schnorr::even_y( &(g * k + t)) {
            break k;
        }
    };
    pre_sign_with_nonce(x, m, t, &k)
}

pub fn pre_verify(p: &Projective, m: &[u8], t: &Statement, ps: &PreSignature) -> bool {
    let g = Projective::generator();
    let p = if schnorr::even_y(p) {*p} else {-*p};
    let e = schnorr::challenge(&(ps.r + t), &p, m);
    g * ps.s_t == ps.r + p * e
}

pub fn adapt(ps: &PreSignature, witness: &Fr) -> Signature {
    Signature { r: ps.r + Projective::generator() * witness, s: ps.s_t + witness }
}

pub fn extract(ps: &PreSignature, sig: &Signature) -> Witness {
    sig.s - ps.s_t
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use super::*;

    #[test]
    fn pre_sign_with_nonce_is_deterministic_and_valid() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let kp = schnorr::KeyPair::generate(&mut rng);
        let m = b"asdfasdf";
        let witness = Fr::rand(&mut rng);
        let t = Projective::generator() * witness;
        let k = Fr::rand(&mut rng);

        let ps1 = pre_sign_with_nonce(&kp.private, m, &t, &k);
        let ps2 = pre_sign_with_nonce(&kp.private, m, &t, &k);
        assert_eq!(ps1, ps2);
        assert!(pre_verify(&kp.public, m, &t, &ps1));
    }

    #[test]
    fn pre_verify_roundtrip() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let kp = schnorr::KeyPair::generate(&mut rng);
        let m = b"asdfasdf";
        let witness = Fr::rand(&mut rng);
        let t = Projective::generator() * witness;
        let ps = pre_sign(&kp.private, m, &t, &mut rng);
        assert!(pre_verify(&kp.public, m, &t, &ps))
    }

    #[test]
    fn verify_accepts_adapt() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let kp = schnorr::KeyPair::generate(&mut rng);
        let m = b"asdfasdf";
        let witness = Fr::rand(&mut rng);
        let t = Projective::generator() * witness;
        let ps = pre_sign(&kp.private, m, &t, &mut rng);
        assert!(pre_verify(&kp.public, m, &t, &ps));
        let pre_as_sig = schnorr::Signature{ r: ps.r, s: ps.s_t };
        assert!(!schnorr::verify(&kp.public, m, &pre_as_sig));
        let sig = adapt(&ps, &witness);
        assert!(schnorr::verify(&kp.public, m, &sig));
    }

    #[test]
    fn extract_passes() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let kp = schnorr::KeyPair::generate(&mut rng);
        let m = b"asdfasdf";
        let witness = Fr::rand(&mut rng);
        let t = Projective::generator() * witness;
        let ps = pre_sign(&kp.private, m, &t, &mut rng);
        let sig = adapt(&ps, &witness);
        assert_eq!(sig.r - ps.r, t);
        assert_eq!(extract(&ps, &sig), witness);
    }

    #[test]
    fn atomic_swap() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let kp_alice = schnorr::KeyPair::generate(&mut rng);
        let kp_bob = schnorr::KeyPair::generate(&mut rng);
        let m_a = b"sighash(tx: spend UTXO_A -> pay Bob 1 BTC)"; //input and output would be committed by the one-byte selector, or sighashflag, `SIGHASH_ALL` 
        let m_b = b"sighash(tx: spend UTXO_B -> pay Alice 1 BTC)";
        let witness_b = Fr::rand(&mut rng);
        let t = Projective::generator() * witness_b;
        let ps_b = pre_sign(&kp_bob.private, m_b, &t, &mut rng);
        assert!(pre_verify(&kp_bob.public, m_b, &t, &ps_b)); // done by Alice, and only then does the presign
        let ps_a = pre_sign(&kp_alice.private, m_a, &t, &mut rng);
        assert!(pre_verify(&kp_alice.public, m_a, &t, &ps_a)); // done by Bob
        let sig_a = adapt(&ps_a, &witness_b); // done by Bob
        let witness_a = extract(&ps_a, &sig_a);
        assert_eq!(witness_a, witness_b);
        let sig_b = adapt(&ps_b, &witness_a); // done by Alice
        // assert below proves atomocity of leak of witness
        assert!(schnorr::verify(&kp_bob.public, m_b, &sig_b));
    }

    #[test]
   fn bip340_matches_secp() {
        use secp256k1::{Secp256k1, XOnlyPublicKey, Message, schnorr::Signature as SecpSig};
        
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let kp = schnorr::KeyPair::generate(&mut rng);
        let m = b"Thiry-two byte message standard.";
        let witness = Fr::rand(&mut rng);
        let t = Projective::generator() * witness;
        let presig = pre_sign(&kp.private, m, &t, &mut rng);
        let sig = adapt(&presig, &witness);
        let pk = XOnlyPublicKey::from_slice(&schnorr::x_only_bytes(&kp.public)).unwrap();
        let ssig = SecpSig::from_slice(&schnorr::to_bytes(&sig)).unwrap();
        assert!(Secp256k1::verification_only().verify_schnorr(
            &ssig,
            &Message::from_digest(*m),
            &pk).is_ok());
   } 
}