use garble_yao::EncodingInfo;
use sha2::{Digest, Sha256};

pub type Secret = garble_yao::Label;
pub type Hash = [u8; 32];


pub struct Pair<T> { pub zero: T, pub one: T }
pub struct PublicKey { pub pairs: Vec<Pair<Hash>> }
pub struct Signature { pub secrets: Vec<Secret> }

pub fn keygen(e: &EncodingInfo) -> PublicKey {
     PublicKey { pairs: e.input_pairs.iter().map( |pair| Pair { zero: Sha256::digest(pair.zero).into(), one: Sha256::digest(pair.one).into() }).collect() }
}

pub fn sign(e: &EncodingInfo, x: &[bool]) -> Signature {
    assert_eq!(e.input_pairs.len(), x.len());

    Signature { secrets: e.input_pairs.iter().zip(x).map(|(pair, &bit)| if bit { pair.one } else { pair.zero }).collect() }
}

pub fn vrfy(pk: &PublicKey, sig: &Signature) -> bool {
    assert_eq!(pk.pairs.len(), sig.secrets.len());
    pk.pairs.iter().zip(&sig.secrets)
        .all(|(pairs, sig)| { 
            let h = <Hash>::from(Sha256::digest(sig));
            h == pairs.zero || h == pairs.one 
    })
}

pub fn extract(pk: &PublicKey, sig: &Signature) -> Vec<Secret> {
    assert_eq!(pk.pairs.len(), sig.secrets.len());
    sig.secrets.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
    use circuit::fixtures::*;
    // Tests with correctness() and extractability() map to properties 
    // in Appendix B.4 in https://eprint.iacr.org/2026/933.pdf
    #[test]
    fn correctness_roundtrip() {
        let circuit = half_adder();
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (_ , e, _) = garble_yao::gb(&circuit, &mut rng);

        let pk = keygen(&e);
        let x = [true, false];
        let sig = sign(&e, &x);
        assert!(vrfy(&pk, &sig));

    }

    #[test]
    fn extractability_extract_equals_en() {
        let circuit = half_adder();
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (_, e, _) = garble_yao::gb(&circuit, &mut rng);

        let pk = keygen(&e);
        let x = [true, false];
        let sig = sign(&e, &x);
        assert_eq!(extract(&pk, &sig), garble_yao::en(&e, &x));
    
    }

    #[test]
    fn end_to_end_eval_and_decode() {
        let circuit = half_adder();
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (gc, e, d) = garble_yao::gb(&circuit, &mut rng);

        let pk = keygen(&e);
        let x = [true, false];
        let sig = sign(&e, &x);
        let l_x = extract(&pk, &sig);
        let l_y = garble_yao::ev(&circuit, &gc, &l_x);
        let y = garble_yao::de(&d, &l_y);
        assert_eq!(Some(circuit.evaluate(&x)), y);
    }
}
    