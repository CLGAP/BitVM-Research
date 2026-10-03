pub mod wide;

use adaptor_sig::PreSignature;
use ark_ec::Group;
use ark_ff::{BigInteger, PrimeField};
use ark_secp256k1::{Fr, Projective};
use ark_std::{UniformRand, rand::Rng};
use garble_yao::{EncodingInfo, Label};
use schnorr::Signature;

pub struct Pair<T> {
    pub zero: T,
    pub one: T,
}

pub struct PublicKey {
    pub pairs: Vec<Pair<Projective>>,
}
pub struct PreSigs {
    pub pairs: Vec<Pair<PreSignature>>,
}

pub struct Claim {
    pub sigs: Vec<Signature>,
}

// covnersion of bytes for ECP reduces sampling (security) due to method
pub fn keygen(e: &EncodingInfo) -> PublicKey {
    let g = Projective::generator();
    PublicKey {
        pairs: e
            .input_pairs
            .iter()
            .map(|pair| Pair {
                zero: g * Fr::from_le_bytes_mod_order(&pair.zero),
                one: g * Fr::from_le_bytes_mod_order(&pair.one),
            })
            .collect(),
    }
}

pub fn pre_sign<R: Rng>(x: &Fr, ms: &[[u8; 32]], pk: &PublicKey, rng: &mut R) -> PreSigs {
    assert_eq!(pk.pairs.len(), ms.len());
    PreSigs {
        pairs: pk
            .pairs
            .iter()
            .zip(ms)
            .map(|(pair, m)| {
                loop {
                    let k = Fr::rand(rng);
                    if let (Ok(zero), Ok(one)) = (
                        adaptor_sig::pre_sign_with_nonce(x, m, &pair.zero, &k),
                        adaptor_sig::pre_sign_with_nonce(x, m, &pair.one, &k),
                    ) {
                        break Pair { zero, one };
                    }
                }
            })
            .collect(),
    }
}

pub fn post(e: &EncodingInfo, pre: &PreSigs, x: &[bool]) -> Claim {
    Claim {
        sigs: pre
            .pairs
            .iter()
            .zip(e.input_pairs.iter())
            .zip(x)
            .map(|((ps_pair, e_pair), b)| {
                if *b {
                    adaptor_sig::adapt(&ps_pair.one, &Fr::from_le_bytes_mod_order(&e_pair.one))
                } else {
                    adaptor_sig::adapt(&ps_pair.zero, &Fr::from_le_bytes_mod_order(&e_pair.zero))
                }
            })
            .collect(),
    }
}

pub fn extract_all(pk: &PublicKey, pre: &PreSigs, claim: &Claim) -> Vec<Label> {
    let g = Projective::generator();
    pre.pairs
        .iter()
        .zip(claim.sigs.iter())
        .zip(pk.pairs.iter())
        .map(|((ps_pair, sig), pk_pair)| {
            let t0 = adaptor_sig::extract(&ps_pair.zero, sig);
            if g * t0 == pk_pair.zero {
                scalar_to_label(&t0)
            } else {
                let t1 = adaptor_sig::extract(&ps_pair.one, sig);
                assert_eq!(
                    g * t1,
                    pk_pair.one,
                    "extracted label matches neither statement"
                );
                scalar_to_label(&t1)
            }
        })
        .collect()
}

pub fn pre_verify_all(p: &Projective, ms: &[[u8; 32]], pk: &PublicKey, pre: &PreSigs) -> bool {
    pk.pairs
        .iter()
        .zip(pre.pairs.iter())
        .zip(ms)
        .all(|((pk_pair, ps_pair), m)| {
            adaptor_sig::pre_verify(p, m, &pk_pair.zero, &ps_pair.zero)
                && adaptor_sig::pre_verify(p, m, &pk_pair.one, &ps_pair.one)
        })
}

fn scalar_to_label(s: &Fr) -> Label {
    let bytes = s.into_bigint().to_bytes_le();
    let mut l = [0u8; 32];
    l.copy_from_slice(&bytes[..32]);
    l
}
