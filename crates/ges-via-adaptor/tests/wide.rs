use ark_ff::{One, BigInteger, PrimeField};
use ark_ec::Group;
use ark_secp256k1::{Fr, Projective};
use garble_yao::{DecodingInfo, EncodingInfo, GarbledCircuit};
use ges_via_adaptor::wide::{wide_setup, WideSecrets, WideSetup, wide_pre_verify, wide_post, wide_extract};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::collections::HashSet;

mod common;
//use hald-adder circuit
use common::setup;

type CommonSetup = (
    circuit::Circuit,
    GarbledCircuit,
    EncodingInfo,
    DecodingInfo,
    Fr,
    Projective,
);

fn fixture(w: usize, rng: &mut ChaCha20Rng) -> (CommonSetup, Vec<[u8; 32]>, WideSetup, WideSecrets) {
    let (circuit, gc, e, d, op_sk, p) = setup(rng);
    let slots = e.input_pairs.len() / w;
    let ms: Vec<[u8; 32]> = (0..slots).map(|i| [i as u8; 32]).collect();
    let (pre_setup, secrets) = wide_setup(&e, rng, w, &ms, &op_sk);
    ((circuit, gc, e, d, op_sk, p), ms, pre_setup, secrets)
}

fn round_trip(w: usize) {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let ((circuit, gc, e, d, _op_sk, p), ms, wide_setup, wide_secrets) = fixture(w, &mut rng);
    assert!(wide_pre_verify(&wide_setup, &ms, &p));
    let x =  [true, false];
    let sigs = wide_post(&wide_secrets, &x, &wide_setup);
    let labels = wide_extract(&wide_setup, &sigs); 
    assert_eq!(labels, garble_yao::en(&e, &x));
    let ev_labels = garble_yao::ev(&circuit, &gc, &labels);
    assert_eq!(garble_yao::de(&d, &ev_labels), Some(circuit.evaluate(&x)));
}

#[test]
fn group_order_valid() {
    assert_eq!(garble_yao::N_LE.to_vec(), Fr::MODULUS.to_bytes_le())
}

#[test]
fn round_trip_w1_multi_slot() { round_trip(1); }

#[test]
fn round_trip_w2_multi_candidate() { round_trip(2); }

#[test]
fn corruption_fails_pre_verify() { 
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let ((_circuit, _gc, _e, _d, _op_sk, p), ms, wide_setup, _wide_secrets) = fixture(2, &mut rng);
    assert!(wide_pre_verify(&wide_setup, &ms, &p));
    
    let mut corrupt_wide_setup = wide_setup.clone();
    corrupt_wide_setup.candidates[0][0].statement += Projective::generator();
    assert!(!wide_pre_verify(&corrupt_wide_setup, &ms, &p));
    
    let mut corrupt_wide_setup = wide_setup.clone();
    corrupt_wide_setup.candidates[0][0].pre_sig.s_t += Fr::one();
    assert!(!wide_pre_verify(&corrupt_wide_setup, &ms, &p));

    let mut corrupt_ms = ms.clone();
    corrupt_ms[0][0] ^= 1;
    assert!(!wide_pre_verify(&wide_setup, &corrupt_ms, &p));
    assert!(!wide_pre_verify(&wide_setup, &ms, &(p + Projective::generator())));
}

#[test]
fn unique_nonces_across_candidates() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let ((_circuit, _gc, _e, _d, _op_sk, _p), _ms, wide_setup, _wide_secrets) = fixture(2, &mut rng);
    let mut seen = HashSet::new();
    for cs in &wide_setup.candidates{
        for c in cs {
            // Suppose k generates R, n-k gen. -R.  x-only collapses R and -R
            // to some x coordinate: their mirrored nonces are flagged. Intended
            // behaviour as this would lead to key leak.
            assert!(seen.insert(schnorr::x_only_bytes(&c.pre_sig.r)));
        }
    }
}
