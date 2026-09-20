use ark_ec::Group;
use ark_secp256k1::{Fr, Projective};
use ark_std::UniformRand;
use bitcoin_tx::*;
use bitcoin::{OutPoint, Txid, TxOut, ScriptBuf, hashes::Hash, secp256k1::{Secp256k1, XOnlyPublicKey, Keypair, SecretKey}, Amount};
use garble_yao::{DecodingInfo, EncodingInfo, GarbledCircuit};
use ges_via_adaptor::{extract_all};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

mod common;
use common::*;

fn setup(
    rng: &mut ChaCha20Rng,
) -> (
    circuit::Circuit,
    GarbledCircuit,
    EncodingInfo,
    DecodingInfo,
    Fr,
    Projective,
) {
    let circuit = circuit::fixtures::half_adder();
    let (gc, e, d) = garble_yao::gb(&circuit, rng);
    let x_key = Fr::rand(rng);
    let p = Projective::generator() * x_key;
    (circuit, gc, e, d, x_key, p)
}

struct Seam {
    f: AssertFixture,
    bond: OutPoint,
    bond_prevout: TxOut,
    p: Projective,
    m: [u8; 32],
    e: EncodingInfo,
    pk: ges_via_adaptor::PublicKey,
    pre: ges_via_adaptor::PreSigs,
    claim: ges_via_adaptor::Claim,
    x: [bool; 2],
}

fn claim_over_assert() -> Seam {
    let secp = Secp256k1::new();
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (_, _, e, _, op_sk, p) = setup(&mut rng);

    let f = assert_fixture();
    let bond = OutPoint::new(Txid::all_zeros(), 0);
    let assert = assert_tx(bond, FUND, &f.taptree);

    let op_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[2u8; 32]).unwrap())
    ).0;
    let bond_prevout = TxOut {
        value: FUND,
        script_pubkey: ScriptBuf::new_p2tr(&secp, op_key, None),
    };

    let m = key_spend_sighash(&assert, 0, &bond_prevout).to_byte_array();
    let ms = [m; 2];
    let x = [true, false];
    let (pk, pre, claim, _) = claim_and_extract_labels(&e, &op_sk, &x, &ms, &mut rng);
    Seam { f, bond, bond_prevout, p, m, e, pk, pre, claim, x }
}

#[test]
fn assert_reveals_label() {
    let s = claim_over_assert();
    for sig in &s.claim.sigs { assert!(schnorr::verify(&s.p, &s.m, sig)) }
    let l_x = extract_all(&s.pk, &s.pre, &s.claim);
    assert_eq!(garble_yao::en(&s.e, &s.x), l_x);
}

#[test]
fn completion_bound_to_assert() {
    let s = claim_over_assert();
    let assert2 = assert_tx(s.bond, FUND - Amount::from_sat(1), &s.f.taptree);
    let m2 = key_spend_sighash(&assert2, 0, &s.bond_prevout).to_byte_array();
    for sig in &s.claim.sigs { assert!(!schnorr::verify(&s.p, &m2, sig)) }
}