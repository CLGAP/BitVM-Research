use ark_ec::Group;
use ark_secp256k1::Projective;
use bitcoin_tx::*;
use bitcoin::{OutPoint, Txid, TxOut, ScriptBuf, hashes::Hash, Amount};
use garble_yao::EncodingInfo;
use ges_via_adaptor::{extract_all, pre_verify_all};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

mod common;
use common::*;

struct Seam {
    f: AssertFixture,
    bond: OutPoint,
    bond_prevout: TxOut,
    gs: ScriptBuf,
    p: Projective,
    ms: Vec<[u8; 32]>,
    e: EncodingInfo,
    pk: ges_via_adaptor::PublicKey,
    pre: ges_via_adaptor::PreSigs,
    claim: ges_via_adaptor::Claim,
    x: [bool; 2],
}

fn claim_over_bond() -> Seam {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let f = assert_fixture();
    let bf = bond_fixture(W);
    let p = Projective::generator() * bf.op_sk;

    let bond = OutPoint::new(Txid::all_zeros(), 0);
    let assert = assert_tx(bond, FUND, &f.taptree);
    let bond_prevout = TxOut { value: FUND, script_pubkey: bf.taptree.output.clone() };

    let ms = slot_sighashes(&assert, 0, &bond_prevout, &bf.taptree.gs, bf.e.input_pairs.len() / W);
    let x = [true, false];
    let (pk, pre, claim, _) = claim_and_extract_labels(&bf.e, &bf.op_sk, &x, &ms, &mut rng);
    Seam { f, bond, bond_prevout, gs: bf.taptree.gs, p, ms, e: bf.e, pk, pre, claim, x }
}

#[test]
fn assert_reveals_label() {
    let s = claim_over_bond();
    assert!(pre_verify_all(&s.p, &s.ms, &s.pk, &s. pre));
    for (sig, m) in s.claim.sigs.iter().zip(&s.ms) { assert!(schnorr::verify(&s.p, m, sig)) }
    let l_x = extract_all(&s.pk, &s.pre, &s.claim);
    assert_eq!(garble_yao::en(&s.e, &s.x), l_x);
}

#[test]
fn completion_bound_to_assert() {
    let s = claim_over_bond();
    let assert2 = assert_tx(s.bond, FUND - Amount::from_sat(1), &s.f.taptree);
    let ms2 = slot_sighashes(&assert2, 0, &s.bond_prevout, &s.gs, s.ms.len());
    for (sig, m2) in s.claim.sigs.iter().zip(&ms2) { assert!(!schnorr::verify(&s.p, m2, sig)) }

    let bond2 = OutPoint::new(Txid::from_byte_array([1u8; 32]), 1);
    let assert3 = assert_tx(bond2, FUND, &s.f.taptree);
    let ms3 = slot_sighashes(&assert3, 0, &s.bond_prevout, &s.gs, s.ms.len());
    for (sig, m3) in s.claim.sigs.iter().zip(&ms3) { assert!(!schnorr::verify(&s.p, m3, sig))}
}