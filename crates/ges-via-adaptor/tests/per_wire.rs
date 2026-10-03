use ark_ec::Group;
use ark_secp256k1::{Fr, Projective};
use ark_std::UniformRand;
use ges_via_adaptor::*;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

mod common;
use common::setup;

#[test]
fn pre_verify_all_accepts_honest() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (_, _, e, _, op_sk, p) = setup(&mut rng);
    let m = b"Assert tx that is 32 bytes long.";
    let ms = [*m; 2];
    let pk = keygen(&e);
    let ps = pre_sign(&op_sk, &ms, &pk, &mut rng);
    let m_2 = b"Other assert tx that is 32 long.";
    let ms_2 = [*m_2; 2];
    assert!(pre_verify_all(&p, &ms, &pk, &ps));
    assert!(!pre_verify_all(&p, &ms_2, &pk, &ps));
    assert!(!pre_verify_all(
        &(p + Projective::generator()),
        &ms,
        &pk,
        &ps
    ));
}

#[test]
fn extractability_extract_equals_en() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (_, _, e, _, op_sk, _) = setup(&mut rng);
    let m = b"Assert tx that is 32 bytes long.";
    let ms = [*m; 2];
    let pk = keygen(&e);
    let pre = pre_sign(&op_sk, &ms, &pk, &mut rng);
    let x = [true, false];
    let claim = post(&e, &pre, &x);
    let l_x = extract_all(&pk, &pre, &claim);
    assert_eq!(garble_yao::en(&e, &x), l_x);
}

#[test]
fn end_to_end_eval_and_decode() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (circuit, gc, e, d, op_sk, _) = setup(&mut rng);
    let m = b"Assert tx that is 32 bytes long.";
    let ms = [*m; 2];
    let pk = keygen(&e);
    let pre = pre_sign(&op_sk, &ms, &pk, &mut rng);
    let x = [true, false];
    let claim = post(&e, &pre, &x);
    let l_x = extract_all(&pk, &pre, &claim);
    let l_y = garble_yao::ev(&circuit, &gc, &l_x);
    assert_eq!(garble_yao::de(&d, &l_y), Some(circuit.evaluate(&x)));
}

#[test]
fn equivocation_leaks_operator_secret_key() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (_, _, e, _, op_sk, p) = setup(&mut rng);
    let m = b"Assert tx that is 32 bytes long.";
    let ms = [*m; 2];
    let pk = keygen(&e);
    let pre = pre_sign(&op_sk, &ms, &pk, &mut rng);
    let ps = &pre.pairs[0];
    let e0 = schnorr::challenge(&(ps.zero.r + pk.pairs[0].zero), &p, m);
    let e1 = schnorr::challenge(&(ps.one.r + pk.pairs[0].one), &p, m);
    let k_recoverd = (ps.zero.s_t - ps.one.s_t) / (e0 - e1);
    assert_eq!(k_recoverd, op_sk);
}

#[test]
fn generalises_end_to_end_eval_and_decode_to_three_gate() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let circuit = circuit::fixtures::xor_and_not();
    let (gc, e, d) = garble_yao::gb(&circuit, &mut rng);
    let op_sk = Fr::rand(&mut rng);
    let m = b"Assert tx that is 32 bytes long.";
    let ms = [*m; 3];
    let pk = keygen(&e);
    let pre = pre_sign(&op_sk, &ms, &pk, &mut rng);
    let x = [true, false, true];
    let claim = post(&e, &pre, &x);
    let l_x = extract_all(&pk, &pre, &claim);
    let l_y = garble_yao::ev(&circuit, &gc, &l_x);
    assert_eq!(garble_yao::de(&d, &l_y), Some(circuit.evaluate(&x)));
}

#[test]
fn bip340_matches_secp() {
    use secp256k1::{Message, Secp256k1, XOnlyPublicKey, schnorr::Signature as SecpSig};

    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let circuit = circuit::fixtures::xor_and_not();
    let (_, e, _) = garble_yao::gb(&circuit, &mut rng);
    let op_sk = Fr::rand(&mut rng);
    let op_pk =
        XOnlyPublicKey::from_slice(&schnorr::x_only_bytes(&(Projective::generator() * op_sk)))
            .unwrap();
    let m = b"Assert tx that is 32 bytes long.";
    let ms = [*m; 3];
    let pk = keygen(&e);
    let pre = pre_sign(&op_sk, &ms, &pk, &mut rng);
    let x = [true, false, true];
    let claim = post(&e, &pre, &x);
    for sig in claim.sigs {
        let ssig = SecpSig::from_slice(&schnorr::to_bytes(&sig)).unwrap();
        assert!(
            Secp256k1::verification_only()
                .verify_schnorr(&ssig, &Message::from_digest(*m), &op_pk)
                .is_ok()
        );
    }
}
