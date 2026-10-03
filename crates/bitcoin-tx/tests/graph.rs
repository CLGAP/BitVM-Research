use bitcoin::{hashes::{sha256, Hash}, secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey, Message}, Amount, OutPoint, taproot::LeafVersion, Txid, Sequence, opcodes::all::OP_CSV, ScriptBuf};
use bitcoin_tx::*;
mod common;
use common::*;

#[test]
fn assert_output_has_two_leaves() {
    let f = assert_fixture();
    let tx = assert_tx(OutPoint::new(Txid::all_zeros(), 0), FUND, &f.taptree);
    assert_eq!(f.taptree.spend_info.script_map().len(), 2);
    assert!(tx.output[0].script_pubkey.is_p2tr());
}

#[test]
fn disprove_witness_matches_challenge_leaf() {
    let f = assert_fixture();
    assert_eq!(sha256::Hash::hash(&f.pre_image), f.h);
    let assert = assert_tx(OutPoint::new(Txid::all_zeros(), 0), FUND, &f.taptree);
    let disprove = disprove_tx(OutPoint::new(assert.compute_txid(), 0), assert.output[0].value, &f.taptree, &f.pre_image, ScriptBuf::new());
    assert_eq!(disprove.input[0].previous_output, OutPoint::new(assert.compute_txid(), 0));
    let witness = &disprove.input[0].witness;
    assert_eq!(witness.len(), 3);
    assert_eq!(witness.nth(0).unwrap(), &f.pre_image[..]);
    assert_eq!(witness.nth(1).unwrap(), f.taptree.challenge.as_bytes());

    spend_sighash(&disprove, 0, &assert.output[0], &f.taptree.challenge); 
}

#[test]
fn timeout_encodes_relative_timelock_and_p2tr_output() {
    let f = assert_fixture();
    let assert = assert_tx(OutPoint::new(Txid::all_zeros(), 0), FUND, &f.taptree);
    let timeout = timeout_tx(OutPoint::new(assert.compute_txid(), 0), assert.output[0].value, f.t, ScriptBuf::new());
    assert_eq!(timeout.input[0].previous_output, OutPoint::new(assert.compute_txid(), 0)); 
    //nSeq encodes relative timelock CSV will enforce
    assert_eq!(&timeout.input[0].sequence, &Sequence::from_height(f.t));
    assert!(&timeout.input[0].sequence.is_relative_lock_time());

    assert!(f.taptree.timeout.as_bytes().contains(&OP_CSV.to_u8()));

    spend_sighash(&timeout, 0, &assert.output[0], &f.taptree.timeout);
}

#[test]
fn wrong_label_hash_fails() {
    let f = assert_fixture();
    let wrong = b"incorrect label";
    assert_ne!(sha256::Hash::hash(wrong), f.h);
}

#[test]
fn outputs_pay_fee_and_clear_dust() {
    const MIN_P2TR_DUST: Amount = Amount::from_sat(330);
    let f = assert_fixture();
    let assert = assert_tx(OutPoint::new(Txid::all_zeros(), 0), FUND, &f.taptree);
    let timeout = timeout_tx(OutPoint::new(assert.compute_txid(), 0), assert.output[0].value, f.t, ScriptBuf::new());
    let disprove = disprove_tx(OutPoint::new(assert.compute_txid(), 0), assert.output[0].value, &f.taptree, &f.pre_image, ScriptBuf::new());
    assert_eq!(assert.output[0].value - FEE, timeout.output[0].value);
    assert_eq!(assert.output[0].value - FEE, disprove.output[0].value);
    assert!(timeout.output[0].value >= MIN_P2TR_DUST); 
    assert!(disprove.output[0].value >= MIN_P2TR_DUST);
}

#[test]
fn settle_is_well_formed_key_spend() {
    let f = assert_fixture();
    let assert = assert_tx(OutPoint::new(Txid::all_zeros(), 0), FUND,&f.taptree);
    let settle = settle_tx(&assert, ScriptBuf::new());
    assert_eq!(settle.input[0].previous_output, OutPoint::new(assert.compute_txid(), 0));
    assert_eq!(settle.input[0].witness.len(), 1);
    key_spend_sighash(&settle, 0, &assert.output[0]);
}

#[test]
fn timeout_sig_verifies() {
    use ark_ff::PrimeField;
    use bitcoin::secp256k1::schnorr::Signature as SecpSig;
    use rand::SeedableRng;

    let f = assert_fixture();
    let secp = Secp256k1::new();
    // Signed with the local schnorr crate; secp is the referee. Same secret
    // bytes as the fixture's key(2), read big-endian to match the leaf's pk_op.
    let x_op = ark_secp256k1::Fr::from_be_bytes_mod_order(&[2u8; 32]);
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(7);
    let assert = assert_tx(OutPoint::new(Txid::all_zeros(), 0), FUND, &f.taptree);
    let mut timeout = timeout_tx(OutPoint::new(assert.compute_txid(), 0), assert.output[0].value, f.t, ScriptBuf::new());
    let sig = sign_timeout(&timeout, 0, &assert.output[0], &f.taptree.timeout, &x_op, &mut rng);
    attach_timeout_sig(&mut timeout, &f.taptree, &sig);

    let msg = Message::from_digest(
        spend_sighash(&timeout, 0, &assert.output[0], &f.taptree.timeout).to_byte_array()
    );
    let ssig = SecpSig::from_slice(&schnorr::to_bytes(&sig)).unwrap();
    let kp_op = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[2u8; 32]).unwrap());
    let pk_op = XOnlyPublicKey::from_keypair(&kp_op).0;
    assert!(secp.verify_schnorr(&ssig, &msg, &pk_op).is_ok());

    let kp_wrong = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[3u8; 32]).unwrap());
    let pk_kp_wrong = XOnlyPublicKey::from_keypair(&kp_wrong).0;
    assert!(secp.verify_schnorr(&ssig, &msg, &pk_kp_wrong).is_err());

    assert_eq!(
        timeout.input[0].witness.nth(0).unwrap(),
        &schnorr::to_bytes(&sig)[..]
    );
}

#[test]
fn bond_tree_has_single_checkgs_leaf() {
    let f = bond_fixture(W);
    assert_eq!(f.taptree.spend_info.script_map().len(), 1);
    assert!(f.taptree.output.is_p2tr());
    assert!(f.taptree.spend_info.script_map().contains_key(&(f.taptree.gs.clone(), LeafVersion::TapScript)));
}