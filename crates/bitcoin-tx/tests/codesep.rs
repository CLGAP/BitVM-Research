use adaptor_sig::{adapt, pre_sign};
use ark_ec::Group;
use ark_secp256k1::{Fr, Projective};
use ark_std::UniformRand;
use bitcoin::{
    absolute::LockTime,
    hashes::Hash,
    opcodes::all::OP_CHECKSIGVERIFY,
    script::Builder,
    secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey},
    taproot::TaprootBuilder,
    transaction::Version,
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use bitcoin_tx::*;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

// control leaf without seperators
fn checkgs_leaf_no_sep(pk: XOnlyPublicKey, n: usize) -> ScriptBuf {
    let mut b = Builder::new();
    for _ in 0..n {
        b = b.push_x_only_key(&pk).push_opcode(OP_CHECKSIGVERIFY);
    }
    b.into_script()
}

fn fund_and_spend(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    internal: XOnlyPublicKey,
    leaf: &ScriptBuf,
) -> (Transaction, Transaction) {
    let spend_info = TaprootBuilder::new()
        .add_leaf(0, leaf.clone())
        .unwrap()
        .finalize(secp, internal)
        .unwrap();

    let funding = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::all_zeros(), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(spend_info.output_key()),
        }],
    };

    let spender = spend_assert(&funding, Sequence::MAX, Witness::new(), ScriptBuf::new());

    (funding, spender)
}

#[test]
fn codesep_makes_slots_distinct() {
    let secp = Secp256k1::new();
    let key = |b: u8| {
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[b; 32]).unwrap());
        XOnlyPublicKey::from_keypair(&kp).0
    };
    let n = 8;

    // seperators: slot 0 sentinel, every 3rd opcode after index (3s - 1)
    let slot_leaf = checkgs_leaf(key(2), n);
    let (funding, spender) = fund_and_spend(&secp, key(1), &slot_leaf);
    let pos = |s: usize| if s == 0 { u32::MAX } else { (3 * s - 1) as u32 };
    let m_slot: Vec<_> = (0..n)
        .map(|s| slot_sighash(&spender, 0, &funding.output[0], &slot_leaf, pos(s)))
        .collect();
    for a in 0..n {
        for b in (a + 1)..n {
            assert_ne!(m_slot[a], m_slot[b])
        }
    }

    // no separators
    let flat_leaf = checkgs_leaf_no_sep(key(3), n);
    let (funding_f, spender_f) = fund_and_spend(&secp, key(4), &flat_leaf);
    let m_flat: Vec<_> = (0..n)
        .map(|_| slot_sighash(&spender_f, 0, &funding_f.output[0], &flat_leaf, u32::MAX))
        .collect();
    for i in 1..n {
        assert_eq!(m_flat[0], m_flat[i])
    }
}

#[test]
fn slot_signature_binds_to_position() {
    let secp = Secp256k1::new();
    let key = |b: u8| {
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[b; 32]).unwrap());
        XOnlyPublicKey::from_keypair(&kp).0
    };
    let n = 8;
    let slot_leaf = checkgs_leaf(key(2), n);
    let (funding, spender) = fund_and_spend(&secp, key(1), &slot_leaf);
    let pos = |s: usize| if s == 0 { u32::MAX } else { (3 * s - 1) as u32 };
    let m_slot: Vec<_> = (0..n)
        .map(|s| slot_sighash(&spender, 0, &funding.output[0], &slot_leaf, pos(s)))
        .collect();

    let msgs: Vec<[u8; 32]> = m_slot.iter().map(|m| m.to_byte_array()).collect();
    let mut rng = ChaCha20Rng::seed_from_u64(42);

    let g = Projective::generator();

    // slot key: joint key whose shares are (at least partially) deleted after presigning
    let x_slot = Fr::rand(&mut rng);
    let mut sigs = Vec::with_capacity(msgs.len());

    for s in &msgs {
        let t = Fr::rand(&mut rng);
        let statement = g * t;
        let ps = pre_sign(&x_slot, s, &statement, &mut rng);
        let sig = adapt(&ps, &t);
        sigs.push(sig);
    }

    let p_slot = g * x_slot;

    for (s, j) in (0..n).flat_map(|s| (0..n).map(move |j| (s, j))) {
        if j == s {
            assert!(schnorr::verify(&p_slot, &msgs[s], &sigs[j]))
        } else {
            assert!(!schnorr::verify(&p_slot, &msgs[s], &sigs[j]))
        }
    }
}
