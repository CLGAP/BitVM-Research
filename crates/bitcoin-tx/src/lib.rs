use bitcoin::{script::Builder, secp256k1::{Secp256k1, Verification, XOnlyPublicKey, Message, Keypair, All, schnorr::Signature}, key::UntweakedPublicKey, ScriptBuf, taproot::{TaprootBuilder, TaprootSpendInfo, LeafVersion, TapLeafHash}, Transaction, transaction::{Version}, OutPoint, Amount, absolute::LockTime, TxIn, TxOut, Sequence, Witness, sighash::{Prevouts, SighashCache}, TapSighash, TapSighashType, hashes::Hash};
use bitcoin::opcodes::all::{OP_SHA256, OP_EQUAL, OP_CSV, OP_DROP, OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CODESEPARATOR};
use garble_yao::{EncodingInfo, Label};
use ges_via_adaptor::{keygen, pre_sign, post, extract_all, Claim, PreSigs, PublicKey};
use ark_std::rand::Rng;
use ark_secp256k1::Fr;
pub struct AssertTaptree {
    pub spend_info: TaprootSpendInfo,
    pub challenge: ScriptBuf, // hashlock
    pub timeout: ScriptBuf, // csv & sig
    pub output: ScriptBuf, // PT2R spk
}

pub const FEE: Amount = Amount::from_sat(1000);

fn challenge_leaf(h: [u8; 32]) -> ScriptBuf {
    Builder::new()
        .push_opcode(OP_SHA256)
        .push_slice(h)
        .push_opcode(OP_EQUAL)
        .into_script()
}

fn timeout_leaf(t: u16, pk: XOnlyPublicKey) -> ScriptBuf {
    Builder::new()
        .push_int(t as i64)
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_x_only_key(&pk)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

// n-slot per digit-leaf: ( <pk_slot> CHECKSIGVERIFY CODESEPERATOR) x n
// pk_slot: jointly generated at setup, secrete shares deleted; nobody can fresh-sign
pub fn checkgs_leaf(pk_slot: XOnlyPublicKey, n: usize) -> ScriptBuf {
    let mut b = Builder::new();
    for _ in 0..n {
        b = b.push_x_only_key(&pk_slot).push_opcode(OP_CHECKSIGVERIFY).push_opcode(OP_CODESEPARATOR)
    }
    b.into_script()
}

pub fn build_assert_taptree(secp: &Secp256k1<impl Verification>,internal_key: UntweakedPublicKey, h: [u8; 32], t: u16, pk_op: XOnlyPublicKey) -> AssertTaptree {
    let challenge = challenge_leaf(h);
    let timeout = timeout_leaf(t, pk_op);
    let spend_info = TaprootBuilder::new()
        .add_leaf(1, challenge.clone()).unwrap()
        .add_leaf(1, timeout.clone()).unwrap()
        .finalize(secp, internal_key).unwrap(); // Taptree merkle root
    let output = ScriptBuf::new_p2tr_tweaked(spend_info.output_key());
    AssertTaptree { 
        spend_info, challenge, timeout, output
    }
}

pub fn assert_tx(bond: OutPoint, value: Amount, tree: &AssertTaptree)-> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn { previous_output: bond, script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new()}],
        output: vec![TxOut { value, script_pubkey: tree.output.clone() }],
    }
}

pub fn spend_assert(assert: &Transaction, sequence: Sequence, witness: Witness, pay_to: ScriptBuf) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: assert.compute_txid(), vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence,
            witness,
        }],
            output: vec![TxOut {
            value: assert.output[0].value - FEE,
            script_pubkey: pay_to
        }]
    }
}

pub fn disprove_tx(assert: &Transaction, tree: &AssertTaptree, pre_image: &[u8]) -> Transaction {
    let control_block = tree.spend_info
            .control_block(&(tree.challenge.clone(), LeafVersion::TapScript))
            .expect("challenge leaf must be in the tree");

    let mut witness = Witness::new();
    witness.push(pre_image);
    witness.push(tree.challenge.as_bytes());
    witness.push(control_block.serialize());

   // stub spk; real: slash to challenger bounty and/or reserve pot
   spend_assert(assert, Sequence::MAX, witness, ScriptBuf::new())
}

pub fn timeout_tx(assert: &Transaction, t: u16) -> Transaction {
    let witness = Witness::new();
    
    // stub spk; real: reclaim bond to operator (P2TR pk_op)
    spend_assert(assert, Sequence::from_height(t), witness, ScriptBuf::new())
}

pub fn spend_sighash(tx: &Transaction, i: usize, prevout: &TxOut, leaf: &ScriptBuf) -> TapSighash {
    let leaf_hash = TapLeafHash::from_script(leaf, LeafVersion::TapScript);
    SighashCache::new(tx).taproot_script_spend_signature_hash(
        i,
        &Prevouts::All(std::slice::from_ref(prevout)),
        leaf_hash,
        TapSighashType::Default
    ).unwrap()
}

pub fn slot_sighash(tx: &Transaction, i: usize, prevout: &TxOut, leaf: &ScriptBuf, codesep_pos: u32) -> TapSighash {
    let leaf_hash = TapLeafHash::from_script(leaf, LeafVersion::TapScript);
    SighashCache::new(tx).taproot_signature_hash(
        i,
        &Prevouts::All(std::slice::from_ref(prevout)), 
        None, 
        Some((leaf_hash, codesep_pos)), 
        TapSighashType::Default).unwrap()
}

pub fn settle_tx(assert: &Transaction, settle_to: ScriptBuf) -> Transaction {
    let mut witness = Witness::new();
    witness.push([0u8; 64]);

    spend_assert(assert, Sequence::MAX, witness, settle_to)
}

pub fn key_spend_sighash(tx: &Transaction, i: usize, prevout: &TxOut) -> TapSighash {
    SighashCache::new(tx)
        .taproot_key_spend_signature_hash(
            i,
            &Prevouts::All(std::slice::from_ref(prevout)),
            TapSighashType::Default
        ).unwrap()
}

pub fn claim_and_extract_labels<R: Rng>(e: &EncodingInfo, op_sk: &Fr, pi: &[bool], sighash: &[u8], rng: &mut R) -> (PublicKey, PreSigs, Claim, Vec<Label>) {
    let pk = keygen(e);
    let pre = pre_sign(op_sk, sighash, &pk, rng);
    let claim = post(e, &pre, pi);
    let l_pi = extract_all(&pk, &pre, &claim);
    (pk, pre, claim, l_pi)
}

pub fn sign_timeout(tx: &Transaction, i: usize, prevout: &TxOut, leaf: &ScriptBuf, secp: &Secp256k1<All>, kp: &Keypair) -> Signature {
    let sighash = spend_sighash(tx, i, prevout, leaf);
    let msg = Message::from_digest(sighash.to_byte_array());
    secp.sign_schnorr_no_aux_rand(&msg, kp) //can later update to use native schnorr
}

pub fn attach_timeout_sig(tx: &mut Transaction, tree: &AssertTaptree, sig: &Signature) {
    let control_block = tree.spend_info
        .control_block(&(tree.timeout.clone(), LeafVersion::TapScript))
        .expect("timeout leaf must be in the tree");

    let mut witness = Witness::new();
    witness.push(sig.serialize());
    witness.push(tree.timeout.as_bytes());
    witness.push(control_block.serialize());
    tx.input[0].witness = witness
}