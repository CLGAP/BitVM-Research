// Made by Opus 4.8

// Phase-1 regtest hex printers (both #[ignore]d, run explicitly).
//
// Scope: validate the two spend paths of the Assert *output* taptree --
// Disprove (challenge hashlock) and Timeout (CSV + BIP340 sig) -- on a live
// regtest node. The Assert transaction itself is NOT tested here: it spends
// the bond via the CheckGS gadget, whose witness is adaptor completions
// (Phase 2). Instead the funded UTXO plays the role of the Assert output, and
// Disprove/Timeout spend it directly.
//
// `print_fund_address` prints the bonded taptree address; `print_spend_hex`
// reads FUND_TXID / FUND_VOUT / DEST and emits DISPROVE_HEX + TIMEOUT_HEX.
// The scripts/regtest.zsh helpers drive the whole loop in one command:
//   source scripts/regtest.zsh
//   rt_disprove          # fund -> spend challenge leaf -> mine -> confirm spent
//   rt_timeout           # fund -> mature t confs -> spend timeout leaf

use bitcoin::{
    absolute::LockTime,
    address::NetworkUnchecked,
    consensus::encode::serialize_hex,
    secp256k1::{Keypair, Secp256k1, SecretKey},
    taproot::LeafVersion,
    transaction::Version,
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};
use bitcoin_tx::*;

mod common;
use common::*;

// Same value we fund with (0.001 BTC); Assert/child outputs subtract FEE.
const FUND: Amount = Amount::from_sat(100_000);

#[test]
#[ignore = "regtest: prints the bonded taptree address to fund"]
fn print_fund_address() {
    let f = fixture();
    let addr = Address::from_script(&f.taptree.output, Network::Regtest)
        .expect("taptree output is a valid p2tr script");
    println!("\nFUND THIS ADDRESS (regtest):\n{addr}\n");
    println!("then: FUND_TXID=<txid> FUND_VOUT=<n> to print spend hex");
}

#[test]
#[ignore = "regtest: prints Assert/Disprove/Timeout hex for a funded outpoint"]
fn print_spend_hex() {
    let txid: Txid = std::env::var("FUND_TXID")
        .expect("set FUND_TXID")
        .parse()
        .expect("FUND_TXID must be a hex txid");
    let vout: u32 = std::env::var("FUND_VOUT")
        .expect("set FUND_VOUT")
        .parse()
        .expect("FUND_VOUT must be an integer");
    // The funded UTXO IS the Assert output (the challenge+timeout taptree).
    // Phase 1 spends it directly via Disprove / Timeout; the real Assert
    // transaction that would create this output needs the CheckGS witness
    // (adaptor completions), which is Phase 2 -- so Assert is not broadcast here.
    let spent = OutPoint::new(txid, vout);
    let f = fixture();
    let prevout = TxOut { value: FUND, script_pubkey: f.taptree.output.clone() };

    // Redirect the spend to a real destination from `getnewaddress`
    // (the empty-script stub in lib.rs is non-standard on regtest).
    let dest: ScriptBuf = std::env::var("DEST")
        .expect("set DEST to a regtest address (btc -rpcwallet=t getnewaddress)")
        .parse::<Address<NetworkUnchecked>>()
        .expect("DEST must be a bech32 address")
        .require_network(Network::Regtest)
        .expect("DEST must be a regtest address")
        .script_pubkey();

    // Disprove: script-path spend of the challenge leaf. Witness is a hashlock
    // opening (preimage, leaf, control block); no signature, so nothing commits
    // to the output. Built here (rather than disprove_tx) to spend `spent`.
    let control = f
        .taptree
        .spend_info
        .control_block(&(f.taptree.challenge.clone(), LeafVersion::TapScript))
        .expect("challenge leaf in tree");
    let mut w = Witness::new();
    w.push(&f.pre_image);
    w.push(f.taptree.challenge.as_bytes());
    w.push(control.serialize());
    let disprove = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn { previous_output: spent, script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: w }],
        output: vec![TxOut { value: FUND - FEE, script_pubkey: dest.clone() }],
    };

    // Timeout: script-path spend of the timeout leaf (CSV + BIP340 sig).
    // The signature commits to the output (Default sighash), so set dest first.
    let secp = Secp256k1::new();
    let kp_op = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[2u8; 32]).unwrap());
    let mut timeout = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn { previous_output: spent, script_sig: ScriptBuf::new(), sequence: Sequence::from_height(f.t), witness: Witness::new() }],
        output: vec![TxOut { value: FUND - FEE, script_pubkey: dest }],
    };
    let sig = sign_timeout(&timeout, 0, &prevout, &f.taptree.timeout, &secp, &kp_op);
    attach_timeout_sig(&mut timeout, &f.taptree, &sig);

    println!("\n# spending the funded Assert-output UTXO: {spent}");
    println!("# challenge preimage (Disprove witness item 0): {}", hex(&f.pre_image));
    println!("# timeout relative locktime: {} blocks (needs that many confs on the UTXO)\n", f.t);
    println!("DISPROVE_HEX={}", serialize_hex(&disprove));
    println!("TIMEOUT_HEX={}", serialize_hex(&timeout));
    println!("\n# Disprove is spendable now; Timeout only after {} confirmations.", f.t);
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
