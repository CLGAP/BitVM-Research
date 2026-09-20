// Made in part with Opus 4.8

// Regtest hex printers (all #[ignore]d, run explicitly via scripts/regtest.zsh).
//
// Phase 1 (print_fund_address / print_spend_hex): the two spend paths of the
// Assert *output* taptree -- Disprove (challenge hashlock) and Timeout (CSV +
// BIP340 sig) -- against a wallet-funded stand-in UTXO.
// Phase 2 (print_bond_address / print_assert_hex): the real thing -- Assert
// spends the bond via the CheckGS gadget, its witness the per-slot adaptor
// completions (BIP340-ported schnorr/adaptor-sig/ges-via-adaptor), each slot
// signing its own codesep-distinguished sighash. print_spend_hex then Disproves
// the REAL Assert output (SPEND_VALUE=99000 overrides the funded amount).
//
// One-command drivers in scripts/regtest.zsh:
//   rt_disprove          # Phase 1: fund stand-in -> Disprove
//   rt_timeout           # Phase 1: fund stand-in -> mature CSV -> Timeout
//   rt_assert            # Phase 2: fund bond -> Assert through consensus
//   rt_disprove_assert   # Phase 2 full path: bond -> Assert -> Disprove

use bitcoin::{
    address::NetworkUnchecked,
    consensus::encode::serialize_hex,
    Address, Amount, Network, OutPoint, ScriptBuf, TxOut, Txid,
};
use bitcoin_tx::*;

mod common;
use common::*;


#[test]
#[ignore = "regtest: prints the bonded taptree address to fund"]
fn print_fund_address() {
    let f = assert_fixture();
    let addr = Address::from_script(&f.taptree.output, Network::Regtest)
        .expect("taptree output is a valid p2tr script");
    println!("\nFUND THIS ADDRESS (regtest):\n{addr}\n");
    println!("then: FUND_TXID=<txid> FUND_VOUT=<n> to print spend hex");
}

#[test]
#[ignore = "regtest: prints the bond (CheckGS) address to fund"]
fn print_bond_address() {
    let f = bond_fixture();
    let addr = Address::from_script(&f.taptree.output, Network::Regtest)
        .expect("tapree output is valid p2tr script");
    println!("\nFUND THIS ADDRESS (regtest):\n{addr}\n");
    println!("then: FUND_TXID=<txid> FUND_VOUT=<n> to print spend hex");
}

#[test]
#[ignore = "regtest: prints Assert/Disprove/Timeout hex for a funded outpoint"]
fn print_spend_hex() {
    use ark_ff::PrimeField;
    use rand::SeedableRng;
   
    let txid: Txid = std::env::var("FUND_TXID")
        .expect("set FUND_TXID")
        .parse()
        .expect("FUND_TXID must be a hex txid");
    let vout: u32 = std::env::var("FUND_VOUT")
        .expect("set FUND_VOUT")
        .parse()
        .expect("FUND_VOUT must be an integer");
    let value: Amount = std::env::var("SPEND_VALUE")
        .map_or(FUND,|v| Amount::from_sat(v.parse().expect("SPEND_VALUE in sats")));

    // The spent UTXO carries the Assert-output taptree: either a wallet-funded
    // stand-in (Phase 1, value = FUND) or the real Assert's output[0]
    // (rt_disprove_assert, value = FUND - FEE via SPEND_VALUE).
    let spent = OutPoint::new(txid, vout);
    let f = assert_fixture();
    let prevout = TxOut { value, script_pubkey: f.taptree.output.clone() };

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
    // to the output.
    let disprove = disprove_tx(spent, value, &f.taptree, &f.pre_image, dest.clone());

    // Timeout: script-path spend of the timeout leaf (CSV + BIP340 sig).
    // The signature commits to the output (Default sighash), so set dest first.
    // Signed with the local schnorr crate: same secret bytes as the fixture's
    // key(2), read big-endian so the scalar matches the leaf's pk_op.
    let x_op = ark_secp256k1::Fr::from_be_bytes_mod_order(&[2u8; 32]);
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(7);
    let mut timeout = timeout_tx(spent, value, f.t, dest);
    let sig = sign_timeout(&timeout, 0, &prevout, &f.taptree.timeout, &x_op, &mut rng);
    attach_timeout_sig(&mut timeout, &f.taptree, &sig);

    println!("\n# spending the funded Assert-output UTXO: {spent}");
    println!("# challenge preimage (Disprove witness item 0): {}", hex(&f.pre_image));
    println!("# timeout relative locktime: {} blocks (needs that many confs on the UTXO)\n", f.t);
    println!("DISPROVE_HEX={}", serialize_hex(&disprove));
    println!("TIMEOUT_HEX={}", serialize_hex(&timeout));
    println!("\n# Disprove is spendable now; Timeout only after {} confirmations.", f.t);
}

#[test]
#[ignore = "regtest: prints Assert hex spending the bond via CheckGS"]
fn print_assert_hex() {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    let txid: Txid = std::env::var("BOND_TXID").expect("set BOND_TXID").parse().unwrap();
    let vout: u32 = std::env::var("BOND_VOUT").expect("set BOND_VOUT").parse().unwrap();
    let bf = bond_fixture();
    let af = assert_fixture();

    // Assert spends the bond outpoint, creates the challenge/timeout tree.
    let assert = assert_tx(OutPoint::new(txid, vout), FUND - FEE, &af.taptree);
    // What the bond UTXO looks like on-chain (sighash commits to it).
    let prevout = TxOut { value: FUND, script_pubkey: bf.taptree.output.clone() };

    let sighashes = slot_sighashes(&assert, 0, &prevout, &bf.taptree.gs, 2);

    // pi = the claimed input bits; completions release exactly those labels.
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let (_pk, _pre, claim, _labels) =
        claim_and_extract_labels(&bf.e, &bf.op_sk, &[true, false], &sighashes, &mut rng);

    let mut assert = assert;
    attach_assert_witness(&mut assert, &bf.taptree, &claim.sigs);
    println!("ASSERT_HEX={}", serialize_hex(&assert));
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

