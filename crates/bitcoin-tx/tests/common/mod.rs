// allow(dead_code): each test binary compiles this module separately, and not
// every binary uses every fixture item.
#![allow(dead_code)]

use bitcoin::{
    hashes::{sha256, Hash},
    secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey},
    Amount,
};
use bitcoin_tx::*;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use ark_std::UniformRand;
use ark_ec::Group;
use ark_ff::{BigInteger, PrimeField};
use ark_secp256k1::{Fr, Projective};
use garble_yao::{LabelPair, EncodingInfo};

pub struct AssertFixture {
    pub taptree: AssertTaptree,
    pub pre_image: [u8; 32],
    pub h: sha256::Hash,
    pub t: u16,
}

pub struct BondFixture {
    pub taptree: BondTaptree,
    pub e: EncodingInfo,
    // In deployment the slot keys is an m-of-m key built from shares. One honest
    // member from signing committee destroying shares is sufficient to prevent
    // garble/operator creating new spend. In test key is Fr::rand, no shares or
    // deletion (rmk:slot-key-gap).
    pub op_sk: Fr,
}

pub const FUND: Amount = Amount::from_sat(100_000);

// Slot width: 1 = per-wire shape (half-adder, 2 slots x 2 candidates).
// Single source of truth for fixtures, state file, and printers.
pub const W: usize = 1;

pub fn assert_fixture() -> AssertFixture {
    let secp = Secp256k1::new();
    let key = |b: u8| {
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[b; 32]).unwrap());
        XOnlyPublicKey::from_keypair(&kp).0
    };
    let pre_image = *b"FALSE_LABEL_L* thiry-two bytes!!";
    let h = sha256::Hash::hash(&pre_image);
    let t: u16 = 10;
    let taptree = build_assert_taptree(&secp, nums_internal_key(), h.to_byte_array(), t, key(2));
    AssertFixture {
        taptree,
        pre_image,
        h,
        t,
    }
}

pub fn bond_fixture(w: usize) -> BondFixture {
    let secp = Secp256k1::new();
    let mut rng = ChaCha20Rng::from_entropy();
    let (_gc, e, _d) = garble_yao::gb(&circuit::fixtures::half_adder(), &mut rng);
    let op_sk = Fr::rand(&mut rng);
    let pk_slot = XOnlyPublicKey::from_slice(&schnorr::x_only_bytes(&(Projective::generator() * op_sk))).unwrap();
    let n = e.input_pairs.len() / w;
    let taptree = build_bond_taptree(&secp, nums_internal_key(), pk_slot, n);
    BondFixture { taptree, e, op_sk }
}

pub fn save_bond_state(path: &str, bf: &BondFixture, w: usize) {
    let mut bytes = vec![w as u8];
    bytes.extend_from_slice(&bf.op_sk.into_bigint().to_bytes_le());
    for pair in &bf.e.input_pairs {
        bytes.extend_from_slice(&pair.zero);
        bytes.extend_from_slice(&pair.one);
    }
    std::fs::write(path, bytes).unwrap();
}

pub fn load_bond_state(path: &str) -> BondFixture {
    let bytes = std::fs::read(path).unwrap();
    // 33 = 32 +1: w is serialized into bytes
    assert_eq!((bytes.len() - 33) % 64, 0);
    let op_sk = Fr::from_le_bytes_mod_order(&bytes[1..33]);
    let input_pairs = bytes[33..].chunks(64).map(|c| LabelPair {
        zero: c[..32].try_into().unwrap(),
        one: c[32..].try_into().unwrap(),
    }).collect();
    let e = EncodingInfo { input_pairs };
    let secp = Secp256k1::new();
    let pk_slot = XOnlyPublicKey::from_slice(&schnorr::x_only_bytes(&(Projective::generator() * op_sk))).unwrap();
    let n = e.input_pairs.len() / (bytes[0] as usize);
    let taptree = build_bond_taptree(&secp, nums_internal_key(), pk_slot, n);
    BondFixture { taptree, e, op_sk }
}