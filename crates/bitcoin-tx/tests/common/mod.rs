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
use ark_secp256k1::{Fr, Projective};
use garble_yao::EncodingInfo;

#[allow(dead_code)]
pub struct AssertFixture {
    pub taptree: AssertTaptree,
    pub pre_image: [u8; 32],
    pub h: sha256::Hash,
    pub t: u16,
}

// allow(dead_code): each test binary compiles this module separately, and not
// every binary uses every fixture item.
#[allow(dead_code)]
pub struct BondFixture {
    pub taptree: BondTaptree,
    pub e: EncodingInfo,
    pub op_sk: Fr,
}

#[allow(dead_code)]
pub const FUND: Amount = Amount::from_sat(100_000);

pub fn assert_fixture() -> AssertFixture {
    let secp = Secp256k1::new();
    let key = |b: u8| {
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[b; 32]).unwrap());
        XOnlyPublicKey::from_keypair(&kp).0
    };
    let pre_image = *b"FALSE_LABEL_L* thiry-two bytes!!";
    let h = sha256::Hash::hash(&pre_image);
    let t: u16 = 10;
    let taptree = build_assert_taptree(&secp, key(1), h.to_byte_array(), t, key(2));
    AssertFixture {
        taptree,
        pre_image,
        h,
        t,
    }
}

#[allow(dead_code)]
pub fn bond_fixture() -> BondFixture {
    let secp = Secp256k1::new();
    let key = |b: u8| {
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[b; 32]).unwrap());
        XOnlyPublicKey::from_keypair(&kp).0
    };
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (_gc, e, _d) = garble_yao::gb(&circuit::fixtures::half_adder(), &mut rng);
    let op_sk = Fr::rand(&mut rng);
    let pk_slot = XOnlyPublicKey::from_slice(&schnorr::x_only_bytes(&(Projective::generator() * op_sk))).unwrap();
    let taptree = build_bond_taptree(&secp, key(2), pk_slot, 2);
    BondFixture { taptree, e, op_sk }
}