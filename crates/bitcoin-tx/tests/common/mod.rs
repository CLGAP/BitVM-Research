use bitcoin::{
    hashes::{sha256, Hash},
    secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey},
    Amount,
};
use bitcoin_tx::*;
#[allow(dead_code)]
pub struct Fixture {
    pub taptree: AssertTaptree,
    pub pre_image: [u8; 32],
    pub h: sha256::Hash,
    pub t: u16,
}

pub const BOND: Amount = Amount::from_sat(100_000);

pub fn fixture() -> Fixture {
    let secp = Secp256k1::new();
    let key = |b: u8| {
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[b; 32]).unwrap());
        XOnlyPublicKey::from_keypair(&kp).0
    };
    let pre_image = *b"FALSE_LABEL_L* thiry-two bytes!!";
    let h = sha256::Hash::hash(&pre_image);
    let t: u16 = 10;
    let taptree = build_assert_taptree(&secp, key(1), h.to_byte_array(), t, key(2));
    Fixture {
        taptree,
        pre_image,
        h,
        t,
    }
}
