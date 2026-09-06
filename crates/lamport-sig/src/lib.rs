use rand::Rng;
use sha2::{Sha256, Digest};

pub type Secret = [u8; 16];
pub type Hash = [u8; 32];

pub struct Pair<T> { pub zero: T, pub one: T }

pub struct SecretKey { pub pairs: Vec<Pair<Secret>> }
pub struct PublicKey { pub pairs: Vec<Pair<Hash>> }
pub struct Signature { pub secrets: Vec<Secret> }

pub fn keygen<R: Rng>(n: usize, rng: &mut R) -> (SecretKey, PublicKey) {
    let mut sk = Vec::with_capacity(n);
    let mut pk = Vec::with_capacity(n);
    for _ in 0..n {
        let mut zero = [0u8; 16];
        let mut one = [0u8; 16];
        rng.fill_bytes(&mut zero);
        rng.fill_bytes(&mut one);
        sk.push(Pair { zero, one });
        let h_zero: Hash = Sha256::digest(zero).into();
        let h_one: Hash = Sha256::digest(one).into();
        pk.push(Pair { zero: h_zero, one: h_one });
    }
    (SecretKey { pairs: sk }, PublicKey {pairs: pk })
}

pub fn sign(sk: SecretKey, m: &[bool]) -> Signature {
    //Check critical: observe that `.zip()` truncates to shorter side
    assert_eq!(m.len(), sk.pairs.len()); 

    Signature { secrets: sk.pairs.iter().zip(m).map(|(pair, &bit)| if bit { pair.one } else { pair.zero }).collect() }
}

pub fn vrfy(pk: &PublicKey, m: &[bool], sig: &Signature) -> bool {
    // see line 30, and note == transitive
    assert!(pk.pairs.len() == m.len() && m.len() == sig.secrets.len() );

    pk.pairs.iter().zip(m).zip(&sig.secrets).all(|((pairs, &bit), sig)| {
        <Hash>::from(Sha256::digest(sig)) ==  if bit {pairs.one} else { pairs.zero}
    })
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;
    
    #[test]
    fn correctness_roundtrip() {
        let n = 4;
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (sk, pk) = keygen(n, &mut rng);
        let message: Vec<bool> = (0..n).map(|_| rng.r#gen()).collect();
        let sig = sign(sk, &message);
        assert!(vrfy(&pk, &message, &sig));
    }

    #[test]
    fn verify_rejects_corrupted_secret() {
        let n = 4;
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (mut sk, pk) = keygen(n, &mut rng);
        let message: Vec<bool> = (0..n).map(|_| rng.r#gen()).collect();
        sk.pairs[0].zero[0] ^= 1;
        sk.pairs[0].one[0] ^= 1;
        let sig = sign(sk, &message);
        assert!(!vrfy(&pk, &message, &sig));
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let n = 4;
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (sk, pk) = keygen(n, &mut rng);
        let mut  message: Vec<bool> = (0..n).map(|_| rng.r#gen()).collect();  
        let sig = sign(sk, &message);
        message[0] ^= true;
        assert!(!vrfy(&pk, &message, &sig));
    }    
}