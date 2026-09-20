use garble_yao::{Label, EncodingInfo};
use adaptor_sig::{PreSignature};
use schnorr::{Signature};
use ark_secp256k1::{Fr, Projective};
use ark_std::{rand::Rng, UniformRand};
use ark_ec::Group;
use ark_ff::{BigInteger, PrimeField};


pub struct Pair<T> { pub zero: T, pub one: T }

pub struct PublicKey { pub pairs: Vec<Pair<Projective>> }
pub struct PreSigs { pub pairs: Vec<Pair<PreSignature>> }

pub struct Claim { pub sigs: Vec<Signature> }

// covnersion of bytes for ECP reduces sampling (security) due to method
pub fn keygen(e: &EncodingInfo) -> PublicKey {
    let g = Projective::generator();
    PublicKey { pairs: e.input_pairs.iter().map( |pair| Pair {
        zero: g * Fr::from_le_bytes_mod_order(&pair.zero),
        one: g * Fr::from_le_bytes_mod_order(&pair.one),
        }).collect(),
    }
}

pub fn pre_sign<R: Rng>(x: &Fr, ms: &[[u8; 32]], pk: &PublicKey, rng: &mut R) -> PreSigs {
    assert_eq!(pk.pairs.len(), ms.len());
    PreSigs {
        pairs: pk.pairs.iter().zip(ms).map(|(pair, m)| {
            let k = loop {
                let k = Fr::rand(rng);
                let r = Projective::generator() * k;
                if schnorr::even_y(&(r + pair.zero)) && schnorr::even_y(&(r + pair.one)) { break k; }
            };   
            Pair {
                zero: adaptor_sig::pre_sign_with_nonce(x, m, &pair.zero, &k),
                one: adaptor_sig::pre_sign_with_nonce(x, m, &pair.one, &k),
            }
        }).collect()
    }    
}


pub fn post(e: &EncodingInfo, pre: &PreSigs, x: &[bool]) -> Claim {
    Claim { sigs:  
        pre.pairs.iter().zip(e.input_pairs.iter()).zip(x).map(|((ps_pair, e_pair), b)| {
        if *b { adaptor_sig::adapt(&ps_pair.one, &Fr::from_le_bytes_mod_order(&e_pair.one)) } 
        else { adaptor_sig::adapt(&ps_pair.zero, &Fr::from_le_bytes_mod_order(&e_pair.zero)) }
    }).collect()}
}

pub fn extract_all(pk: &PublicKey, pre: &PreSigs, claim: &Claim) -> Vec<Label> {
	let g = Projective::generator();
	pre.pairs.iter().zip(claim.sigs.iter()).zip(pk.pairs.iter()).map(|((ps_pair, sig), pk_pair)| {
	let t0 =  adaptor_sig::extract(&ps_pair.zero, sig);
	if g * t0  == pk_pair.zero { scalar_to_label(&t0) } 
	else {  let t1 = adaptor_sig::extract(&ps_pair.one, sig);
		assert_eq!(g * t1, pk_pair.one, "extracted label matches neither statement");
		scalar_to_label(&t1)
	}}).collect()
}

pub fn pre_verify_all(p: &Projective, ms: &[[u8; 32]], pk: &PublicKey, pre: &PreSigs) -> bool {
    pk.pairs.iter().zip(pre.pairs.iter()).zip(ms).all(|((pk_pair, ps_pair), m)| {
	adaptor_sig::pre_verify(p, m, &pk_pair.zero, &ps_pair.zero) && adaptor_sig::pre_verify(p, m, &pk_pair.one, &ps_pair.one)
	})
}

fn scalar_to_label(s: &Fr) -> Label {
	let bytes = s.into_bigint().to_bytes_le();
	let mut l = [0u8; 32];
	l.copy_from_slice(&bytes[..32]);
	l
}


#[cfg(test)] 
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::{ChaCha20Rng};
    use garble_yao::{GarbledCircuit, DecodingInfo};

    fn setup(rng: &mut ChaCha20Rng) -> (circuit::Circuit, GarbledCircuit, EncodingInfo, DecodingInfo, Fr, Projective) {
        let circuit = circuit::fixtures::half_adder();
        let (gc, e, d) = garble_yao::gb(&circuit, rng);
        let x_key = Fr::rand(rng);
        let p = Projective::generator() * x_key;
        (circuit, gc, e, d, x_key, p)
    }

    #[test]
    fn pre_verify_all_accepts_honest() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (_ , _, e, _, op_sk , p) = setup(&mut rng);
        let m = b"Assert tx that is 32 bytes long.";
        let ms = [*m; 2];
        let pk = keygen(&e);
        let ps = pre_sign(&op_sk, &ms, &pk, &mut rng);
        let m_2 = b"Other assert tx that is 32 long.";
        let ms_2 = [*m_2; 2];
        assert!(pre_verify_all(&p, &ms, &pk, &ps));
        assert!(!pre_verify_all(&p, &ms_2, &pk, &ps));
        assert!(!pre_verify_all(&(p + Projective::generator()), &ms, &pk, &ps));
    }

    #[test]
    fn extractability_extract_equals_en() { 
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (_ , _, e, _, op_sk , _) = setup(&mut rng);
        let m = b"Assert tx that is 32 bytes long.";
        let ms = [*m; 2];
        let pk = keygen(&e);
        let pre= pre_sign(&op_sk, &ms, &pk, &mut rng);
        let x = [true, false];
        let claim = post(&e, &pre, &x);
        let l_x = extract_all(&pk, &pre, &claim);
        assert_eq!(garble_yao::en(&e, &x), l_x);
    }

    #[test]
    fn end_to_end_eval_and_decode() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (circuit, gc, e, d,  op_sk, _) = setup(&mut rng);
        let m = b"Assert tx that is 32 bytes long.";
        let ms = [*m; 2];
        let pk = keygen(&e);
        let pre= pre_sign(&op_sk, &ms, &pk, &mut rng);
        let x = [true, false];
        let claim = post(&e, &pre, &x);
        let l_x = extract_all(&pk, &pre, &claim);
        let l_y = garble_yao::ev(&circuit, &gc, &l_x);
        assert_eq!(garble_yao::de(&d, &l_y), Some(circuit.evaluate(&x)));
    }

    #[test]
    fn equivocation_leaks_operator_secret_key() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (_, _, e, _,  op_sk, p) = setup(&mut rng);
        let m = b"Assert tx that is 32 bytes long.";
        let ms = [*m; 2];
        let pk = keygen(&e);
        let pre= pre_sign(&op_sk, &ms, &pk, &mut rng);
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
        use secp256k1::{Secp256k1, XOnlyPublicKey, Message, schnorr::Signature as SecpSig};

        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let circuit = circuit::fixtures::xor_and_not();
        let (_, e, _) = garble_yao::gb(&circuit, &mut rng);
        let op_sk = Fr::rand(&mut rng);
        let op_pk = XOnlyPublicKey::from_slice(&schnorr::x_only_bytes(&(Projective::generator() * op_sk))).unwrap();
        let m = b"Assert tx that is 32 bytes long.";
        let ms = [*m; 3];
        let pk = keygen(&e);
        let pre = pre_sign(&op_sk, &ms, &pk, &mut rng);
        let x = [true, false, true];
        let claim = post(&e, &pre, &x);
        for sig in claim.sigs {
            let ssig = SecpSig::from_slice(&schnorr::to_bytes(&sig)).unwrap();
            assert!(Secp256k1::verification_only().verify_schnorr(
                &ssig,
                &Message::from_digest(*m),
                &op_pk).is_ok());
        }
    }
}
