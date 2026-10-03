use adaptor_sig::PreSignature;
use ark_ec::Group;
use ark_ff::{BigInteger, PrimeField};
use ark_secp256k1::{Fr, Projective};
use ark_std::{UniformRand, rand::Rng};
use garble_yao::{EncodingInfo, Label};
use sha2::{Digest, Sha256};

// held privately by the Operator(Garbler)
pub struct WideSecrets {
    pub keys: Vec<Vec<Fr>>,
}

//object made public
#[derive(Clone)]
pub struct WideSetup {
   pub candidates: Vec<Vec<Candidate>>,
}

// object made public
#[derive(Clone)]
pub struct Candidate {
    pub statement: Projective,
    pub pre_sig: PreSignature,
    pub row: Vec<u8>,
}

pub fn wide_setup<R: Rng>(e: &EncodingInfo, rng: &mut R, w: usize, ms: &[[u8; 32]], x: &Fr) -> (WideSetup, WideSecrets) {
    assert_eq!(e.input_pairs.len() % w, 0);
    let slots = e.input_pairs.len() / w;
    assert_eq!(ms.len(), slots);
    let candidates_options = 2usize.pow(w as u32);
    let mut keys: Vec<Vec<Fr>> = Vec::new();
    let mut candidates: Vec<Vec<Candidate>> = Vec::new();

    for slot in 0..slots {
        let mut slot_keys = Vec::new();
        let mut slot_candidates = Vec::new();

        for row in 0..candidates_options {
            let key = Fr::rand(rng);
            let t = Projective::generator() * key;
            let ps = adaptor_sig::pre_sign(x, &ms[slot], &t, rng);

            // MSB: bit (w-1-j) of row selects the label of the slot's j-th
            // wire, so a w-bit chunk of pi read left to right is row
            let plaintext: Vec<u8> = (0..w)
                .flat_map(|j| {
                    let pair = &e.input_pairs[ slot * w + j];
                    if row >> (w - j - 1) & 1 == 1 { pair.one } else { pair.zero }
                }).collect();
            assert_eq!(plaintext.len(), 32 * w);
            slot_keys.push(key);
            slot_candidates.push(Candidate { statement: t, pre_sig: ps, row: xor_keystream(&key, &plaintext, w) });

        }
        keys.push(slot_keys);
        candidates.push(slot_candidates);
    }
    
    ( WideSetup { candidates }, WideSecrets { keys } )
}

pub fn wide_pre_verify(setup: &WideSetup, ms: &[[u8; 32]], p: &Projective) -> bool {
    assert_eq!(setup.candidates.len(), ms.len());
    setup.candidates.iter().zip(ms).all(|(cs, m)| {
        cs.iter().all(|c| {
            adaptor_sig::pre_verify( p ,m,&c.statement, &c.pre_sig)

        })
    })
}

pub fn wide_post(secrets: &WideSecrets, x: &[bool], setup: &WideSetup) -> Vec<schnorr::Signature> {
   let w = setup.candidates[0].len().ilog2() as usize;
   x.chunks(w).enumerate().map(|(slot, chunk)| {
        let mut v: usize = 0;
        for &bit in chunk {
           v = v * 2 + bit as usize;
        }
        adaptor_sig::adapt(&setup.candidates[slot][v].pre_sig, &secrets.keys[slot][v])
   }).collect()
}

pub fn wide_extract(setup: &WideSetup, sigs: &[schnorr::Signature]) -> Vec<Label> {
    let w = setup.candidates[0].len().ilog2() as usize;
    let mut labels: Vec<Label> = Vec::new();
    for (cs, s) in setup.candidates.iter().zip(sigs) {
        let v = cs.iter().position(|c| {
            s.r - c.pre_sig.r == c.statement
        }).unwrap();
        let plaintext = xor_keystream(&(s.s - cs[v].pre_sig.s_t), &cs[v].row, w);
        assert_eq!(plaintext.len(), w * 32);
        for chunk in plaintext.chunks(32) {
            labels.push(chunk.try_into().unwrap());
        }
    }
    labels
}

// take witness W (Fr) as little-endian bytes
fn xor_keystream(key: &Fr, data: &[u8], w: usize) -> Vec<u8> {
    let mut keystream: Vec<u8> = Vec::new();
    let key_bytes = key.into_bigint().to_bytes_le();
    for i in 0..w {
        let mut h = Sha256::new();
        h.update(&key_bytes);
        h.update([i as u8]);
        keystream.extend(h.finalize());
    }
    
    let mut buf: Vec<u8> = Vec::new();
    for k in 0..data.len() {
        buf.push(data[k] ^ keystream[k])
    }
    buf
}
