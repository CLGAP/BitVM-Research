use circuit::{Circuit, Gate};
use rand::{Rng, seq::SliceRandom};
use sha2::{Digest, Sha384};

// Label: 32 bytes (k = 256; rejection-sampled below the secp256k1 group order,
// so every label is its own scalar and the label-to-scalar map of the adaptor
// bridge is injective and invertible). Pad t = 128 bits.
// Ciphertext row = label || 0^16 = 48 bytes. SHA-384 outputs exactly 48 bytes, so its whole
// output is the keystream (k + t = 256 + 128); no bytes discarded.
pub type Label = [u8; 32];
pub type Ciphertext = [u8; 48];

// secp256k1 group order n, stored least-significant byte first (labels are read
// little-endian by the adaptor bridge). Big-endian value:
//   n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
//     = 115792089237316195423570985008687907852837564279074904382605163141518161494337
// (slightly below 2^256; n has no compact power form -- that belongs to the
// base-field prime p = 2^256 - 2^32 - 977)
// Source: SEC 2 v2.0, §2.4.1, https://www.secg.org/sec2-v2.pdf (also BIP340).
pub const N_LE: [u8; 32] = [
    0x41, 0x41, 0x36, 0xD0, 0x8C, 0x5E, 0xD2, 0xBF,
    0x3B, 0xA0, 0x48, 0xAF, 0xE6, 0xDC, 0xAE, 0xBA,
    0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];
#[derive(Clone)]
pub struct LabelPair {
    pub zero: Label, // L^0
    pub one: Label, // L^1
}

pub struct EncodingInfo {
    pub input_pairs: Vec<LabelPair>,
}

pub struct DecodingInfo {
    pub output_maps: Vec<LabelPair>,
}

pub struct GarbledGate {
    pub ciphertexts: Vec<Ciphertext>, // 4 for fan-in-2, 2 for NOT
}

pub struct GarbledCircuit {
    pub gates: Vec<GarbledGate>,
}

pub fn gb<R: Rng>(circuit: &Circuit, rng: &mut R) -> (GarbledCircuit, EncodingInfo, DecodingInfo) {
    let mut wire_pairs: Vec<LabelPair> = Vec::with_capacity(circuit.num_wires);
    for _ in 0..circuit.num_wires {
       let zero = sample_label(rng);
       let one = sample_label(rng);
       wire_pairs.push(LabelPair { zero, one } );
    }

    let input_pairs: Vec<LabelPair> = circuit.input_wires.iter().map(|&w| wire_pairs[w].clone()).collect();
    let e = EncodingInfo { input_pairs };

    let output_maps: Vec<LabelPair> = circuit.output_wires.iter().map(|&w| wire_pairs[w].clone()).collect();
    let d = DecodingInfo { output_maps };

    let mut garbled_circuit: Vec<GarbledGate> = Vec::with_capacity(circuit.gates.len());
    for (gate_idx, gate) in circuit.gates.iter().enumerate() {
        let nu = (i32::try_from(gate_idx).unwrap()).to_le_bytes(); //nonce
        let mut ciphertext: Vec<Ciphertext> = Vec::new();

        match gate {
            Gate::And { a, b, out } => {
                for i in [false, true] {
                    for j in [false, true] {
                        let k_1 = if i { wire_pairs[*a].one } else { wire_pairs[*a].zero };
                        let k_2 = if j { wire_pairs[*b].one } else { wire_pairs[*b].zero };
                        let m_label = if i && j { wire_pairs[*out].one } else { wire_pairs[*out].zero }; 

                        let hash: [u8; 48] = Sha384::new().chain_update(k_1).chain_update(k_2).chain_update(nu).finalize().into();
                        let mut plaintext = [0u8;48];
                        plaintext[..32].copy_from_slice(&m_label); 
                        let mut row = [0u8; 48];
                        for k in 0..48 { row[k] = hash[k] ^ plaintext[k]; }
                        ciphertext.push(row);
                    }
                }
            }
            Gate::Xor { a, b, out } => {
                for i in [false, true] {
                    for j in [false, true] {
                        let k_1 = if i { wire_pairs[*a].one } else { wire_pairs[*a].zero };
                        let k_2 = if j { wire_pairs[*b].one } else { wire_pairs[*b].zero };
                        let m_label = if i ^ j { wire_pairs[*out].one } else { wire_pairs[*out].zero };

                        let hash: [u8; 48]= Sha384::new().chain_update(k_1).chain_update(k_2).chain_update(nu).finalize().into();
                        let mut plaintext= [0u8; 48];
                        plaintext[..32].copy_from_slice(&m_label);
                        let mut row = [0u8; 48];
                        for k in 0..48 { row[k]= hash[k] ^ plaintext[k] };
                        ciphertext.push(row);
                    }
                }
            }
            Gate::Not { input, output } => {
                for i in [false, true] {
                    let k_1 = if i { wire_pairs[*input].one } else { wire_pairs[*input].zero };
                    let m_label = if i { wire_pairs[*output].zero } else { wire_pairs[*output].one };

                    let hash: [u8; 48] = Sha384::new().chain_update(k_1).chain_update(nu).finalize().into();
                    let mut plaintext = [0u8; 48];
                    plaintext[..32].copy_from_slice(&m_label);
                    let mut row = [0u8; 48];
                    for j in 0..48 { row[j] = hash[j] ^ plaintext[j] }
                    ciphertext.push(row);
                }
            } 
        }
        ciphertext.shuffle(rng);
        garbled_circuit.push(GarbledGate { ciphertexts: ciphertext });
    }
    let gc = GarbledCircuit { gates: garbled_circuit };
    (gc, e, d)    
}

// Rejection sampling: draw 32 uniform bytes, keep only values below the group
// order n (draws >= n are discarded, a ~2^-127 sliver). Labels then span
// essentially all of Z_n, so the witness interval is full width (~2^128
// kangaroo cost) and reading a label as a scalar never reduces mod n.
fn sample_label<R: Rng>(rng: &mut R) -> Label {
   loop {
        let mut label = [0u8; 32];
        rng.fill_bytes(&mut label);
        if below_order(&label) { break label ; }
    }
}

// Lexicographic compare against N_LE from the most significant byte (index 31,
fn below_order(l: &Label) -> bool {
    l.iter().rev().lt(N_LE.iter().rev())
}

pub fn en(e: &EncodingInfo, x: &[bool]) -> Vec<Label> {
    e.input_pairs.iter().zip(x).map(|(pair, &bit)| if bit { pair.one } else { pair.zero }).collect()
}                                            

pub fn ev(circuit: &Circuit, gc: &GarbledCircuit, l_x: &[Label]) -> Vec<Label> {
    assert_eq!(circuit.gates.len(), gc.gates.len(), "Garbled circuit and original circuit must have same number of gates");
    assert_eq!(circuit.input_wires.len(), l_x.len(), "There must be an encoded wire for every input wire");
    let mut buf: Vec<Option<Label>> = vec![None; circuit.num_wires];

    for (i, &wire_id) in circuit.input_wires.iter().enumerate() {
        buf[wire_id] = Some(l_x[i]);
    }

    for (gate_idx, gate) in circuit.gates.iter().enumerate() {
        let nu = (i32::try_from(gate_idx).unwrap()).to_le_bytes();
        let garbled = &gc.gates[gate_idx];

        match gate {
            Gate::And { a, b, out} | Gate::Xor { a, b, out } => {
                let k_1 = buf[*a].expect("wire not set");
                let k_2 = buf[*b].expect("wire not set");
                let hash: [u8; 48] = Sha384::new().chain_update(k_1).chain_update(k_2).chain_update( nu).finalize().into();
                let label = trial_decrypt(&garbled.ciphertexts, &hash);
                buf[*out] = Some(label)
            }
            Gate::Not { input, output} => {
                let k = buf[*input].expect("wire not set");
                let hash: [u8; 48] = Sha384::new().chain_update(k).chain_update(nu).finalize().into();
                let label = trial_decrypt(&garbled.ciphertexts, &hash);
                buf[*output] = Some(label);
            }
        }
    }
    circuit.output_wires.iter().map(|&w| buf[w].expect("output wire not set")).collect()
}

fn trial_decrypt(ciphertexts: &[Ciphertext], hash: &[u8;48]) -> Label {
    for c in ciphertexts {
        let mut pt = [0u8; 48];
        for k in 0..48 { pt[k] = hash[k] ^ c[k]; }  // (B Xor A) Xor A = B
        if pt[32..] == [0u8; 16] {
            let mut label = [0u8; 32];
            label.copy_from_slice(&pt[..32]);
            return label;
        }
    }
    panic!("No valid decryption, authentication issue/bug");
}

pub fn de(d: &DecodingInfo, l_y: &[Label]) -> Option<Vec<bool>> {
    d.output_maps.iter().zip(l_y).map(|(pair, label)| {
        if pair.zero == *label { Some(false) }
        else if pair.one == *label { Some(true) }
        else { None }
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use circuit::fixtures::{half_adder, and_gate, xor_and_not};
    use rand_chacha::ChaCha20Rng;
    use rand::SeedableRng;

    #[test]
    fn and_round_trip_truth_table() {
        let circuit = and_gate();
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (gc, e, d) = gb(&circuit, &mut rng);

        for [a, b] in [[false, false], [false, true], [true, false], [true, true]] {
            let l_x = en(&e, &[a, b]);
            let l_y = ev(&circuit, &gc, &l_x);
            let y = de(&d, &l_y).expect("Correct decoding never returns None");
            assert_eq!(y, vec![a && b], "for inputs ({}, {})", a, b);
        }
    }

    #[test]
    fn half_adder_round_trip_truth_table() {
        let circuit = half_adder();
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (gc, e, d) = gb(&circuit, &mut rng);
        
        for [a, b] in [[false, false], [false, true], [true, false], [true, true]] {
            let l_x = en(&e, &[a, b]);
            let l_y = ev(&circuit, &gc, &l_x);
            let y = de(&d, &l_y).expect("Correct decoding never returns None");
            assert_eq!(y, vec![a ^ b, a && b], "for inputs ({}, {})", a, b);
        }
    }

    #[test]
    fn three_gate_round_trip_truth_table() {
        let circuit = xor_and_not();
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (gc, e, d) = gb(&circuit, &mut rng);
        
        for [a, b, c] in [
            [false, false, false], [false, false, true],
            [false, true, false],  [false, true, true],
            [true, false, false],  [true, false, true],
            [true, true, false],   [true, true, true],
            ] {
            let l_x = en(&e, &[a, b, c]);
            let l_y = ev(&circuit, &gc, &l_x);
            let y = de(&d, &l_y).expect("Correct decoding never returns None");
            assert_eq!(y, vec![(a ^ b) && !c], "for inputs ({}, {}, {})", a, b, c);
        }                
    }

    #[test]
    fn de_returns_none_on_invalid_label() {
        let circuit = xor_and_not();
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (gc, e, d) = gb(&circuit, &mut rng);
        
        for x in [
            [false, false, false], [false, false, true],
            [false, true, false],  [false, true, true],
            [true, false, false],  [true, false, true],
            [true, true, false],   [true, true, true],
            ] {
            let l_x = en(&e, &x);
            let mut l_y = ev(&circuit, &gc, &l_x);
            l_y[0] = [0; 32];
            assert_eq!(de(&d, &l_y), None);
        }

    }

    #[test]
    fn de_returns_none_on_partial_invalid_label() {
        let circuit = half_adder();
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (gc, e, d) = gb(&circuit, &mut rng);
        
        for [a, b] in [[false, false], [false, true], [true, false], [true, true]] {
            let l_x = en(&e, &[a, b]);
            let mut l_y = ev(&circuit, &gc, &l_x);
            l_y[0] = [0; 32];
            assert!(de(&d, &l_y).is_none(), "for inputs ({}, {})", a, b);
        }
    }

    #[test]
    fn below_order_boundary() {
        assert!(!below_order(&[0xFF; 32]));
        assert!(!below_order(&N_LE));
        let mut n_le_min_1 = N_LE;
        n_le_min_1[0] = 0x40;
        assert!(below_order(&n_le_min_1));
    }
}
