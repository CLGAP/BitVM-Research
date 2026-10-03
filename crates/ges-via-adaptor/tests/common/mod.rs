use ark_ec::Group;
use ark_secp256k1::{Fr, Projective};
use ark_std::UniformRand;
use garble_yao::{DecodingInfo, EncodingInfo, GarbledCircuit};
use rand_chacha::ChaCha20Rng;

// Shared fixture: garbled half-adder + operator keypair. Each test file
// builds its own messages/width on top (per-wire ms vs wide ms + w).
#[allow(dead_code)] // each tests/*.rs is its own crate; not all use it
pub fn setup(
    rng: &mut ChaCha20Rng,
) -> (
    circuit::Circuit,
    GarbledCircuit,
    EncodingInfo,
    DecodingInfo,
    Fr,
    Projective,
) {
    let circuit = circuit::fixtures::half_adder();
    let (gc, e, d) = garble_yao::gb(&circuit, rng);
    let x_key = Fr::rand(rng);
    let p = Projective::generator() * x_key;
    (circuit, gc, e, d, x_key, p)
}
