# garbled-bitvm

A research implementation of the cryptographic primitives behind BitVM3:
garbled circuits, extractable and adaptor signatures, and the Bitcoin
transaction graph that carries the Assert/Disprove dispute. Work in progress;
not audited and not for production use.

Accompanying theory notes: [`theory/theory.pdf`](theory/theory.pdf) (draft).

## Crates

- `circuit` — Boolean circuits over {AND, XOR, NOT} and their evaluation.
- `garble-yao` — Yao's garbling scheme: garble, encode, evaluate, decode.
- `lamport-sig` — Lamport one-time signatures.
- `schnorr` — Schnorr signatures over secp256k1 (arkworks).
- `adaptor-sig` — Schnorr adaptor signatures: pre-sign, adapt, extract.
- `ges` — garbled-encoding extractable signature (Lamport instantiation).
- `ges-via-adaptor` — the GES realised with adaptor signatures, where each
  garbled input label is the adaptor witness.
- `bitcoin-tx` — the Assert/Disprove/Timeout Taproot transaction graph, built on
  `rust-bitcoin`.

## Build

```
cargo test --workspace
```
