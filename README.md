# crypto-lab-mpcith-sign

## What It Is

This demo implements MPC-in-the-Head signatures using additive secret sharing,
SHA-256 commitments, Merkle proofs, and the Fiat-Shamir transform for
non-interactive signing. It demonstrates a toy linear relation proof for
knowledge of a witness x where A*x = b (mod q), plus a toy PERK-style
permutation witness flow. The secret you type is threaded through the whole
round: each byte becomes a coordinate of the witness x, a fresh public matrix A
is drawn, and b = A*x is published — so the party cards share *your* witness,
never a discarded one. The exhibit is honest about its simplification: an
expandable note names this as the **linear special case** (parties only apply
A*share and the outputs sum to b purely by linearity — no interaction, no
correlated randomness) and explains that real MPCitH earns its name on
*nonlinear* relations, where seed trees and correlated randomness enter. A
zero-knowledge experiment then shows truthfully that the sealed party's *output*
is pinned by b − Σ(revealed outputs) — only one candidate share matches it —
while the *witness coordinate* stays hidden: a slider varies the hidden share
and the revealed transcript never moves. A **Sign this round** button carries the
exact secret, N, A and b into the Fiat-Shamir exhibit, so the same committed
round you built interactively becomes a signature side by side. A cheating-prover
sandbox drives the soundness bound (1 - 1/N) and (1/N)^tau live, and PERK is
framed as the *same wrapper around a different hard problem* (permuted kernel),
shown as an actual rearrangement of y into x. The algorithm family is
post-quantum and zero-knowledge oriented, with signature security tied to hash
commitments and the hardness of the underlying statement relation. It is an
educational model, not a production cryptographic implementation.

## Exhibits

1. **The Idea** — the three-card XOR analogy (XOR = + mod 2 in GF(2)), bridged
   explicitly to the same operation over a larger group (+ mod q) in Exhibit 2.
2. **MPC Party Simulation** — split your witness across N parties, commit each
   view, challenge, and open all-but-one; with first-encounter glosses for
   *additive secret sharing*, *commitment*, *binding*, and *all-but-one opening*,
   an honest "what does MPC really mean here?" note (the linear special case),
   and a truthful zero-knowledge slider (output pinned, witness hidden).
3. **Fiat-Shamir Signature** — replace the live verifier with a hash; the
   **Sign this round** button threads Exhibit 2's exact statement here so you
   watch one round become a signature, and Modify Message shows message →
   challenge → hidden-party movement over the same statement.
4. **Toy PERK** — same MPCitH wrapper, a *different* hard statement (permuted
   kernel) inside, visualized as a permutation rearranging y into x.
5. **Security Diversity** — assumption diversity table (lattice vs hash vs
   MPCitH), reinforcing that MPCitH is a compiler, not a single scheme.

## When to Use It

- Teaching how interactive identification becomes signatures with Fiat-Shamir.
  This demo exposes commit, challenge, and response artifacts directly.
- Explaining additive secret sharing and all-but-one view opening in MPCitH.
  The party cards show shares, local outputs, commitments, and hidden-view flow.
- Comparing assumption diversity against lattice-based signatures.
  The exhibits contrast MPCitH tradeoffs such as larger signatures.
- Prototyping UI-level understanding of toy PERK-style permutation witnesses.
  It shows relation checks and verification outcomes in browser-only TypeScript.
- Do NOT use it for production key management or compliance claims.
  Toy parameters and educational code are not suitable for deployment security.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-mpcith-sign](https://systemslibrarian.github.io/crypto-lab-mpcith-sign/)**

The live app lets you split a secret into shares, run simulated party views,
issue a challenge, and verify revealed views in an MPCitH-style round — with the
typed secret threaded through as the witness. After verifying, a zero-knowledge
panel shows why the sealed share leaks nothing, and a separate cheating-prover
experiment tallies caught-vs-slipped attempts converging on (1 - 1/N) with a tau
slider that shrinks (1/N)^tau. You can also run Fiat-Shamir signing traces
(with a message -> challenge -> hidden-party diff on "Modify Message") and a toy
PERK sign/verify flow that visualizes pi as a rearrangement of y into x, all
while adjusting controls such as party count N and field prime q.

## What Can Go Wrong

- Large signatures: MPCitH signatures carry per-execution commitment and seed-tree data, so they are far larger than lattice signatures — underestimating this breaks bandwidth budgets.
- Too few repetitions: soundness depends on the number of parallel executions and the challenge space; using too few leaves a forger a non-negligible cheating probability.
- Weak Fiat-Shamir: if the challenge hash does not bind all commitments and public inputs, an attacker can grind the transcript and forge signatures — the classic weak-Fiat-Shamir failure.
- Predictable or reused seeds: the all-but-one opening relies on the unopened view's randomness staying hidden; bad RNG or seed reuse can leak the witness.
- Toy parameters and no constant-time guarantees: this educational code uses small fields and is not side-channel hardened.

## Real-World Usage

- NIST additional-signatures on-ramp: several MPC-in-the-Head submissions (including SDitH, PERK, MIRA, RYDE, MQOM, and the VOLE-in-the-Head scheme FAEST) are candidates in NIST's call for additional post-quantum signatures.
- Picnic: an earlier MPCitH/ZKBoo-based signature that reached the alternate-candidate stage of the original NIST PQC process, demonstrating signatures from symmetric primitives alone.
- Assumption diversity: MPCitH lets signatures be built from hash/block-cipher hardness, hedging against breaks in structured lattice or code assumptions.
- Cryptanalysis and research: the family is an active area for analyzing the size/soundness tradeoffs of zero-knowledge-derived signatures.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-mpcith-sign
cd crypto-lab-mpcith-sign
npm install
npm run dev
```

## Related Demos

- [crypto-lab-multivariate](https://systemslibrarian.github.io/crypto-lab-multivariate/) — UOV multivariate signatures, another non-lattice PQ family.
- [crypto-lab-sphincs-ledger](https://systemslibrarian.github.io/crypto-lab-sphincs-ledger/) — SLH-DSA hash-based signatures, also built on symmetric assumptions.
- [crypto-lab-dilithium-seal](https://systemslibrarian.github.io/crypto-lab-dilithium-seal/) — ML-DSA lattice signatures for assumption comparison.
- [crypto-lab-falcon-seal](https://systemslibrarian.github.io/crypto-lab-falcon-seal/) — Falcon/FN-DSA NTRU lattice signatures.
- [crypto-lab-zk-proof-lab](https://systemslibrarian.github.io/crypto-lab-zk-proof-lab/) — the Fiat-Shamir and commitment machinery underlying MPCitH.

## Testing

Run the cryptographic test suite (also gated in CI before every deploy):

```bash
npm test
```

See [VERIFICATION.md](VERIFICATION.md) for the invariants each test enforces.

---

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
