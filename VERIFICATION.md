# Verification

Every claim below is enforced by an automated test in `tests/crypto.test.ts`.
Run the suite with:

```bash
npm test
```

CI (`.github/workflows/deploy.yml`) runs `npm test` before every build, so a
broken invariant blocks deployment.

## Invariants under test

1. `shareSecret` + `reconstructSecret` round-trips the original secret.
2. An all-but-one (partial) reconstruction recovers the secret only when the
   missing share is XORed back in.
3. `shareSecret` rejects `N < 2`.
4. `commit` / `verifyCommit` accept a value under its salt.
5. A tampered value or a wrong salt is rejected by `verifyCommit`.
6. A Merkle inclusion proof verifies; a tampered leaf is rejected.
7. `sign` + `verify` returns valid for the signed message.
8. Verifying against a different message fails with a Fiat-Shamir challenge mismatch.
9. A tampered revealed view causes `verify` to fail.
10. The challenge equals `SHA-256(message || merkleRoots)` exactly.
11. A toy PERK keypair satisfies `H · π(y) = b (mod q)`.
12. Toy PERK `sign` + `verify` accepts the signed message and rejects a different one.
13. `estimateSignatureSize` breakdown sums to its reported total.

## UI regression (`tests/ui.test.ts`, jsdom)

14. All six exhibit panels render on load (five conceptual exhibits; Exhibit 2
    is split into the party simulation and the standalone cheating-prover
    soundness experiment 2b).
15. Raising the N slider after a round is committed clears the stale round and
    does not crash `renderPartyCards` / `verifyStep` (regression for an
    out-of-bounds commitment-array read).
16. A persistent screen-reader live region (`#sr-live`) and the skip-link target
    (`#main`) are present.
17. The typed secret is threaded into the witness/statement flow banner (the
    default `0x2a` surfaces as witness coordinate `42`), proving the secret is
    what gets proven rather than a discarded, freshly-randomized witness.
18. A full Split -> MPC -> Challenge -> Verify opens the zero-knowledge
    experiment listing the true hidden share plus decoys, all equally consistent.
19. The cheating-prover experiment tallies 100 attempts as caught or slipped.

## Manual / build checks

- `npm run build` compiles with zero TypeScript errors (`tsc` then `vite build`).
- `grep -r "Math.random" src/` returns zero matches — all randomness uses
  `crypto.getRandomValues`.
- No NIST Round 2 candidate is described as standardized.
