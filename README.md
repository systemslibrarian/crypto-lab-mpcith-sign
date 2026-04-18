# crypto-lab-mpcith-sign

## What It Is

This demo implements MPC-in-the-Head signatures using additive secret sharing,
SHA-256 commitments, Merkle proofs, and the Fiat-Shamir transform for
non-interactive signing. It demonstrates a toy linear relation proof for
knowledge of a witness x where A*x = b (mod q), plus a toy PERK-style
permutation witness flow. The algorithm family is post-quantum and
zero-knowledge oriented, with signature security tied to hash commitments and
the hardness of the underlying statement relation. It is an educational model,
not a production cryptographic implementation.

## When to Use It

- Teaching how interactive identification becomes signatures with Fiat-Shamir.
  This demo exposes commit, challenge, and response artifacts directly.
- Explaining additive secret sharing and all-but-one view opening in MPCitH.
  The party cards show shares, local outputs, commitments, and hidden-view flow.
- Comparing assumption diversity against lattice-based signatures.
  The exhibits contrast MPCitH tradeoffs such as larger signatures.
- Prototyping UI-level understanding of toy PERK-style permutation witnesses.
  It shows relation checks and verification outcomes in browser-only TypeScript.
- Not for production key management or compliance claims.
  Toy parameters and educational code are not suitable for deployment security.

## Live Demo

https://systemslibrarian.github.io/crypto-lab-mpcith-sign/

The live app lets you split a secret into shares, run simulated party views,
issue a challenge, and verify revealed views in an MPCitH-style round. You can
also run Fiat-Shamir signing traces and a toy PERK sign/verify flow while
adjusting controls such as party count N and field prime q.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-mpcith-sign
cd crypto-lab-mpcith-sign
npm install
npm run dev
```

No environment variables are required.

## Part of the Crypto-Lab Suite

One of 60+ live browser demos at
[systemslibrarian.github.io/crypto-lab](https://systemslibrarian.github.io/crypto-lab/)
- spanning Atbash (600 BCE) through NIST FIPS 203/204/205 (2024).

---

*"Whether you eat or drink, or whatever you do, do all to the glory of God." — 1 Corinthians 10:31*
