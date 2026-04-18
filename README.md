# crypto-lab-mpcith-sign

## What It Is

Browser-based demo of MPC-in-the-Head (MPCitH) signatures - the post-quantum
signature paradigm where security rests only on hash functions. The prover
simulates a multi-party computation internally, commits to each party's view,
then uses Fiat-Shamir to turn the interactive zero-knowledge proof into a
non-interactive signature.

This project implements a full toy MPCitH protocol for proving knowledge of
x such that A*x = b (mod q), with SHA-256 challenge derivation and real
secret sharing, commitments, challenge-response, and verification checks.
It also includes a toy PERK-style instantiation based on the Permuted Kernel
Problem and explains NIST's Round 2 additional MPCitH candidates: Mirath,
PERK, RYDE, SDitH, MQOM, and FAEST.

None of these Round 2 additional candidates are standardized as of 2026.

## When to Use It

- Understanding why NIST sought non-lattice signature alternatives
- Learning how Fiat-Shamir turns interaction into signatures
- Comparing MPCitH tradeoffs with ML-DSA and SLH-DSA
- Teaching the MPC simulation paradigm (IKOS 2007)

## Live Demo

https://systemslibrarian.github.io/crypto-lab-mpcith-sign/

## What Can Go Wrong

- MPCitH signatures are larger than ML-DSA (thousands of bytes vs hundreds).
  This is a core tradeoff, not just an implementation detail.
- Demo parameters (N=8, tau=4, small vectors and fields) are toy security only.
- Round 2 additional candidates are under active cryptanalysis and may or may
  not survive to standardization.
- This toy PERK exhibit is educational and intentionally small.

## Real-World Usage

MPCitH was introduced by Ishai, Kushilevitz, Ostrovsky, and Sahai (2007).
The Picnic signature scheme demonstrated practical MPCitH signing in the NIST
PQC process.

NIST's additional signature process includes non-lattice options to increase
assumption diversity. MPCitH candidates are attractive because they avoid
lattice structure while still yielding practical signatures, at larger sizes.
