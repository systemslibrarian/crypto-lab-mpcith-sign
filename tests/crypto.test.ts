import { describe, expect, it } from 'vitest';
import {
  bytesToHex,
  commit,
  hexToBytes,
  merkleProof,
  partialReconstruct,
  reconstructSecret,
  shareSecret,
  verifyCommit,
  verifyMerkleProof,
} from '../src/sharing';
import { generateStatement, sign, verify, type MPCParams } from '../src/mpcith';
import {
  estimateSignatureSize,
  perkEquationHolds,
  perkKeyGen,
  perkSign,
  perkVerify,
  type PERKParams,
} from '../src/perk';

const enc = new TextEncoder();

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const copy = new Uint8Array(data);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', copy.buffer));
}

describe('additive secret sharing (GF(2^8))', () => {
  it('reconstructs the original secret from all shares', async () => {
    const secret = hexToBytes('2a7fbe01');
    const shares = await shareSecret(secret, 5);
    expect(shares).toHaveLength(5);
    expect(bytesToHex(reconstructSecret(shares))).toBe(bytesToHex(secret));
  });

  it('leaks nothing from a partial reconstruction (all-but-one)', async () => {
    const secret = hexToBytes('2a');
    const shares = await shareSecret(secret, 4);
    const partial = partialReconstruct(shares, 1);
    // XORing the missing share back in must recover the secret exactly.
    const recovered = partial[0] ^ shares[1][0];
    expect(recovered).toBe(secret[0]);
  });

  it('rejects N < 2', async () => {
    await expect(shareSecret(hexToBytes('2a'), 1)).rejects.toThrow();
  });
});

describe('SHA-256 commitments', () => {
  it('verifies a commitment under its salt', async () => {
    const value = enc.encode('view bytes');
    const { commitment, salt } = await commit(value);
    expect(await verifyCommit(value, salt, commitment)).toBe(true);
  });

  it('rejects a tampered value or wrong salt', async () => {
    const value = enc.encode('view bytes');
    const { commitment, salt } = await commit(value);
    expect(await verifyCommit(enc.encode('other'), salt, commitment)).toBe(false);
    const wrongSalt = new Uint8Array(salt);
    wrongSalt[0] ^= 0xff;
    expect(await verifyCommit(value, wrongSalt, commitment)).toBe(false);
  });
});

describe('Merkle proofs', () => {
  it('verifies an inclusion proof and rejects a tampered leaf', async () => {
    const leaves = await Promise.all(
      Array.from({ length: 6 }, (_v, i) => sha256(enc.encode(`leaf-${i}`))),
    );
    const { root, proof } = await merkleProof(leaves, 3);
    expect(await verifyMerkleProof(leaves[3], 3, proof, root)).toBe(true);

    const tampered = new Uint8Array(leaves[3]);
    tampered[0] ^= 0x01;
    expect(await verifyMerkleProof(tampered, 3, proof, root)).toBe(false);
  });
});

describe('MPC-in-the-Head signatures (Fiat-Shamir)', () => {
  const params: MPCParams = { N: 4, tau: 3, q: 251 };

  it('produces a signature that verifies', async () => {
    const { statement, witness } = await generateStatement(4, 3, params.q);
    const msg = enc.encode('Authenticated by Paul Clark, LCPL');
    const { signature } = await sign(msg, statement, witness, params);
    expect((await verify(msg, statement, signature, params)).valid).toBe(true);
  });

  it('rejects a signature checked against a different message', async () => {
    const { statement, witness } = await generateStatement(4, 3, params.q);
    const { signature } = await sign(enc.encode('hello'), statement, witness, params);
    const result = await verify(enc.encode('hello!'), statement, signature, params);
    expect(result.valid).toBe(false);
    expect(result.failureReason).toMatch(/challenge/i);
  });

  it('rejects a tampered revealed view', async () => {
    const { statement, witness } = await generateStatement(4, 3, params.q);
    const msg = enc.encode('tamper test');
    const { signature } = await sign(msg, statement, witness, params);
    const round = signature.revealedViews[0];
    const view = round.find((v) => v !== null);
    expect(view).toBeTruthy();
    view!.output[0] = (view!.output[0] + 1) % params.q;
    expect((await verify(msg, statement, signature, params)).valid).toBe(false);
  });

  it('derives the challenge as SHA-256(message || roots)', async () => {
    const { statement, witness } = await generateStatement(4, 3, params.q);
    const msg = enc.encode('fiat-shamir');
    const { signature } = await sign(msg, statement, witness, params);

    let input = new Uint8Array(msg);
    for (const root of signature.merkleRoots) {
      const next = new Uint8Array(input.length + root.length);
      next.set(input);
      next.set(root, input.length);
      input = next;
    }
    expect(bytesToHex(await sha256(input))).toBe(bytesToHex(signature.challenge));
  });
});

describe('toy PERK', () => {
  const params: PERKParams = { n: 8, m: 4, q: 251, N: 8, tau: 4 };

  it('generates a keypair satisfying H·π(y) = b', async () => {
    const kp = await perkKeyGen(params);
    expect(perkEquationHolds(kp.publicKey, kp.privateKey.pi, params.q)).toBe(true);
  });

  it('signs and verifies, and rejects a different message', async () => {
    const kp = await perkKeyGen(params);
    const sig = await perkSign(enc.encode('toy PERK'), kp, params);
    expect(await perkVerify(enc.encode('toy PERK'), kp.publicKey, sig, params)).toBe(true);
    expect(await perkVerify(enc.encode('toy perk'), kp.publicKey, sig, params)).toBe(false);
  });

  it('reports a signature-size breakdown that sums to the total', () => {
    const size = estimateSignatureSize(params);
    const { merkleRoots, challenge, revealedViews, merkleProofs } = size.breakdown;
    expect(merkleRoots + challenge + revealedViews + merkleProofs).toBe(size.bytes);
  });
});
