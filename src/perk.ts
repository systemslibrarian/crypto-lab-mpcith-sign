import { bytesToHex, hexToBytes } from './sharing';
import { sign, type MPCSignature, type MPCParams, type Statement, verify } from './mpcith';

export interface PERKParams {
  n: number;
  m: number;
  q: number;
  N: number;
  tau: number;
}

export interface PERKKeyPair {
  publicKey: {
    H: number[][];
    y: number[];
    b: number[];
  };
  privateKey: {
    pi: number[];
    x: number[];
  };
}

function randomInt(maxExclusive: number): number {
  const sample = new Uint8Array(1);
  const limit = 256 - (256 % maxExclusive);
  while (true) {
    crypto.getRandomValues(sample);
    if (sample[0] < limit) {
      return sample[0] % maxExclusive;
    }
  }
}

function mod(x: number, q: number): number {
  const r = x % q;
  return r < 0 ? r + q : r;
}

function multiplyMatrixVector(A: number[][], x: number[], q: number): number[] {
  return A.map((row) => {
    let acc = 0;
    for (let i = 0; i < row.length; i += 1) {
      acc = mod(acc + row[i] * x[i], q);
    }
    return acc;
  });
}

function randomPermutation(n: number): number[] {
  const arr = Array.from({ length: n }, (_, i) => i);
  for (let i = n - 1; i > 0; i -= 1) {
    const j = randomInt(i + 1);
    const tmp = arr[i];
    arr[i] = arr[j];
    arr[j] = tmp;
  }
  return arr;
}

function applyPermutation(v: number[], pi: number[]): number[] {
  if (v.length !== pi.length) {
    throw new Error('Permutation length mismatch');
  }
  const out = new Array<number>(v.length);
  for (let i = 0; i < pi.length; i += 1) {
    out[i] = v[pi[i]];
  }
  return out;
}

function invertPermutation(pi: number[]): number[] {
  const inv = new Array<number>(pi.length);
  for (let i = 0; i < pi.length; i += 1) {
    inv[pi[i]] = i;
  }
  return inv;
}

function toMPCParams(params: PERKParams): MPCParams {
  return {
    N: params.N,
    tau: params.tau,
    q: params.q,
  };
}

function toStatement(publicKey: PERKKeyPair['publicKey'], q: number): Statement {
  return {
    A: publicKey.H,
    b: publicKey.b,
    q,
  };
}

interface SerializedMPCSignature {
  merkleRoots: string[];
  challenge: string;
  hiddenParties: number[];
  revealedViews: Array<
    Array<{
      share: number[];
      output: number[];
      salt: string;
      merkleProof: string[];
    } | null>
  >;
}

function serializeMPCSignature(sig: MPCSignature): Uint8Array {
  const serializable: SerializedMPCSignature = {
    merkleRoots: sig.merkleRoots.map((root) => bytesToHex(root)),
    challenge: bytesToHex(sig.challenge),
    hiddenParties: sig.hiddenParties,
    revealedViews: sig.revealedViews.map((round) =>
      round.map((view) => {
        if (!view) {
          return null;
        }
        return {
          share: view.share,
          output: view.output,
          salt: bytesToHex(view.salt),
          merkleProof: view.merkleProof.map((p) => bytesToHex(p)),
        };
      }),
    ),
  };

  return new TextEncoder().encode(JSON.stringify(serializable));
}

function deserializeMPCSignature(serialized: Uint8Array): MPCSignature {
  const parsed = JSON.parse(new TextDecoder().decode(serialized)) as SerializedMPCSignature;
  return {
    merkleRoots: parsed.merkleRoots.map((root) => hexToBytes(root)),
    challenge: hexToBytes(parsed.challenge),
    hiddenParties: parsed.hiddenParties,
    revealedViews: parsed.revealedViews.map((round) =>
      round.map((view) => {
        if (!view) {
          return null;
        }
        return {
          share: view.share,
          output: view.output,
          salt: hexToBytes(view.salt),
          merkleProof: view.merkleProof.map((p) => hexToBytes(p)),
        };
      }),
    ),
  };
}

/**
 * Generate a toy PERK keypair.
 */
export async function perkKeyGen(params: PERKParams): Promise<PERKKeyPair> {
  const x = Array.from({ length: params.n }, () => randomInt(params.q));
  const pi = randomPermutation(params.n);
  const invPi = invertPermutation(pi);

  // Build y so that permute(y, pi) = x.
  const y = applyPermutation(x, invPi);

  const H = Array.from({ length: params.m }, () =>
    Array.from({ length: params.n }, () => randomInt(params.q)),
  );
  const b = multiplyMatrixVector(H, x, params.q);

  return {
    publicKey: { H, y, b },
    privateKey: { pi, x },
  };
}

/**
 * Sign with toy PERK.
 * The private permutation pi induces witness x = permute(y, pi), then MPCitH proves H·x = b.
 */
export async function perkSign(
  message: Uint8Array,
  keyPair: PERKKeyPair,
  params: PERKParams,
): Promise<Uint8Array> {
  const witness = applyPermutation(keyPair.publicKey.y, keyPair.privateKey.pi);
  const statement = toStatement(keyPair.publicKey, params.q);
  const mpcParams = toMPCParams(params);

  const { signature } = await sign(message, statement, witness, mpcParams);
  return serializeMPCSignature(signature);
}

/**
 * Verify a toy PERK signature.
 */
export async function perkVerify(
  message: Uint8Array,
  publicKey: PERKKeyPair['publicKey'],
  signature: Uint8Array,
  params: PERKParams,
): Promise<boolean> {
  const decoded = deserializeMPCSignature(signature);
  const result = await verify(message, toStatement(publicKey, params.q), decoded, toMPCParams(params));
  return result.valid;
}

/**
 * Compute signature size in bytes for given parameters.
 */
export function estimateSignatureSize(params: PERKParams): {
  bytes: number;
  breakdown: {
    merkleRoots: number;
    challenge: number;
    revealedViews: number;
    merkleProofs: number;
  };
} {
  const merkleRoots = params.tau * 32;
  const challenge = 32;

  const perViewShare = params.n;
  const perViewOutput = params.m;
  const perViewSalt = 16;
  const perViewOverhead = perViewShare + perViewOutput + perViewSalt;

  const revealedViews = params.tau * (params.N - 1) * perViewOverhead;
  const proofDepth = Math.ceil(Math.log2(params.N));
  const merkleProofs = params.tau * (params.N - 1) * proofDepth * 32;

  const bytes = merkleRoots + challenge + revealedViews + merkleProofs;
  return {
    bytes,
    breakdown: {
      merkleRoots,
      challenge,
      revealedViews,
      merkleProofs,
    },
  };
}

export function perkEquationHolds(publicKey: PERKKeyPair['publicKey'], pi: number[], q: number): boolean {
  const lhs = multiplyMatrixVector(publicKey.H, applyPermutation(publicKey.y, pi), q);
  if (lhs.length !== publicKey.b.length) {
    return false;
  }
  for (let i = 0; i < lhs.length; i += 1) {
    if (lhs[i] !== publicKey.b[i]) {
      return false;
    }
  }
  return true;
}
