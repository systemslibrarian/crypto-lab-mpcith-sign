import {
  bytesToHex,
  commit,
  merkleProof,
  merkleRoot,
  verifyCommit,
  verifyMerkleProof,
} from './sharing';

export interface MPCParams {
  N: number;
  tau: number;
  q: number;
}

export interface Statement {
  A: number[][];
  b: number[];
  q: number;
}

export interface MPCView {
  share: number[];
  output: number[];
  salt: Uint8Array;
}

export interface MPCSignature {
  merkleRoots: Uint8Array[];
  challenge: Uint8Array;
  hiddenParties: number[];
  revealedViews: Array<
    Array<{
      share: number[];
      output: number[];
      salt: Uint8Array;
      merkleProof: Uint8Array[];
    } | null>
  >;
}

function randomInt(maxExclusive: number): number {
  if (!Number.isInteger(maxExclusive) || maxExclusive <= 0 || maxExclusive > 256) {
    throw new Error('maxExclusive must be an integer in [1, 256]');
  }
  const sample = new Uint8Array(1);
  while (true) {
    crypto.getRandomValues(sample);
    const value = sample[0];
    const limit = 256 - (256 % maxExclusive);
    if (value < limit) {
      return value % maxExclusive;
    }
  }
}

function mod(x: number, q: number): number {
  const r = x % q;
  return r < 0 ? r + q : r;
}

function validateParams(params: MPCParams): void {
  if (!Number.isInteger(params.N) || params.N < 2) {
    throw new Error('params.N must be >= 2');
  }
  if (!Number.isInteger(params.tau) || params.tau < 1) {
    throw new Error('params.tau must be >= 1');
  }
  if (!Number.isInteger(params.q) || params.q < 2 || params.q > 251) {
    throw new Error('params.q must be in [2, 251] for byte-safe demo arithmetic');
  }
}

function validateStatement(statement: Statement): void {
  const { A, b, q } = statement;
  if (!Number.isInteger(q) || q < 2) {
    throw new Error('Invalid field modulus');
  }
  if (!Array.isArray(A) || A.length === 0) {
    throw new Error('A must be a non-empty matrix');
  }
  const n = A[0]?.length ?? 0;
  if (n === 0) {
    throw new Error('A must have at least one column');
  }
  for (const row of A) {
    if (row.length !== n) {
      throw new Error('A must be rectangular');
    }
    for (const value of row) {
      if (!Number.isInteger(value) || value < 0 || value >= q) {
        throw new Error('A contains out-of-range field element');
      }
    }
  }
  if (b.length !== A.length) {
    throw new Error('b length must equal matrix row count');
  }
  for (const value of b) {
    if (!Number.isInteger(value) || value < 0 || value >= q) {
      throw new Error('b contains out-of-range field element');
    }
  }
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

function addVectorsMod(a: number[], b: number[], q: number): number[] {
  if (a.length !== b.length) {
    throw new Error('Vector length mismatch');
  }
  const out = new Array<number>(a.length);
  for (let i = 0; i < a.length; i += 1) {
    out[i] = mod(a[i] + b[i], q);
  }
  return out;
}

function subtractVectorsMod(a: number[], b: number[], q: number): number[] {
  if (a.length !== b.length) {
    throw new Error('Vector length mismatch');
  }
  const out = new Array<number>(a.length);
  for (let i = 0; i < a.length; i += 1) {
    out[i] = mod(a[i] - b[i], q);
  }
  return out;
}

function encodeVector(values: number[]): Uint8Array {
  return Uint8Array.from(values.map((v) => v & 0xff));
}

function concatBytes(parts: Uint8Array[]): Uint8Array {
  let length = 0;
  for (const part of parts) {
    length += part.length;
  }
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function serializeViewShareOutput(share: number[], output: number[]): Uint8Array {
  return concatBytes([encodeVector(share), encodeVector(output)]);
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const copy = new Uint8Array(data.length);
  copy.set(data);
  const hash = await crypto.subtle.digest('SHA-256', copy.buffer);
  return new Uint8Array(hash);
}

function deriveHiddenParty(challenge: Uint8Array, round: number, N: number): number {
  const byte = challenge[round % challenge.length];
  if ((N & (N - 1)) === 0) {
    return byte & (N - 1);
  }
  return byte % N;
}

function arraysEqual(a: number[], b: number[]): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

function splitWitnessAdditive(witness: number[], N: number, q: number): number[][] {
  const n = witness.length;
  const shares: number[][] = [];
  const partialSum = new Array<number>(n).fill(0);

  for (let party = 0; party < N - 1; party += 1) {
    const share = new Array<number>(n);
    for (let i = 0; i < n; i += 1) {
      share[i] = randomInt(q);
      partialSum[i] = mod(partialSum[i] + share[i], q);
    }
    shares.push(share);
  }

  const lastShare = new Array<number>(n);
  for (let i = 0; i < n; i += 1) {
    lastShare[i] = mod(witness[i] - partialSum[i], q);
  }
  shares.push(lastShare);
  return shares;
}

function validateWitness(witness: number[], n: number, q: number): void {
  if (witness.length !== n) {
    throw new Error('Witness length mismatch with matrix columns');
  }
  for (const value of witness) {
    if (!Number.isInteger(value) || value < 0 || value >= q) {
      throw new Error('Witness contains out-of-range field element');
    }
  }
}

export async function generateStatement(
  n: number,
  m: number,
  q: number,
): Promise<{ statement: Statement; witness: number[] }> {
  if (!Number.isInteger(n) || n <= 0 || !Number.isInteger(m) || m <= 0) {
    throw new Error('n and m must be positive integers');
  }
  if (!Number.isInteger(q) || q < 2 || q > 251) {
    throw new Error('q must be in [2, 251] for this demo');
  }

  const witness = Array.from({ length: n }, () => randomInt(q));
  const A = Array.from({ length: m }, () => Array.from({ length: n }, () => randomInt(q)));
  const b = multiplyMatrixVector(A, witness, q);
  return {
    statement: { A, b, q },
    witness,
  };
}

export async function mpcRound(
  statement: Statement,
  witness: number[],
  params: MPCParams,
): Promise<{
  merkleRoot: Uint8Array;
  commitments: Uint8Array[];
  views: Array<{
    share: number[];
    output: number[];
    salt: Uint8Array;
  }>;
  partyOutputs: number[][];
}> {
  validateParams(params);
  validateStatement(statement);

  const q = statement.q;
  const n = statement.A[0].length;
  validateWitness(witness, n, q);

  const shares = splitWitnessAdditive(witness, params.N, q);
  const partyOutputs = shares.map((share) => multiplyMatrixVector(statement.A, share, q));

  let outputSum = new Array<number>(statement.b.length).fill(0);
  for (const out of partyOutputs) {
    outputSum = addVectorsMod(outputSum, out, q);
  }
  if (!arraysEqual(outputSum, statement.b)) {
    throw new Error('MPC share outputs do not sum to public target b');
  }

  const views: MPCView[] = [];
  const commitments: Uint8Array[] = [];
  for (let i = 0; i < params.N; i += 1) {
    const share = shares[i];
    const output = partyOutputs[i];
    const value = serializeViewShareOutput(share, output);
    const { commitment, salt } = await commit(value);
    commitments.push(commitment);
    views.push({ share, output, salt });
  }

  const root = await merkleRoot(commitments);

  return {
    merkleRoot: root,
    commitments,
    views,
    partyOutputs,
  };
}

function serializeRootsForChallenge(message: Uint8Array, roots: Uint8Array[]): Uint8Array {
  return concatBytes([message, ...roots]);
}

export async function sign(
  message: Uint8Array,
  statement: Statement,
  witness: number[],
  params: MPCParams,
): Promise<{
  signature: MPCSignature;
  challengeDerivation: string;
}> {
  validateParams(params);
  validateStatement(statement);

  const rounds: Array<Awaited<ReturnType<typeof mpcRound>>> = [];
  for (let r = 0; r < params.tau; r += 1) {
    rounds.push(await mpcRound(statement, witness, params));
  }

  const roots = rounds.map((round) => round.merkleRoot);
  const challengeInput = serializeRootsForChallenge(message, roots);
  const challenge = await sha256(challengeInput);

  const hiddenParties: number[] = [];
  const revealedViews: MPCSignature['revealedViews'] = [];

  for (let r = 0; r < params.tau; r += 1) {
    const hidden = deriveHiddenParty(challenge, r, params.N);
    hiddenParties.push(hidden);

    const row: Array<{
      share: number[];
      output: number[];
      salt: Uint8Array;
      merkleProof: Uint8Array[];
    } | null> = [];

    for (let party = 0; party < params.N; party += 1) {
      if (party === hidden) {
        row.push(null);
        continue;
      }
      const view = rounds[r].views[party];
      const proof = await merkleProof(rounds[r].commitments, party);
      row.push({
        share: view.share,
        output: view.output,
        salt: view.salt,
        merkleProof: proof.proof,
      });
    }

    revealedViews.push(row);
  }

  const derivationLines: string[] = [];
  derivationLines.push(`message = ${bytesToHex(message)}`);
  roots.forEach((root, idx) => {
    derivationLines.push(`root_${idx + 1} = ${bytesToHex(root)}`);
  });
  derivationLines.push(`challenge = SHA-256(message || roots) = ${bytesToHex(challenge)}`);
  hiddenParties.forEach((hidden, idx) => {
    derivationLines.push(`round ${idx + 1}: hidden party = ${hidden}`);
  });

  return {
    signature: {
      merkleRoots: roots,
      challenge,
      hiddenParties,
      revealedViews,
    },
    challengeDerivation: derivationLines.join('\n'),
  };
}

export async function verify(
  message: Uint8Array,
  statement: Statement,
  signature: MPCSignature,
  params: MPCParams,
): Promise<{ valid: boolean; failureReason?: string }> {
  try {
    validateParams(params);
    validateStatement(statement);

    if (signature.merkleRoots.length !== params.tau) {
      return { valid: false, failureReason: 'Wrong number of Merkle roots' };
    }
    if (signature.revealedViews.length !== params.tau) {
      return { valid: false, failureReason: 'Wrong number of rounds in revealed views' };
    }
    if (signature.hiddenParties.length !== params.tau) {
      return { valid: false, failureReason: 'Wrong number of hidden party indexes' };
    }

    const challengeInput = serializeRootsForChallenge(message, signature.merkleRoots);
    const expectedChallenge = await sha256(challengeInput);
    if (!bytesEqual(expectedChallenge, signature.challenge)) {
      return { valid: false, failureReason: 'Fiat-Shamir challenge mismatch' };
    }

    for (let r = 0; r < params.tau; r += 1) {
      const expectedHidden = deriveHiddenParty(signature.challenge, r, params.N);
      if (signature.hiddenParties[r] !== expectedHidden) {
        return { valid: false, failureReason: `Hidden party mismatch in round ${r + 1}` };
      }

      const revealed = signature.revealedViews[r];
      if (revealed.length !== params.N) {
        return { valid: false, failureReason: `Wrong party count in round ${r + 1}` };
      }

      const sumOutputs = new Array<number>(statement.b.length).fill(0);
      for (let party = 0; party < params.N; party += 1) {
        const view = revealed[party];
        const isHidden = party === expectedHidden;

        if (isHidden) {
          if (view !== null) {
            return { valid: false, failureReason: `Hidden party ${party} was revealed in round ${r + 1}` };
          }
          continue;
        }

        if (view === null) {
          return { valid: false, failureReason: `Missing revealed party ${party} in round ${r + 1}` };
        }

        if (view.share.length !== statement.A[0].length) {
          return { valid: false, failureReason: `Share length mismatch in round ${r + 1}, party ${party}` };
        }
        if (view.output.length !== statement.b.length) {
          return { valid: false, failureReason: `Output length mismatch in round ${r + 1}, party ${party}` };
        }

        for (const value of view.share) {
          if (!Number.isInteger(value) || value < 0 || value >= statement.q) {
            return { valid: false, failureReason: `Share value out of range in round ${r + 1}, party ${party}` };
          }
        }
        for (const value of view.output) {
          if (!Number.isInteger(value) || value < 0 || value >= statement.q) {
            return { valid: false, failureReason: `Output value out of range in round ${r + 1}, party ${party}` };
          }
        }

        const recomputedOutput = multiplyMatrixVector(statement.A, view.share, statement.q);
        if (!arraysEqual(recomputedOutput, view.output)) {
          return { valid: false, failureReason: `Local MPC output mismatch in round ${r + 1}, party ${party}` };
        }

        const serialized = serializeViewShareOutput(view.share, view.output);
        const { commitment } = await commit(serialized, view.salt);
        const commitmentOk = await verifyCommit(serialized, view.salt, commitment);
        if (!commitmentOk) {
          return { valid: false, failureReason: `Commitment self-check failed in round ${r + 1}, party ${party}` };
        }

        const proofOk = await verifyMerkleProof(
          commitment,
          party,
          view.merkleProof,
          signature.merkleRoots[r],
        );
        if (!proofOk) {
          return { valid: false, failureReason: `Merkle proof failed in round ${r + 1}, party ${party}` };
        }

        for (let i = 0; i < sumOutputs.length; i += 1) {
          sumOutputs[i] = mod(sumOutputs[i] + view.output[i], statement.q);
        }
      }

      const impliedHiddenOutput = subtractVectorsMod(statement.b, sumOutputs, statement.q);
      for (const value of impliedHiddenOutput) {
        if (value < 0 || value >= statement.q) {
          return { valid: false, failureReason: `Implied hidden output out of range in round ${r + 1}` };
        }
      }
    }

    return { valid: true };
  } catch (error) {
    return {
      valid: false,
      failureReason: error instanceof Error ? error.message : 'Unknown verification error',
    };
  }
}
