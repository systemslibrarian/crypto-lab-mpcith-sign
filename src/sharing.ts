function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

function concatBytes(chunks: Uint8Array[]): Uint8Array {
  let length = 0;
  for (const chunk of chunks) {
    length += chunk.length;
  }
  const out = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const copy = new Uint8Array(data.length);
  copy.set(data);
  const hash = await crypto.subtle.digest('SHA-256', copy.buffer);
  return new Uint8Array(hash);
}

/**
 * Additive secret sharing over GF(2^8) (byte arithmetic).
 * Split secret s into N shares: s1 xor s2 xor ... xor sN = s
 * N-1 shares are random; last share = s xor s1 xor ... xor sN-1
 */
export async function shareSecret(secret: Uint8Array, N: number): Promise<Uint8Array[]> {
  if (!Number.isInteger(N) || N < 2) {
    throw new Error('N must be an integer >= 2');
  }

  const shares: Uint8Array[] = [];
  for (let i = 0; i < N - 1; i += 1) {
    shares.push(randomBytes(secret.length));
  }

  const lastShare = new Uint8Array(secret.length);
  for (let i = 0; i < secret.length; i += 1) {
    let byte = secret[i];
    for (let j = 0; j < shares.length; j += 1) {
      byte ^= shares[j][i];
    }
    lastShare[i] = byte;
  }
  shares.push(lastShare);

  return shares;
}

/**
 * Reconstruct secret from all N shares.
 * XOR all shares together.
 */
export function reconstructSecret(shares: Uint8Array[]): Uint8Array {
  if (shares.length === 0) {
    throw new Error('At least one share is required');
  }

  const length = shares[0].length;
  for (const share of shares) {
    if (share.length !== length) {
      throw new Error('All shares must have equal length');
    }
  }

  const secret = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) {
    let value = 0;
    for (const share of shares) {
      value ^= share[i];
    }
    secret[i] = value;
  }
  return secret;
}

/**
 * Reconstruct from N-1 shares (with one missing).
 * Returns partial XOR — the missing share is needed to complete.
 */
export function partialReconstruct(shares: Uint8Array[], missingIndex: number): Uint8Array {
  if (shares.length === 0) {
    throw new Error('At least one share is required');
  }
  if (!Number.isInteger(missingIndex) || missingIndex < 0 || missingIndex >= shares.length) {
    throw new Error('missingIndex out of range');
  }

  const length = shares[0].length;
  for (const share of shares) {
    if (share.length !== length) {
      throw new Error('All shares must have equal length');
    }
  }

  const partial = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) {
    let value = 0;
    for (let j = 0; j < shares.length; j += 1) {
      if (j === missingIndex) {
        continue;
      }
      value ^= shares[j][i];
    }
    partial[i] = value;
  }

  return partial;
}

/**
 * Commit to a value using SHA-256.
 * commitment = SHA-256(salt || value)
 * salt: 16 random bytes (prevents commitment grinding)
 */
export async function commit(
  value: Uint8Array,
  salt?: Uint8Array,
): Promise<{ commitment: Uint8Array; salt: Uint8Array }> {
  const chosenSalt = salt ? new Uint8Array(salt) : randomBytes(16);
  const commitment = await sha256(concatBytes([chosenSalt, value]));
  return { commitment, salt: chosenSalt };
}

/**
 * Verify a commitment.
 */
export async function verifyCommit(
  value: Uint8Array,
  salt: Uint8Array,
  commitment: Uint8Array,
): Promise<boolean> {
  const recomputed = await sha256(concatBytes([salt, value]));
  if (recomputed.length !== commitment.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < recomputed.length; i += 1) {
    diff |= recomputed[i] ^ commitment[i];
  }
  return diff === 0;
}

/**
 * Merkle tree over commitments.
 * Used to batch-commit to all N party commitments in one root hash.
 * Enables revealing N-1 commitments with O(log N) overhead.
 */
export async function merkleRoot(leaves: Uint8Array[]): Promise<Uint8Array> {
  if (leaves.length === 0) {
    throw new Error('At least one leaf is required');
  }

  let layer = leaves.slice();
  while (layer.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      const left = layer[i];
      const right = layer[i + 1] ?? layer[i];
      next.push(await sha256(concatBytes([left, right])));
    }
    layer = next;
  }
  return layer[0];
}

export async function merkleProof(
  leaves: Uint8Array[],
  revealIndex: number,
): Promise<{ root: Uint8Array; proof: Uint8Array[] }> {
  if (leaves.length === 0) {
    throw new Error('At least one leaf is required');
  }
  if (!Number.isInteger(revealIndex) || revealIndex < 0 || revealIndex >= leaves.length) {
    throw new Error('revealIndex out of range');
  }

  const proof: Uint8Array[] = [];
  let index = revealIndex;
  let layer = leaves.slice();

  while (layer.length > 1) {
    const isRightNode = index % 2 === 1;
    const siblingIndex = isRightNode ? index - 1 : index + 1;
    proof.push(layer[siblingIndex] ?? layer[index]);

    const next: Uint8Array[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      const left = layer[i];
      const right = layer[i + 1] ?? layer[i];
      next.push(await sha256(concatBytes([left, right])));
    }

    index = Math.floor(index / 2);
    layer = next;
  }

  return { root: layer[0], proof };
}

export async function verifyMerkleProof(
  leaf: Uint8Array,
  index: number,
  proof: Uint8Array[],
  root: Uint8Array,
): Promise<boolean> {
  if (!Number.isInteger(index) || index < 0) {
    return false;
  }

  let computed = leaf;
  let currentIndex = index;
  for (const sibling of proof) {
    if (currentIndex % 2 === 0) {
      computed = await sha256(concatBytes([computed, sibling]));
    } else {
      computed = await sha256(concatBytes([sibling, computed]));
    }
    currentIndex = Math.floor(currentIndex / 2);
  }

  if (computed.length !== root.length) {
    return false;
  }

  let diff = 0;
  for (let i = 0; i < computed.length; i += 1) {
    diff |= computed[i] ^ root[i];
  }
  return diff === 0;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.trim().replace(/^0x/i, '');
  if (clean.length === 0) {
    return new Uint8Array();
  }
  if (clean.length % 2 !== 0) {
    throw new Error('Hex input must contain an even number of digits');
  }
  if (!/^[0-9a-fA-F]+$/.test(clean)) {
    throw new Error('Hex input contains non-hex characters');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    out[i / 2] = Number.parseInt(clean.slice(i, i + 2), 16);
  }
  return out;
}
