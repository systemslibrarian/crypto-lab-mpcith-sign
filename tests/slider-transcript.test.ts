import { expect, it } from 'vitest';
import { mpcRound } from '../src/mpcith';
import { commit } from '../src/sharing';

const A = [[1, 2, 3, 4], [2, 0, 1, 3], [0, 1, 2, 1]];
const x = [2, 3, 4, 5];

async function outputFor(witness: number[], b = [40, 23, 16]): Promise<number[]> {
  const round = await mpcRound({ A, b, q: 251 }, witness, { N: 4, tau: 4, q: 251 });
  return [0, 1, 2].map(i => round.partyOutputs.reduce((sum, row) => sum + row[i], 0) % 251);
}

it('a first-coordinate slider edit generally changes the fixed statement', async () => {
  expect(await outputFor(x)).toEqual([40, 23, 16]);
  await expect(outputFor([3, 3, 4, 5])).rejects.toThrow('MPC share outputs do not sum to public target b');
  expect(await outputFor([3, 3, 4, 5], [41, 25, 16])).toEqual([41, 25, 16]);
});

it('a kernel edit preserves the statement but not the original committed view bytes', async () => {
  // A*(-5,-5,1,3) = 0 by independent integer arithmetic.
  const alternative = [248, 249, 5, 8];
  expect(await outputFor(alternative)).toEqual([40, 23, 16]);
  const salt = new Uint8Array(32).fill(17);
  const original = await commit(Uint8Array.from([...x, 40, 23, 16]), salt);
  const edited = await commit(Uint8Array.from([...alternative, 40, 23, 16]), salt);
  expect(edited.commitment).not.toEqual(original.commitment);
});
