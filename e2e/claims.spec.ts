import { expect, test as base, type Locator, type Page } from '@playwright/test';

/**
 * Functional gate on the claims this lab makes on screen.
 *
 * The two a11y suites drive every control but assert only axe; the Vitest suite
 * checks the crypto in isolation. Neither checks that the *page* says true
 * things about the round it just ran. This suite re-derives each headline from
 * the numbers the page itself printed: the three shares against the secret they
 * XOR to, the party shares against the witness, the party outputs against the
 * published b, the zero-knowledge required-output against b − Σ(revealed), the
 * cheating tally against (1/N)^τ, and the threaded signature against the exact
 * statement Exhibit 2 published.
 */

const test = base.extend<{ pageErrors: string[] }>({
  pageErrors: [
    async ({ page }, use) => {
      const errors: string[] = [];
      page.on('pageerror', (error) => errors.push(`pageerror: ${error.message}`));
      page.on('console', (message) => {
        if (message.type() === 'error') errors.push(`console.error: ${message.text()}`);
      });
      await use(errors);
      expect(errors, 'uncaught page errors').toEqual([]);
    },
    { auto: true },
  ],
});

const Q_DEFAULT = 251;

async function open(page: Page): Promise<void> {
  await page.goto('.');
  await expect(page.locator('.flow-banner')).toBeVisible();
}

function exhibit(page: Page, heading: string): Locator {
  return page.locator('section.panel').filter({ has: page.locator(`h2:text-is("${heading}")`) });
}

async function flat(locator: Locator): Promise<string> {
  return (await locator.innerText()).replace(/\s+/g, ' ').trim();
}

function grab(source: string, pattern: RegExp): RegExpMatchArray {
  const match = source.match(pattern);
  expect(match, `expected ${pattern} in: ${source}`).not.toBeNull();
  return match as RegExpMatchArray;
}

/** Parse a printed vector like "[1, 2, 3]". */
const vec = (text: string): number[] => text.split(',').map((v) => Number(v.trim()));

const mod = (x: number, q: number): number => ((x % q) + q) % q;

const sumVectors = (vectors: number[][], q: number): number[] =>
  vectors.reduce(
    (acc, v) => acc.map((value, i) => mod(value + v[i]!, q)),
    new Array<number>(vectors[0]?.length ?? 0).fill(0),
  );

const verdict = (page: Page): Locator => page.locator('.verify-result');

/** The flow banner's three stages: typed secret, derived witness, published b. */
async function flow(page: Page): Promise<{ secret: string; witness: number[]; b: number[] | null }> {
  const text = await flat(page.locator('.flow-banner'));
  const m = grab(text, /secret (\S+) → witness x (\[[^\]]*\]|—) → public b = A·x (\[[^\]]*\]|run MPC to publish b)/);
  return {
    secret: m[1]!,
    witness: m[2] === '—' ? [] : vec(m[2]!.slice(1, -1)),
    b: m[3]!.startsWith('[') ? vec(m[3]!.slice(1, -1)) : null,
  };
}

/** Every party card's printed witness share and A·share output ('sealed' → null). */
async function partyCards(
  page: Page,
): Promise<Array<{ share: number[] | null; output: number[] | null; hidden: boolean }>> {
  const cards = page.locator('.party-card');
  const out: Array<{ share: number[] | null; output: number[] | null; hidden: boolean }> = [];
  for (let i = 0; i < (await cards.count()); i += 1) {
    const text = await flat(cards.nth(i));
    const share = grab(text, /Witness share \(mod q\): (\[[^\]]*\]|sealed|pending)/)[1]!;
    const output = grab(text, /My output A·share: (\[[^\]]*\]|sealed|pending)/)[1]!;
    out.push({
      share: share.startsWith('[') ? vec(share.slice(1, -1)) : null,
      output: output.startsWith('[') ? vec(output.slice(1, -1)) : null,
      hidden: (await cards.nth(i).getAttribute('class'))?.includes('hidden') ?? false,
    });
  }
  return out;
}

/** Type a secret, split it, and commit an MPC round over it. */
async function buildRound(page: Page, secretHex: string): Promise<void> {
  await page.locator('#secret-hex').fill(secretHex);
  await page.locator('#split-secret').click();
  await expect(verdict(page)).toContainText('Split complete');
  await page.locator('#run-mpc').click();
  await expect(verdict(page)).toContainText('MPC views committed');
}

// ---------------------------------------------------------------------------
// Exhibit 1
// ---------------------------------------------------------------------------

test('exhibit 1: the three printed shares XOR back to the printed secret', async ({ page }) => {
  await open(page);
  const cards = exhibit(page, 'Exhibit 1 — The Idea');

  const read = async () => {
    const text = await flat(cards);
    const m = grab(
      text,
      /SECRET: (\d+) Party A: (\d+) Party B: (\d+) Party C: (\d+) Challenge: hide Party ([ABC])/,
    );
    return {
      secret: Number(m[1]),
      shares: [Number(m[2]), Number(m[3]), Number(m[4])],
      hidden: m[5]!,
    };
  };

  const first = await read();
  // The analogy is only honest if the shares really reconstruct the secret.
  expect(first.shares.reduce((a, b) => a ^ b)).toBe(first.secret);

  await page.locator('#reshuffle-cards').click();
  const second = await read();
  expect(second.shares.reduce((a, b) => a ^ b)).toBe(second.secret);
  expect(second.secret, 'reshuffling changes the shares, not the secret').toBe(first.secret);
  expect(second.shares).not.toEqual(first.shares);
  expect(['A', 'B', 'C']).toContain(second.hidden);
});

// ---------------------------------------------------------------------------
// Exhibit 2 — the MPC round
// ---------------------------------------------------------------------------

test('exhibit 2: the shares add up to the typed witness and the outputs add up to b', async ({
  page,
}) => {
  await open(page);
  await buildRound(page, '2a7f');

  const state = await flow(page);
  expect(state.secret).toBe('2a7f');
  // Each byte of the typed secret becomes one witness coordinate (mod q).
  expect(state.witness).toEqual([0x2a % Q_DEFAULT, 0x7f % Q_DEFAULT]);
  expect(state.b).not.toBeNull();

  const cards = await partyCards(page);
  expect(cards).toHaveLength(4);
  expect(cards.every((c) => c.share !== null && c.output !== null)).toBe(true);

  // Additive secret sharing: the party shares sum (mod q) to the witness.
  expect(sumVectors(cards.map((c) => c.share!), Q_DEFAULT)).toEqual(state.witness);
  // Linearity: the party outputs sum (mod q) to the published b.
  expect(sumVectors(cards.map((c) => c.output!), Q_DEFAULT)).toEqual(state.b);

  await expect(verdict(page)).toContainText('each party holds one additive share of YOUR witness');
});

test('exhibit 2: all-but-one opening accepts, and exactly one view stays sealed', async ({ page }) => {
  await open(page);
  await buildRound(page, '2a7f');

  await page.locator('#run-challenge').click();
  const challenged = Number(grab(await flat(verdict(page)), /Challenge set: party (\d+) is hidden/)[1]);

  const cards = await partyCards(page);
  const hiddenIndexes = cards.flatMap((c, i) => (c.hidden ? [i] : []));
  expect(hiddenIndexes).toEqual([challenged - 1]);
  // The sealed party's share and output are withheld, not printed.
  expect(cards[challenged - 1]!.share).toBeNull();
  expect(cards[challenged - 1]!.output).toBeNull();

  await page.locator('#run-verify').click();
  await expect(verdict(page)).toContainText('Verifier accepted');

  const accepted = await flat(verdict(page));
  // The count of checked views is N − 1, and the sealed party is named.
  expect(Number(grab(accepted, /Verifier accepted all (\d+) revealed views/)[1])).toBe(cards.length - 1);
  expect(accepted).toContain(`Party ${challenged} stayed sealed, yet the proof holds`);
  expect(accepted).toContain('satisfies output = A·share');
  expect(accepted).not.toContain('rejected');
});

test('exhibit 2 failure paths: each precondition is enforced and named', async ({ page }) => {
  await open(page);

  // Verify before anything is committed.
  await page.locator('#run-verify').click();
  await expect(verdict(page)).toHaveText('Split, run MPC, and challenge first.');

  // MPC with an empty secret.
  await page.locator('#secret-hex').fill('');
  await page.locator('#run-mpc').click();
  await expect(verdict(page)).toHaveText('Type a hex secret and Split first.');
  expect((await flow(page)).b).toBeNull();

  await buildRound(page, '2a7f');

  // Changing the party count invalidates the committed round.
  await page.locator('#n-slider').fill('6');
  await expect(verdict(page)).toHaveText('Party count changed. Run MPC again.');
  let cards = await partyCards(page);
  expect(cards).toHaveLength(6);
  expect(cards.every((c) => c.share === null && c.output === null)).toBe(true);

  // As does changing the field.
  await buildRound(page, '2a7f');
  await page.locator('#q-select').selectOption('101');
  await expect(verdict(page)).toHaveText('Field q changed. Run MPC again.');

  // Regression: a published b belongs to the witness it was computed from. Type
  // a new secret and the stale b must go with it, rather than sitting beside a
  // witness it does not match.
  await page.locator('#q-select').selectOption('251');
  await buildRound(page, '2a7f');
  const published = await flow(page);
  expect(published.b).not.toBeNull();
  await page.locator('#secret-hex').fill('0102');
  await expect(verdict(page)).toHaveText('Secret changed. Split and run MPC again.');
  const stale = await flow(page);
  expect(stale.witness).toEqual([1, 2]);
  expect(stale.b, 'the old b must not be shown as A·x for the new x').toBeNull();
  cards = await partyCards(page);
  expect(cards.every((c) => c.share === null)).toBe(true);
});

test('zero-knowledge panel: the sealed output is pinned by b, the sealed share is not', async ({
  page,
}) => {
  await open(page);
  await buildRound(page, '2a7f');
  await page.locator('#run-challenge').click();

  const revealed = (await partyCards(page)).filter((c) => !c.hidden).map((c) => c.output!);
  const published = (await flow(page)).b!;

  await page.locator('#run-verify').click();
  await expect(page.locator('.zk-body')).toContainText('the missing one is pinned');

  const zk = await flat(page.locator('.zk-body'));
  const required = vec(grab(zk, /b − Σ\(revealed outputs\) = \[([^\]]*)\]/)[1]!);
  // The panel's required output really is b − Σ(revealed outputs).
  const sumRevealed = sumVectors(revealed, Q_DEFAULT);
  expect(required).toEqual(published.map((value, i) => mod(value - sumRevealed[i]!, Q_DEFAULT)));

  // Exactly one candidate — the prover's real share — hits that output.
  const rows = page.locator('.zk-body tbody tr');
  await expect(rows).toHaveCount(3);
  await expect(page.locator('.zk-body tbody tr.zk-row-match')).toHaveCount(1);
  const firstRow = await flat(rows.nth(0));
  expect(firstRow).toContain('the prover’s real share');
  expect(firstRow).toContain('matches');
  for (let i = 1; i < 3; i += 1) {
    const row = await flat(rows.nth(i));
    expect(row).toContain(`random guess #${i}`);
    expect(row).toContain('rejected');
    // The decoy's own output is printed, and it differs from the required one.
    const decoy = vec(grab(row, /rejected — output = \[([^\]]*)\]/)[1]!);
    expect(decoy).not.toEqual(required);
  }

  // The slider walks alternative witnesses. Δ = 0 is the real one…
  const trueShare = vec(grab(firstRow, /the prover’s real share \[([^\]]*)\]/)[1]!);
  const readSlider = async () => {
    const text = await flat(page.locator('#zk-slider-readout'));
    return {
      share: vec(grab(text, /sealed share becomes \[([^\]]*)\]/)[1]!),
      output: vec(grab(text, /its output would be \[([^\]]*)\]/)[1]!),
      hitsB: text.includes('still hits b'),
      transcript: grab(text, /revealed transcript (\w+)/)[1]!,
    };
  };
  let slider = await readSlider();
  expect(slider.share).toEqual(trueShare);
  expect(slider.output).toEqual(required);
  expect(slider.hitsB).toBe(true);

  // …and any other Δ is a different witness with the same revealed transcript.
  const transcriptBefore = await flat(page.locator('.party-grid'));
  await page.locator('#zk-share-slider').fill('7');
  await expect(page.locator('.zk-delta')).toHaveText('Δ = 7');
  slider = await readSlider();
  expect(slider.share[0]).toBe(mod(trueShare[0]! + 7, Q_DEFAULT));
  expect(slider.share.slice(1)).toEqual(trueShare.slice(1));
  expect(slider.output).not.toEqual(required);
  expect(slider.hitsB).toBe(false);
  expect(slider.transcript).toBe('unchanged');
  // The claim that the transcript does not move, checked against the transcript.
  expect(await flat(page.locator('.party-grid'))).toBe(transcriptBefore);
});

// ---------------------------------------------------------------------------
// Exhibit 2b — the cheating prover
// ---------------------------------------------------------------------------

async function cheatTally(page: Page): Promise<{
  trials: number;
  caught: number;
  slipped: number;
  empirical: number;
  theory: number;
}> {
  const result = await flat(page.locator('.cheat-result'));
  const stat = await flat(page.locator('.cheat-stat'));
  const m = grab(
    result,
    /(\d+) forgery attempts against the real verifier: caught (\d+), accepted (\d+)\. Empirical acceptance rate ([\d.]+)% vs theory \(1\/N\)\^τ = ([\d.]+)%/,
  );
  expect(stat).toContain(`${m[5]}%`);
  return {
    trials: Number(m[1]),
    caught: Number(m[2]),
    slipped: Number(m[3]),
    empirical: Number(m[4]),
    theory: Number(m[5]),
  };
}

test('cheating prover: the tally adds up and the acceptance rate tracks (1/N)^tau', async ({
  page,
}) => {
  test.setTimeout(180_000);
  await open(page);

  // N = 4, τ = 1 — the default: a forger escapes only when the one round hides
  // the party they corrupted, i.e. 1 time in 4.
  await page.locator('#cheat-100').click();
  await expect(page.locator('.cheat-result')).toContainText('forgery attempts', { timeout: 60_000 });

  const first = await cheatTally(page);
  expect(first.trials).toBe(100);
  // Parts sum to the whole.
  expect(first.caught + first.slipped).toBe(first.trials);
  expect(first.empirical).toBeCloseTo((first.slipped / first.trials) * 100, 1);
  expect(first.theory).toBeCloseTo(25, 4);
  // Measured, not asserted: allow a wide band but reject a broken verifier.
  expect(first.slipped).toBeGreaterThan(4);
  expect(first.slipped).toBeLessThan(50);
  // A rejection must name its reason. The line reports the most recent attempt,
  // so run single attempts until one is caught (p ≈ 0.75 each).
  let reason = '';
  for (let i = 0; i < 12 && !reason; i += 1) {
    await page.locator('#cheat-once').click();
    await expect(page.locator('.cheat-result')).toContainText(`${101 + i} forgery attempts`, {
      timeout: 30_000,
    });
    const line = await flat(page.locator('.cheat-result'));
    const match = line.match(/Last rejection: ([^.]+)\./);
    if (match) reason = match[1]!;
  }
  expect(reason, 'a caught forgery must say why the verifier rejected it').not.toBe('');
  expect(reason).toMatch(/round \d+/);

  // Reset clears the tally.
  await page.locator('#cheat-reset').click();
  await expect(page.locator('.cheat-result')).toHaveText('');

  // τ = 8 over N = 8: (1/8)^8 ≈ 6e-8, so no forgery may slip through.
  await page.locator('#cheat-n').fill('8');
  await page.locator('#cheat-tau').fill('8');
  await expect(page.locator('#cheat-tau-value')).toHaveText('8');
  await page.locator('#cheat-once').click();
  await expect(page.locator('.cheat-result')).toContainText('forgery attempts', { timeout: 60_000 });
  for (let i = 0; i < 9; i += 1) {
    await page.locator('#cheat-once').click();
    await expect(page.locator('.cheat-result')).toContainText(`${i + 2} forgery attempts`, {
      timeout: 60_000,
    });
  }

  const hard = await cheatTally(page);
  expect(hard.trials).toBe(10);
  expect(hard.caught + hard.slipped).toBe(hard.trials);
  expect(hard.theory).toBeLessThan(0.001);
  expect(hard.slipped, 'a 8-round forgery must not be accepted').toBe(0);
  expect(hard.caught).toBe(hard.trials);
  expect(hard.empirical).toBe(0);
});

// ---------------------------------------------------------------------------
// Exhibit 3 — Fiat-Shamir
// ---------------------------------------------------------------------------

/** The hidden-party list, as the Exhibit 3 summary line reports it. */
async function hiddenLine(page: Page): Promise<number[]> {
  const text = await flat(exhibit(page, 'Exhibit 3 — Fiat-Shamir Signature'));
  const list = grab(text, /Hidden parties per round: ((?:party \d+(?:, )?)+)/)[1]!;
  return [...list.matchAll(/party (\d+)/g)].map((m) => Number(m[1]));
}

test('fiat-shamir: the challenge binds the message, and changing it moves the hidden parties', async ({
  page,
}) => {
  await open(page);

  await page.locator('#run-fs').click();
  await expect(page.locator('.fs-diff')).toContainText('Challenge = SHA-256(message ‖ commitments)');

  const firstHidden = await hiddenLine(page);
  expect(firstHidden).toHaveLength(4); // τ = 4 for the standalone run
  for (const party of firstHidden) {
    expect(party).toBeGreaterThanOrEqual(1);
    expect(party).toBeLessThanOrEqual(8); // N = 8
  }

  const trace = await flat(page.locator('pre.trace'));
  const before = grab(await flat(page.locator('.fs-diff')), /now ([0-9a-f]{64})/)[1]!;
  // The trace is the real derivation: the message, one root per round, and the
  // challenge that came out.
  expect(trace).toContain('message =');
  expect([...trace.matchAll(/root_\d+ =/g)]).toHaveLength(firstHidden.length);
  expect(trace).toContain(before);

  await page.locator('#tamper-fs').click();
  await expect(page.locator('.fs-diff')).toContainText('Message changed');

  const diff = await flat(page.locator('.fs-diff'));
  const messages = grab(diff, /before (.+?) after (.+?) was ([0-9a-f]{64}) now ([0-9a-f]{64})/);
  expect(messages[2]).toBe(`${messages[1]} *`);
  expect(messages[3]).toBe(before);
  expect(messages[4], 'a different message must give a different challenge').not.toBe(before);
  // Roughly half the digest bytes should change; assert at least that some did.
  expect(await page.locator('.fs-diff mark.byte-changed').count()).toBeGreaterThan(0);

  // The flip list must agree with the summary line about who is hidden now.
  const flips = await page.locator('.fs-flip-list li').allInnerTexts();
  expect(flips).toHaveLength(firstHidden.length);
  const nowHidden = await hiddenLine(page);
  flips.forEach((line, round) => {
    const m = grab(line.replace(/\s+/g, ' '), /round (\d+): party (\d+) → party (\d+)/);
    expect(Number(m[1])).toBe(round + 1);
    expect(Number(m[2]), 'the "before" party is the previous assignment').toBe(firstHidden[round]);
    expect(Number(m[3]), 'the flip list and the summary must name the same party').toBe(
      nowHidden[round],
    );
  });
  // At least one round's hidden party moved.
  expect(nowHidden).not.toEqual(firstHidden);
});

test('sign this round: the threaded signature carries Exhibit 2 exact statement', async ({ page }) => {
  await open(page);
  await page.locator('#n-slider').fill('6');
  await buildRound(page, '2a7f');
  await page.locator('#run-challenge').click();

  const published = await flow(page);
  expect(published.b).not.toBeNull();

  await page.locator('#sign-this-round').click();
  await expect(page.locator('.thread-banner')).toBeVisible();

  const banner = await flat(page.locator('.thread-banner'));
  const claimed = grab(banner, /Same secret (\S+), same N = (\d+), same public b = \[([^\]]*)\]/);
  expect(claimed[1]).toBe(published.secret);
  expect(Number(claimed[2])).toBe(6);
  // Regression: "same public b" must be the b Exhibit 2 published, not a fresh
  // statement's b — the two panels are on screen together.
  expect(vec(claimed[3]!)).toEqual(published.b);
  expect((await flow(page)).b, 'signing must not disturb the published round').toEqual(published.b);

  // τ = N − 1 rounds, and the hash — not a human — picked the hidden parties.
  const tau = Number(grab(banner, /τ = (\d+)/)[1]);
  expect(tau).toBe(5);
  const bannerParties = [...grab(banner, /The hash picked the hidden parties: ([^.]+)\./)[1]!.matchAll(/party (\d+)/g)].map(
    (m) => Number(m[1]),
  );
  expect(bannerParties).toHaveLength(tau);
  for (const party of bannerParties) {
    expect(party).toBeGreaterThanOrEqual(1);
    expect(party).toBeLessThanOrEqual(6);
  }
  // The banner and the summary line must name the same parties.
  expect(await hiddenLine(page)).toEqual(bannerParties);
});

// ---------------------------------------------------------------------------
// Exhibit 4 — toy PERK
// ---------------------------------------------------------------------------

test('toy PERK: pi is a real rearrangement of y into x, and the signature verifies', async ({
  page,
}) => {
  await open(page);
  const perk = exhibit(page, 'Exhibit 4 — Toy PERK');

  // Failure path: nothing to verify before signing.
  await page.locator('#perk-verify').click();
  await expect(perk).toContainText('Generate keypair and signature first.');

  await page.locator('#perk-keygen').click();
  await expect(perk).toContainText('Keypair generated');

  const readVectors = async () => {
    const text = await flat(page.locator('.perm-viz'));
    const y = [...text.matchAll(/y\[(\d+)\] (\d+)/g)].map((m) => ({
      index: Number(m[1]),
      value: Number(m[2]),
    }));
    const x = [...text.matchAll(/x\[(\d+)\] (\d+) ← y\[(\d+|\?)\]/g)].map((m) => ({
      index: Number(m[1]),
      value: Number(m[2]),
      from: m[3] === '?' ? null : Number(m[3]),
    }));
    return { text, y, x };
  };

  // Sealed: the mapping is withheld, but x is still a permutation of y.
  let vectors = await readVectors();
  expect(vectors.y).toHaveLength(8);
  expect(vectors.x).toHaveLength(8);
  expect(vectors.x.every((slot) => slot.from === null)).toBe(true);
  expect(vectors.text).toContain('π is sealed');
  expect([...vectors.x].map((s) => s.value).sort((a, b) => a - b)).toEqual(
    [...vectors.y].map((s) => s.value).sort((a, b) => a - b),
  );
  // H·x = b lands on the public target.
  expect(vectors.text).toMatch(/H·x = b lands on the public target \[[\d, ]+\] ✓/);

  // Revealed: every x slot really pulls the value from the y slot it names.
  await page.locator('#perk-reveal').click();
  vectors = await readVectors();
  const froms = vectors.x.map((slot) => slot.from!);
  expect(froms.every((from) => from !== null)).toBe(true);
  expect([...froms].sort((a, b) => a - b)).toEqual([0, 1, 2, 3, 4, 5, 6, 7]); // a permutation
  for (const slot of vectors.x) {
    expect(slot.value, `x[${slot.index}] must be y[${slot.from}]`).toBe(
      vectors.y[slot.from!]!.value,
    );
    expect(vectors.text).toContain(`π: x[${slot.index}] takes y[${slot.from}]`);
  }

  await page.locator('#perk-sign').click();
  await expect(perk).toContainText('VALID signature.');
  await expect(perk).not.toContainText('INVALID');
  await page.locator('#perk-verify').click();
  await expect(perk).toContainText('VALID signature.');

  // The size breakdown adds up to the headline estimate.
  const text = await flat(perk);
  const total = Number(grab(text, /Estimated signature size: ~(\d+) bytes/)[1]);
  const parts = ['Merkle roots', 'Challenge', 'Revealed views', 'Merkle proofs'].map((label) =>
    Number(grab(text, new RegExp(`${label} (\\d+)`))[1]),
  );
  expect(parts.reduce((a, b) => a + b, 0)).toBe(total);
});
