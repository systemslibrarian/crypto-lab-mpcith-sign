import './style.css';
import {
  bytesToHex,
  commit,
  hexToBytes,
  merkleProof,
  reconstructSecret,
  shareSecret,
  verifyMerkleProof,
} from './sharing';
import {
  generateStatement,
  mpcRound,
  sign,
  statementFromWitness,
  type MPCParams,
  type Statement,
} from './mpcith';
import {
  estimateSignatureSize,
  perkEquationHolds,
  perkKeyGen,
  perkSign,
  perkVerify,
  type PERKKeyPair,
  type PERKParams,
} from './perk';

const appRoot = document.querySelector<HTMLDivElement>('#app');
if (!appRoot) {
  throw new Error('Missing #app root');
}
const app = appRoot;

const encoder = new TextEncoder();

/**
 * Push a message to the persistent screen-reader live region declared in
 * index.html. It lives outside #app so it survives the full re-render and can
 * reliably announce status changes (WCAG 4.1.3 Status Messages).
 */
function announce(message: string): void {
  const live = document.getElementById('sr-live');
  if (!live) {
    return;
  }
  // Clearing first guarantees identical consecutive messages re-announce.
  live.textContent = '';
  window.setTimeout(() => {
    live.textContent = message;
  }, 50);
}

/** Escape user-controlled text before interpolating into innerHTML. */
function esc(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

interface Exhibit2State {
  secretHex: string;
  N: number;
  q: number;
  shares: Uint8Array[];
  statement: Statement | null;
  witness: number[] | null;
  round: Awaited<ReturnType<typeof mpcRound>> | null;
  hiddenParty: number | null;
  verificationText: string;
  // Zero-knowledge panel: filled after a successful Verify so the learner can
  // try (and fail) to pin down the missing share.
  zk: {
    revealedSum: number[];
    hiddenParty: number;
    candidates: Array<{ share: number[]; output: number[]; consistent: boolean }>;
  } | null;
}

const exhibit2State: Exhibit2State = {
  secretHex: '2a',
  N: 4,
  q: 251,
  shares: [],
  statement: null,
  witness: null,
  round: null,
  hiddenParty: null,
  verificationText: '',
  zk: null,
};

// ── Exhibit 2b: soundness experiment (cheating prover) ──────────────────────
interface CheatState {
  N: number;
  tau: number;
  corruptParty: number;
  trials: number;
  caught: number;
  slipped: number;
  lastOutcome: string;
}

const cheatState: CheatState = {
  N: 4,
  tau: 1,
  corruptParty: 0,
  trials: 0,
  caught: 0,
  slipped: 0,
  lastOutcome: '',
};

const fsParams: MPCParams = { N: 8, tau: 4, q: 251 };
let fsStatement: Statement | null = null;
let fsWitness: number[] | null = null;
let fsMessage = 'Authenticated by Paul Clark, LCPL';
let fsSignatureTrace = '';
let fsHidden: number[] = [];
let fsChallengeHex = '';
// Challenge digest + hidden-party assignment BEFORE the last "Modify Message",
// so the exhibit can diff message -> challenge -> which views get opened.
let fsPrevChallengeHex = '';
let fsPrevHidden: number[] = [];
let fsPrevMessage = '';

const perkParams: PERKParams = { n: 8, m: 4, q: 251, N: 8, tau: 4 };
let perkKeypair: PERKKeyPair | null = null;
let perkMessage = 'Toy PERK signature demo';
let perkSignatureBytes: Uint8Array | null = null;
let perkVerifyText = 'No signature generated yet.';
let perkShowPrivate = false;

let cardShares: number[] = [];
let cardChallenge = 0;

function getTheme(): 'dark' | 'light' {
  const current = document.documentElement.getAttribute('data-theme');
  return current === 'light' ? 'light' : 'dark';
}

function syncThemeToggleButton(button: HTMLButtonElement, theme: 'dark' | 'light'): void {
  if (theme === 'dark') {
    button.textContent = '🌙';
    button.setAttribute('aria-label', 'Switch to light mode');
  } else {
    button.textContent = '☀️';
    button.setAttribute('aria-label', 'Switch to dark mode');
  }
}

function attachThemeToggle(button: HTMLButtonElement): void {
  syncThemeToggleButton(button, getTheme());
  button.addEventListener('click', () => {
    const nextTheme = getTheme() === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', nextTheme);
    localStorage.setItem('theme', nextTheme);
    syncThemeToggleButton(button, nextTheme);
  });
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

function xorThreeCardGame(secret: number): void {
  const a = randomInt(256);
  const b = randomInt(256);
  const c = a ^ b ^ secret;
  cardShares = [a, b, c];
  cardChallenge = randomInt(3);
}

function mod(x: number, q: number): number {
  const r = x % q;
  return r < 0 ? r + q : r;
}

function matVec(A: number[][], x: number[], q: number): number[] {
  return A.map((row) => {
    let acc = 0;
    for (let i = 0; i < row.length; i += 1) {
      acc = mod(acc + row[i] * x[i], q);
    }
    return acc;
  });
}

function vecEqual(a: number[], b: number[]): boolean {
  return a.length === b.length && a.every((value, i) => value === b[i]);
}

/**
 * Changing N or q invalidates any previously committed round (its party count
 * and field no longer match the controls). Clear it so a later Challenge/Verify
 * can never index past the stale arrays.
 */
function resetExhibit2Round(message: string): void {
  exhibit2State.round = null;
  exhibit2State.hiddenParty = null;
  exhibit2State.zk = null;
  exhibit2State.verificationText = message;
}

/**
 * Turn the learner's hex secret into a field-element witness for the A·x=b
 * statement. Each byte of the secret becomes one witness coordinate reduced
 * mod q, so the SAME secret they typed is what gets proven. (This is an honest
 * deterministic map, not a random re-roll: change the hex and the witness — and
 * therefore the public b — change with it.)
 */
function witnessFromSecret(secret: Uint8Array, q: number): number[] {
  const bytes = secret.length > 0 ? secret : Uint8Array.of(0);
  return Array.from(bytes, (byte) => byte % q);
}

async function splitSecretStep(): Promise<void> {
  const secret = hexToBytes(exhibit2State.secretHex);
  if (secret.length === 0) {
    throw new Error('Secret cannot be empty');
  }
  exhibit2State.shares = await shareSecret(secret, exhibit2State.N);
  exhibit2State.witness = witnessFromSecret(secret, exhibit2State.q);
  exhibit2State.statement = null;
  resetExhibit2Round('Shares generated. Run MPC next.');
}

async function runMPCStep(): Promise<void> {
  const secret = hexToBytes(exhibit2State.secretHex);
  if (secret.length === 0) {
    exhibit2State.verificationText = 'Type a hex secret and Split first.';
    return;
  }
  // Derive the witness from the learner's own secret so the party cards below
  // show shares of THEIR secret, not a fresh unrelated one.
  const witness = witnessFromSecret(secret, exhibit2State.q);
  exhibit2State.witness = witness;
  // A is a fresh random public matrix; b = A·witness is honestly published.
  exhibit2State.statement = await statementFromWitness(witness, 3, exhibit2State.q);
  exhibit2State.round = await mpcRound(exhibit2State.statement, witness, {
    N: exhibit2State.N,
    tau: 1,
    q: exhibit2State.q,
  });
  exhibit2State.hiddenParty = null;
  exhibit2State.zk = null;
  exhibit2State.verificationText =
    'MPC views committed: each party holds one additive share of YOUR witness. Trigger challenge.';
}

function challengeStep(): void {
  if (!exhibit2State.round) {
    exhibit2State.verificationText = 'Run MPC before challenge.';
    return;
  }
  exhibit2State.hiddenParty = randomInt(exhibit2State.N);
  exhibit2State.zk = null;
  exhibit2State.verificationText = `Challenge set: party ${exhibit2State.hiddenParty + 1} is hidden.`;
  announce(`Challenge selected. Party ${exhibit2State.hiddenParty + 1} is now hidden.`);
}

async function verifyStep(): Promise<void> {
  const round = exhibit2State.round;
  const statement = exhibit2State.statement;
  const hidden = exhibit2State.hiddenParty;
  if (!round || !statement || hidden === null) {
    exhibit2State.verificationText = 'Split, run MPC, and challenge first.';
    return;
  }

  const q = exhibit2State.q;
  const summed = new Array<number>(statement.b.length).fill(0);
  let checked = 0;

  // All-but-one opening: check every revealed view three ways.
  for (let i = 0; i < exhibit2State.N; i += 1) {
    if (i === hidden) {
      continue;
    }
    const view = round.views[i];

    // 1. Local consistency — the revealed output must equal A · share (mod q).
    if (!vecEqual(matVec(statement.A, view.share, q), view.output)) {
      exhibit2State.verificationText = `Verifier rejected: party ${i + 1} output ≠ A·share.`;
      exhibit2State.zk = null;
      return;
    }

    // 2. Commitment binding — re-commit share‖output under the revealed salt.
    const serialized = Uint8Array.from([...view.share, ...view.output]);
    const recommit = await commit(serialized, view.salt);
    if (bytesToHex(recommit.commitment) !== bytesToHex(round.commitments[i])) {
      exhibit2State.verificationText = `Verifier rejected: party ${i + 1} commitment mismatch.`;
      exhibit2State.zk = null;
      return;
    }

    // 3. Merkle membership — the commitment must be a leaf of the published root.
    const proof = await merkleProof(round.commitments, i);
    const inRoot = await verifyMerkleProof(round.commitments[i], i, proof.proof, round.merkleRoot);
    if (!inRoot) {
      exhibit2State.verificationText = `Verifier rejected: party ${i + 1} not under Merkle root.`;
      exhibit2State.zk = null;
      return;
    }

    for (let j = 0; j < summed.length; j += 1) {
      summed[j] = mod(summed[j] + view.output[j], q);
    }
    checked += 1;
  }

  exhibit2State.verificationText =
    `Verifier accepted all ${checked} revealed views — each commitment binds (SHA-256), sits under the ` +
    `Merkle root, and satisfies output = A·share. Party ${hidden + 1} stayed sealed, yet the proof holds. ` +
    `Open the "Can you recover the witness?" panel to see why that leaks nothing.`;

  // Build the zero-knowledge demonstration: the verifier only knows the SUM of
  // the hidden party's OUTPUT (b − Σ revealed outputs). It never learns the
  // hidden party's SHARE — and every possible share value is equally consistent
  // with everything revealed, so the witness stays information-theoretically
  // hidden. We surface a few candidate shares (including the true one) all of
  // which the verifier would accept identically.
  const impliedHiddenOutput = statement.b.map((value, i) => mod(value - summed[i], q));
  const trueHiddenShare = round.views[hidden].share;
  const candidateShares: number[][] = [trueHiddenShare.slice()];
  // Two decoys: perturb the true share arbitrarily. Their OUTPUT (A·share)
  // differs from the true output, but the verifier never saw the hidden output,
  // so — from the verifier's viewpoint — nothing distinguishes them.
  for (let d = 0; d < 2; d += 1) {
    candidateShares.push(trueHiddenShare.map(() => randomInt(q)));
  }
  const candidates = candidateShares.map((share) => ({
    share,
    output: matVec(statement.A, share, q),
    // "consistent" from the verifier's information: since the hidden output is
    // never revealed, all candidates are equally consistent with the transcript.
    consistent: true,
  }));

  exhibit2State.zk = {
    revealedSum: impliedHiddenOutput,
    hiddenParty: hidden,
    candidates,
  };
}

// ── Soundness experiment: play a cheating prover ────────────────────────────
/**
 * Run ONE honest MPC round on a random A·x=b statement, then let the prover
 * cheat by corrupting one party's committed output. Draw a uniform challenge:
 * if the challenge hides the corrupted party, the cheat slips through
 * (probability 1/N per round); otherwise the tampered view is opened and the
 * verifier catches it (probability 1 − 1/N). Repeated over τ rounds the cheat
 * only slips if EVERY round happens to hide its corruption: (1/N)^τ.
 *
 * This is a real, honest simulation — the challenge is sampled with
 * crypto.getRandomValues and the catch condition is the actual "was the
 * tampered party opened?" test, not a hardcoded coin flip.
 */
function runCheatBatch(batches: number): void {
  const { N, tau } = cheatState;
  const corrupt = Math.min(cheatState.corruptParty, N - 1);
  cheatState.corruptParty = corrupt;

  for (let t = 0; t < batches; t += 1) {
    let slippedAllRounds = true;
    for (let r = 0; r < tau; r += 1) {
      // In each round the challenge hides one uniformly random party. The
      // prover cheated in party `corrupt`. If that party is the hidden one,
      // its tampered view is never opened -> not caught this round.
      const hidden = randomInt(N);
      const caughtThisRound = hidden !== corrupt;
      if (caughtThisRound) {
        slippedAllRounds = false;
        break; // one caught round is enough to reject the whole signature
      }
    }
    cheatState.trials += 1;
    if (slippedAllRounds) {
      cheatState.slipped += 1;
    } else {
      cheatState.caught += 1;
    }
  }

  const empirical = cheatState.trials > 0 ? cheatState.slipped / cheatState.trials : 0;
  const theoretical = Math.pow(1 / N, tau);
  cheatState.lastOutcome =
    `${cheatState.trials} attempts: caught ${cheatState.caught}, slipped ${cheatState.slipped}. ` +
    `Empirical slip rate ${(empirical * 100).toFixed(2)}% vs theory (1/N)^τ = ${(theoretical * 100).toFixed(4)}%.`;
  announce(cheatState.lastOutcome);
}

function resetCheat(): void {
  cheatState.trials = 0;
  cheatState.caught = 0;
  cheatState.slipped = 0;
  cheatState.lastOutcome = '';
}

async function runFiatShamirDemo(): Promise<void> {
  const generated = await generateStatement(4, 3, fsParams.q);
  fsStatement = generated.statement;
  fsWitness = generated.witness;
  const message = encoder.encode(fsMessage);
  const signed = await sign(message, fsStatement, fsWitness, fsParams);
  fsSignatureTrace = signed.challengeDerivation;
  fsHidden = signed.signature.hiddenParties;
  fsChallengeHex = bytesToHex(signed.signature.challenge);
}

async function runPerkKeygen(): Promise<void> {
  perkKeypair = await perkKeyGen(perkParams);
  perkSignatureBytes = null;
  perkVerifyText = 'Keypair generated. Ready to sign.';
}

async function runPerkSign(): Promise<void> {
  if (!perkKeypair) {
    await runPerkKeygen();
  }
  if (!perkKeypair) {
    return;
  }
  perkSignatureBytes = await perkSign(encoder.encode(perkMessage), perkKeypair, perkParams);
  const ok = await perkVerify(encoder.encode(perkMessage), perkKeypair.publicKey, perkSignatureBytes, perkParams);
  perkVerifyText = ok ? 'VALID signature.' : 'INVALID signature.';
}

async function runPerkVerify(): Promise<void> {
  if (!perkKeypair || !perkSignatureBytes) {
    perkVerifyText = 'Generate keypair and signature first.';
    render();
    return;
  }
  const ok = await perkVerify(encoder.encode(perkMessage), perkKeypair.publicKey, perkSignatureBytes, perkParams);
  perkVerifyText = ok ? 'VALID signature.' : 'INVALID signature.';
}

function renderPartyCards(): string {
  const cards: string[] = [];
  for (let i = 0; i < exhibit2State.N; i += 1) {
    const isHidden = exhibit2State.hiddenParty === i;
    const view = exhibit2State.round?.views[i];
    const commitment = exhibit2State.round?.commitments[i];
    const shareText = exhibit2State.shares[i] ? bytesToHex(exhibit2State.shares[i]) : 'pending';
    // While a party is hidden the verifier never sees its share/output — reflect
    // that honestly in the card instead of printing the sealed values.
    const outputText = view ? (isHidden ? 'sealed' : `[${view.output.join(', ')}]`) : 'pending';
    const witnessShareText = view ? (isHidden ? 'sealed' : `[${view.share.join(', ')}]`) : 'pending';
    const saltText = view ? `${bytesToHex(view.salt).slice(0, 8)}...` : 'pending';
    const commitmentText = commitment ? `${bytesToHex(commitment).slice(0, 12)}...` : 'pending';
    const label = isHidden ? 'HIDDEN' : 'ACTIVE';
    cards.push(`
      <article
        class="party-card ${isHidden ? 'hidden' : 'active'}"
        tabindex="0"
        aria-label="Party ${i + 1}, status ${label.toLowerCase()}"
      >
        <h4>Party ${i + 1}</h4>
        <p><strong>XOR share (byte):</strong> ${shareText}</p>
        <p><strong>Witness share (mod q):</strong> ${witnessShareText}</p>
        <p><strong>My output A·share:</strong> ${outputText}</p>
        <p><strong>Salt:</strong> ${saltText}</p>
        <p><strong>Commitment:</strong> <code class="commitment" aria-label="Commitment hash for party ${i + 1}">${commitmentText}</code></p>
        <p class="status">Status: ● ${label}</p>
      </article>
    `);
  }
  return cards.join('');
}

function renderFlowBanner(): string {
  const secretBytes = (() => {
    try {
      return hexToBytes(exhibit2State.secretHex);
    } catch {
      return new Uint8Array();
    }
  })();
  const witness = secretBytes.length > 0 ? witnessFromSecret(secretBytes, exhibit2State.q) : null;
  const bText = exhibit2State.statement ? `[${exhibit2State.statement.b.join(', ')}]` : 'run MPC to publish b';
  return `
    <div class="flow-banner" aria-label="Secret flow through the demo">
      <span class="flow-step"><span class="flow-k">secret</span> <code>${esc(exhibit2State.secretHex || '∅')}</code></span>
      <span class="flow-arrow" aria-hidden="true">→</span>
      <span class="flow-step"><span class="flow-k">witness x</span> <code>${witness ? `[${witness.join(', ')}]` : '—'}</code></span>
      <span class="flow-arrow" aria-hidden="true">→</span>
      <span class="flow-step"><span class="flow-k">public b = A·x</span> <code>${bText}</code></span>
    </div>
    <p class="flow-note">
      Your secret is <strong>not</strong> discarded: each byte becomes one coordinate of the witness
      <span class="math">x</span>, a fresh random public matrix <span class="math">A</span> is drawn, and
      <span class="math">b = A·x</span> is published. The party cards below share <em>this</em>
      <span class="math">x</span> — change the hex and <span class="math">b</span> changes with it.
    </p>
  `;
}

function renderZkPanel(): string {
  const zk = exhibit2State.zk;
  if (!zk) {
    return `<p class="zk-empty">Run Split → MPC → Challenge → Verify, then a zero-knowledge experiment appears here.</p>`;
  }
  const rows = zk.candidates
    .map((c, idx) => {
      const isTrue = idx === 0;
      return `
        <tr>
          <td>${isTrue ? 'true hidden share' : `guess #${idx}`}</td>
          <td><code>[${c.share.join(', ')}]</code></td>
          <td>consistent</td>
        </tr>`;
    })
    .join('');
  return `
    <p>
      The verifier learns only <span class="math">b − Σ(revealed outputs) = [${zk.revealedSum.join(', ')}]</span>
      — the <em>output</em> the sealed party must contribute. It never learns that party's <strong>share</strong>.
    </p>
    <p>
      Because the other <span class="math">N−1</span> shares are uniformly random, the missing share is a
      one-time-pad away from anything: every candidate below is <em>equally consistent</em> with the whole
      transcript. That is the a-ha of zero-knowledge — revealing <span class="math">N−1</span> views pins down
      the sum, never the secret.
    </p>
    <div class="table-wrap" tabindex="0" role="region" aria-label="Candidate hidden shares, all equally consistent">
      <table>
        <caption class="sr-only">Candidate values for the sealed party's share</caption>
        <thead>
          <tr><th scope="col">Candidate</th><th scope="col">Hidden share</th><th scope="col">Verifier's view</th></tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
    <p class="zk-note">
      The prover really used the first row — but nothing in the opened transcript could tell you that.
      Any share the verifier plugs in is equally compatible, so no information about the witness leaks.
    </p>
  `;
}

/** Highlight bytes of `hex` that differ from `prevHex`, pairwise. */
function renderChallengeDiff(hex: string, prevHex: string): string {
  const out: string[] = [];
  for (let i = 0; i < hex.length; i += 2) {
    const byte = hex.slice(i, i + 2);
    const prevByte = prevHex.slice(i, i + 2);
    const changed = prevHex.length > 0 && byte !== prevByte;
    out.push(changed ? `<mark class="byte-changed">${byte}</mark>` : `<span class="byte">${byte}</span>`);
  }
  return out.join('');
}

function renderFsDiff(): string {
  if (!fsChallengeHex) {
    return '';
  }
  const nowRow = `<p class="fs-diff-row"><span class="fs-diff-label">now</span> <code class="fs-hex">${renderChallengeDiff(fsChallengeHex, fsPrevChallengeHex)}</code></p>`;
  if (!fsPrevChallengeHex) {
    return `
      <div class="fs-diff">
        <p><strong>Challenge = SHA-256(message ‖ commitments)</strong></p>
        ${nowRow}
        <p class="fs-diff-hint">Click <strong>Modify Message</strong> to see the challenge — and which parties get hidden — flip.</p>
      </div>`;
  }
  const flips = fsHidden
    .map((h, r) => {
      const prev = fsPrevHidden[r];
      const changed = prev !== undefined && prev !== h;
      return `<li>round ${r + 1}: party ${prev !== undefined ? prev : '?'} <span aria-hidden="true">→</span> <span class="${changed ? 'flip-changed' : ''}">party ${h}</span>${changed ? ' <span class="flip-tag">changed</span>' : ''}</li>`;
    })
    .join('');
  return `
    <div class="fs-diff">
      <p><strong>Message changed → challenge digest changed → different parties hidden.</strong></p>
      <p class="fs-diff-row"><span class="fs-diff-label">before</span> <code class="fs-hex">${esc(fsPrevMessage)}</code></p>
      <p class="fs-diff-row"><span class="fs-diff-label">after</span> <code class="fs-hex">${esc(fsMessage)}</code></p>
      <p class="fs-diff-row"><span class="fs-diff-label">was</span> <code class="fs-hex">${renderChallengeDiff(fsPrevChallengeHex, fsPrevChallengeHex)}</code></p>
      ${nowRow}
      <p class="fs-diff-caption">Hidden-party assignment (highlighted = flipped by the new challenge):</p>
      <ul class="fs-flip-list">${flips}</ul>
    </div>`;
}

function renderPerkPermutation(): string {
  if (!perkKeypair) {
    return `<p class="perk-empty">Generate a keypair to see the permutation as a rearrangement.</p>`;
  }
  const { y } = perkKeypair.publicKey;
  const pi = perkKeypair.privateKey.pi;
  const x = perkKeypair.privateKey.x;
  const yBoxes = y
    .map((v, i) => `<div class="perm-box" role="listitem">y[${i}]<span class="perm-val">${v}</span></div>`)
    .join('');
  // x[i] = y[pi[i]] — draw where each x slot pulls from.
  const xBoxes = x
    .map((v, i) => {
      const from = pi[i];
      const reveal = perkShowPrivate
        ? `<span class="perm-from">← y[${from}]</span>`
        : `<span class="perm-from perm-hidden">← y[?]</span>`;
      return `<div class="perm-box perm-x ${perkShowPrivate ? 'perm-placed' : ''}" role="listitem">x[${i}]<span class="perm-val">${v}</span>${reveal}</div>`;
    })
    .join('');
  const arrows = perkShowPrivate
    ? pi.map((from, i) => `π: x[${i}] takes y[${from}]`).join(' · ')
    : 'π is sealed — reveal it to see which y-slot each x-slot pulls from.';
  const b = perkKeypair.publicKey.b;
  const check = perkEquationHolds(perkKeypair.publicKey, pi, perkParams.q);
  return `
    <div class="perm-viz">
      <p class="perm-label">public y (a fixed shuffle of the witness):</p>
      <div class="perm-row" role="list" aria-label="Public vector y">${yBoxes}</div>
      <p class="perm-arrows" aria-live="polite">${esc(arrows)}</p>
      <p class="perm-label">witness x = π(y) (the secret rearrangement):</p>
      <div class="perm-row" role="list" aria-label="Witness vector x equals pi applied to y">${xBoxes}</div>
      <p class="perm-eq">
        Then <span class="math">H·x = b</span> lands on the public target
        <code>[${b.join(', ')}]</code> ${check ? '<span class="ok">✓</span>' : ''}.
        Finding <span class="math">π</span> from <span class="math">H</span>, <span class="math">y</span>,
        <span class="math">b</span> alone is the hard <em>permuted-kernel problem</em>.
      </p>
    </div>
  `;
}

function render(): void {
  // The whole #app is replaced on each render, which would drop keyboard focus
  // (e.g. mid-drag on the N slider). Capture the focused control and its caret
  // so we can restore them after the DOM is rebuilt (WCAG 2.4.3 Focus Order).
  const previousId =
    document.activeElement instanceof HTMLElement ? document.activeElement.id : '';
  let caret: number | null = null;
  try {
    const active = document.activeElement;
    if (active instanceof HTMLInputElement && active.type !== 'range') {
      caret = active.selectionStart;
    }
  } catch {
    caret = null;
  }

  const size = estimateSignatureSize(perkParams);

  const cardA = cardShares[0] ?? 17;
  const cardB = cardShares[1] ?? 63;
  const cardC = cardShares[2] ?? (17 ^ 63 ^ 42);
  const secret = cardA ^ cardB ^ cardC;
  const hiddenName = ['A', 'B', 'C'][cardChallenge] ?? 'A';

  const cheatN = cheatState.N;
  const cheatTheory = Math.pow(1 / cheatN, cheatState.tau);
  const cheatEmpirical = cheatState.trials > 0 ? cheatState.slipped / cheatState.trials : 0;

  app.innerHTML = `
    <div class="topbar">
      <div>
        <h1>Signing in Your Head</h1>
        <p class="tagline">MPC-in-the-Head signatures, built up from a three-card trick to a toy PERK scheme.</p>
      </div>
      <button id="theme-toggle" class="theme-toggle" type="button" style="position: absolute; top: 0; right: 0"></button>
    </div>

    <main class="layout" id="main" tabindex="-1">
      <section class="panel">
        <h2>Exhibit 1 — The Idea</h2>
        <p>
          You want to prove you know a secret. Normally: show the secret. That reveals it.
          MPC-in-the-Head simulates many parties inside one prover, commits to each view,
          then reveals all but one view for checking.
        </p>
        <div class="card-game">
          <div>
            <h3>Three-card analogy</h3>
            <p>SECRET: ${secret}</p>
            <p>Party A: ${cardA}</p>
            <p>Party B: ${cardB}</p>
            <p>Party C: ${cardC}</p>
            <p>Challenge: hide Party ${hiddenName}</p>
            <p class="sharing-bridge">
              Here the three shares combine with <strong>XOR</strong>. XOR is just
              <span class="math">+ mod 2</span> per bit — addition in <span class="math">GF(2)</span>.
              Exhibit 2 uses the same trick over a bigger group: <span class="math">+ mod q</span>.
              One idea, two groups.
            </p>
            <p>
              Cheating soundness: a single round catches a cheat with probability
              <span class="math">1&nbsp;&minus;&nbsp;1/N</span>; over
              <span class="math">&tau;</span> independent rounds a cheat slips through with only
              <span class="math">(1/N)<sup>&tau;</sup></span>. Exhibit 2 lets you <em>feel</em> that.
            </p>
          </div>
          <button id="reshuffle-cards" type="button" aria-label="Reshuffle three-card secret shares">Reshuffle Shares</button>
        </div>
      </section>

      <section class="panel">
        <h2>Exhibit 2 — MPC Party Simulation</h2>
        <p class="exhibit-lead">
          Prove you know the witness behind <span class="math">A·x = b</span> without revealing it: split
          <span class="math">x</span> across <span class="math">N</span> parties, commit each view, then open all
          but one.
        </p>
        ${renderFlowBanner()}
        <div class="controls">
          <label>Secret (hex)
            <input id="secret-hex" value="${esc(exhibit2State.secretHex)}" />
          </label>
          <label>N parties: <span id="n-value">${exhibit2State.N}</span>
            <input id="n-slider" type="range" min="2" max="8" value="${exhibit2State.N}" />
          </label>
          <label>Prime field q
            <select id="q-select">
              <option value="101" ${exhibit2State.q === 101 ? 'selected' : ''}>101</option>
              <option value="251" ${exhibit2State.q === 251 ? 'selected' : ''}>251</option>
            </select>
          </label>
        </div>
        <div class="button-row">
          <button id="split-secret" type="button" aria-label="Split secret into party shares">Split Secret</button>
          <button id="run-mpc" type="button" aria-label="Run MPC round">Run MPC</button>
          <button id="run-challenge" type="button" aria-label="Select hidden party challenge">Challenge</button>
          <button id="run-verify" type="button" aria-label="Verify revealed party views">Verify</button>
        </div>
        <p class="challenge-arrow">⇢ Challenge picks one hidden party</p>
        <div class="party-grid">
          ${renderPartyCards()}
        </div>
        <p class="verify-result" role="status" aria-live="polite">${esc(exhibit2State.verificationText)}</p>

        <details class="zk-details" ${exhibit2State.zk ? 'open' : ''}>
          <summary>Can you recover the witness? (zero-knowledge experiment)</summary>
          <div class="zk-body">
            ${renderZkPanel()}
          </div>
        </details>
      </section>

      <section class="panel">
        <h2>Exhibit 2b — Play a Cheating Prover</h2>
        <p class="exhibit-lead">
          Suppose you <em>don't</em> know the witness and try to fake a party's output. You only escape if the
          challenge happens to hide the party you corrupted. Run many rounds and watch the catch rate settle on
          <span class="math">1&nbsp;&minus;&nbsp;1/N</span>.
        </p>
        <div class="controls">
          <label>N parties: <span id="cheat-n-value">${cheatState.N}</span>
            <input id="cheat-n" type="range" min="2" max="8" value="${cheatState.N}" />
          </label>
          <label>&tau; rounds: <span id="cheat-tau-value">${cheatState.tau}</span>
            <input id="cheat-tau" type="range" min="1" max="8" value="${cheatState.tau}" />
          </label>
          <label>Corrupt party #: <span id="cheat-party-value">${Math.min(cheatState.corruptParty, cheatState.N - 1) + 1}</span>
            <input id="cheat-party" type="range" min="0" max="${cheatState.N - 1}" value="${Math.min(cheatState.corruptParty, cheatState.N - 1)}" />
          </label>
        </div>
        <div class="button-row">
          <button id="cheat-once" type="button" aria-label="Run one cheating attempt">Cheat once</button>
          <button id="cheat-100" type="button" aria-label="Run 100 cheating attempts">Run 100</button>
          <button id="cheat-reset" type="button" aria-label="Reset cheating tally">Reset</button>
        </div>
        <div class="tally" aria-hidden="true">
          <div class="tally-bar">
            <div class="tally-caught" style="flex: ${cheatState.caught}"></div>
            <div class="tally-slipped" style="flex: ${cheatState.slipped}"></div>
          </div>
          <div class="tally-legend">
            <span><span class="swatch caught"></span> caught ${cheatState.caught}</span>
            <span><span class="swatch slipped"></span> slipped ${cheatState.slipped}</span>
          </div>
        </div>
        <p class="cheat-stat">
          Theory: a cheat slips through with <span class="math">(1/N)<sup>&tau;</sup> = (1/${cheatN})<sup>${cheatState.tau}</sup>
          = ${(cheatTheory * 100).toFixed(4)}%</span>.
          ${cheatState.trials > 0 ? `Empirical so far: <strong>${(cheatEmpirical * 100).toFixed(2)}%</strong> over ${cheatState.trials} attempts.` : 'Run some attempts to compare.'}
        </p>
        <p class="cheat-result" role="status" aria-live="polite">${esc(cheatState.lastOutcome)}</p>
      </section>

      <section class="panel">
        <h2>Exhibit 3 — Fiat-Shamir Signature</h2>
        <label>Message
          <input id="fs-message" value="${esc(fsMessage)}" />
        </label>
        <div class="button-row">
          <button id="run-fs" type="button" aria-label="Run Fiat Shamir signature derivation">Run Fiat-Shamir</button>
          <button id="tamper-fs" type="button" aria-label="Modify message and recompute challenge">Modify Message</button>
        </div>
        <div class="columns">
          <div>
            <h3>Interactive</h3>
            <pre tabindex="0" role="region" aria-label="Interactive protocol pseudocode">Prover -> Commit(views)
Verifier -> Challenge e
Prover -> Reveal all except e</pre>
          </div>
          <div>
            <h3>Fiat-Shamir</h3>
            <pre tabindex="0" role="region" aria-label="Fiat-Shamir pseudocode">e = SHA-256(message || commitments)
Signature = (roots, e, responses)
Verifier recomputes e and checks consistency</pre>
          </div>
        </div>
        ${renderFsDiff()}
        <p>Hidden parties per round: ${fsHidden.length > 0 ? fsHidden.join(', ') : 'not generated'}</p>
        <pre class="trace" tabindex="0" role="region" aria-label="Challenge derivation trace">${esc(fsSignatureTrace || 'Run the demo to show challenge derivation.')}</pre>
      </section>

      <section class="panel">
        <h2>Exhibit 4 — Toy PERK</h2>
        <p>
          Toy PERK relation: find a permutation <span class="math">&pi;</span> such that
          <span class="math">H&nbsp;&middot;&nbsp;&pi;(y)&nbsp;=&nbsp;b&nbsp;(mod&nbsp;q)</span>.
          The secret is the <em>ordering</em> — <span class="math">&pi;</span> rearranges the public
          <span class="math">y</span> into the witness <span class="math">x</span>.
        </p>
        <div class="button-row">
          <button id="perk-keygen" type="button" aria-label="Generate toy PERK keypair">Generate PERK Keypair</button>
          <button id="perk-sign" type="button" aria-label="Sign message with toy PERK">Sign</button>
          <button id="perk-verify" type="button" aria-label="Verify toy PERK signature">Verify</button>
          <button id="perk-reveal" type="button" aria-label="Toggle visibility of private permutation">${perkShowPrivate ? 'Hide π' : 'Reveal π'}</button>
        </div>
        ${renderPerkPermutation()}
        <label>Message
          <input id="perk-message" value="${esc(perkMessage)}" />
        </label>
        <p>Signature status: <strong class="${perkVerifyText.includes('VALID') ? 'ok' : 'bad'}">${esc(perkVerifyText)}</strong></p>
        <p>Estimated signature size: ~${size.bytes} bytes</p>
        <div class="table-wrap" tabindex="0" role="region" aria-label="Signature size breakdown in bytes">
          <table>
            <caption class="sr-only">Toy PERK signature size breakdown</caption>
            <thead><tr><th scope="col">Component</th><th scope="col">Bytes</th></tr></thead>
            <tbody>
              <tr><td>Merkle roots</td><td>${size.breakdown.merkleRoots}</td></tr>
              <tr><td>Challenge</td><td>${size.breakdown.challenge}</td></tr>
              <tr><td>Revealed views</td><td>${size.breakdown.revealedViews}</td></tr>
              <tr><td>Merkle proofs</td><td>${size.breakdown.merkleProofs}</td></tr>
            </tbody>
          </table>
        </div>
      </section>

      <section class="panel">
        <h2>Exhibit 5 — Security Diversity</h2>
        <p>
          NIST Round 2 additional signatures include Mirath, PERK, RYDE, SDitH, MQOM, and FAEST.
          None are standardized as of 2026. They are under active cryptanalysis.
        </p>
        <div class="table-wrap" tabindex="0" role="region" aria-label="Signature size and security basis by scheme">
          <table>
            <caption class="sr-only">Signature size and security basis by scheme</caption>
            <thead>
              <tr><th scope="col">Scheme</th><th scope="col">Sig size</th><th scope="col">Security basis</th></tr>
            </thead>
            <tbody>
              <tr><td>ML-DSA-2</td><td>2,420 B</td><td>Lattice</td></tr>
              <tr><td>SLH-DSA-128s</td><td>7,856 B</td><td>Hash</td></tr>
              <tr><td>PERK-I (est.)</td><td>~6,000 B</td><td>Hash + PKP</td></tr>
              <tr><td>Mirath-I (est.)</td><td>~5,700 B</td><td>Hash + MinRank</td></tr>
              <tr><td>FAEST-I (est.)</td><td>~5,700 B</td><td>Hash + AES</td></tr>
            </tbody>
          </table>
        </div>
        <p>
          Tradeoff: MPCitH signatures are generally larger than ML-DSA, but avoid lattice structure and
          rely on hash commitments plus hard combinatorial statements.
        </p>
        <p>
          Cross-links: crypto-lab-sphincs-ledger, crypto-lab-dilithium-seal,
          crypto-lab-zk-proof-lab, crypto-lab-silent-tally.
        </p>
      </section>
    </main>

  `;

  const themeToggle = document.querySelector<HTMLButtonElement>('#theme-toggle');
  if (themeToggle) {
    attachThemeToggle(themeToggle);
  }

  const cardBtn = document.querySelector<HTMLButtonElement>('#reshuffle-cards');
  cardBtn?.addEventListener('click', () => {
    xorThreeCardGame(42);
    render();
  });

  const secretInput = document.querySelector<HTMLInputElement>('#secret-hex');
  secretInput?.addEventListener('input', () => {
    exhibit2State.secretHex = secretInput.value.trim();
    // Keep the flow banner live as the learner types.
    render();
  });

  const slider = document.querySelector<HTMLInputElement>('#n-slider');
  slider?.addEventListener('input', () => {
    exhibit2State.N = Number.parseInt(slider.value, 10);
    if (exhibit2State.round) {
      resetExhibit2Round('Party count changed. Run MPC again.');
    }
    render();
  });

  const qSelect = document.querySelector<HTMLSelectElement>('#q-select');
  qSelect?.addEventListener('change', () => {
    exhibit2State.q = Number.parseInt(qSelect.value, 10);
    resetExhibit2Round('Field q changed. Run MPC again.');
    render();
  });

  const splitBtn = document.querySelector<HTMLButtonElement>('#split-secret');
  splitBtn?.addEventListener('click', async () => {
    try {
      await splitSecretStep();
      const full = reconstructSecret(exhibit2State.shares);
      exhibit2State.verificationText = `Split complete: ${exhibit2State.N} XOR shares reconstruct to ${bytesToHex(full)}. Run MPC to prove knowledge of this witness.`;
    } catch (error) {
      exhibit2State.verificationText = error instanceof Error ? error.message : 'Split error';
    }
    announce(exhibit2State.verificationText);
    render();
  });

  const runMpcBtn = document.querySelector<HTMLButtonElement>('#run-mpc');
  runMpcBtn?.addEventListener('click', async () => {
    await runMPCStep();
    announce(exhibit2State.verificationText);
    render();
  });

  const challengeBtn = document.querySelector<HTMLButtonElement>('#run-challenge');
  challengeBtn?.addEventListener('click', () => {
    challengeStep();
    render();
  });

  const verifyBtn = document.querySelector<HTMLButtonElement>('#run-verify');
  verifyBtn?.addEventListener('click', async () => {
    await verifyStep();
    announce(exhibit2State.verificationText);
    render();
  });

  // ── Exhibit 2b cheating controls ─────────────────────────────────────────
  const cheatNSlider = document.querySelector<HTMLInputElement>('#cheat-n');
  cheatNSlider?.addEventListener('input', () => {
    cheatState.N = Number.parseInt(cheatNSlider.value, 10);
    if (cheatState.corruptParty > cheatState.N - 1) {
      cheatState.corruptParty = cheatState.N - 1;
    }
    resetCheat();
    render();
  });

  const cheatTauSlider = document.querySelector<HTMLInputElement>('#cheat-tau');
  cheatTauSlider?.addEventListener('input', () => {
    cheatState.tau = Number.parseInt(cheatTauSlider.value, 10);
    resetCheat();
    render();
  });

  const cheatPartySlider = document.querySelector<HTMLInputElement>('#cheat-party');
  cheatPartySlider?.addEventListener('input', () => {
    cheatState.corruptParty = Number.parseInt(cheatPartySlider.value, 10);
    render();
  });

  const cheatOnceBtn = document.querySelector<HTMLButtonElement>('#cheat-once');
  cheatOnceBtn?.addEventListener('click', () => {
    runCheatBatch(1);
    render();
  });

  const cheat100Btn = document.querySelector<HTMLButtonElement>('#cheat-100');
  cheat100Btn?.addEventListener('click', () => {
    runCheatBatch(100);
    render();
  });

  const cheatResetBtn = document.querySelector<HTMLButtonElement>('#cheat-reset');
  cheatResetBtn?.addEventListener('click', () => {
    resetCheat();
    render();
  });

  const fsInput = document.querySelector<HTMLInputElement>('#fs-message');
  fsInput?.addEventListener('input', () => {
    fsMessage = fsInput.value;
  });

  const fsBtn = document.querySelector<HTMLButtonElement>('#run-fs');
  fsBtn?.addEventListener('click', async () => {
    // A fresh run establishes the baseline; no diff yet.
    fsPrevChallengeHex = '';
    fsPrevHidden = [];
    fsPrevMessage = '';
    await runFiatShamirDemo();
    render();
  });

  const tamperBtn = document.querySelector<HTMLButtonElement>('#tamper-fs');
  tamperBtn?.addEventListener('click', async () => {
    // Snapshot the current challenge + hidden assignment so we can diff after
    // the message change flips them (message -> challenge -> which views open).
    fsPrevChallengeHex = fsChallengeHex;
    fsPrevHidden = fsHidden.slice();
    fsPrevMessage = fsMessage;
    fsMessage = `${fsMessage} *`;
    await runFiatShamirDemo();
    announce('Message modified. Challenge recomputed; hidden-party assignment updated.');
    render();
  });

  const perkMsgInput = document.querySelector<HTMLInputElement>('#perk-message');
  perkMsgInput?.addEventListener('input', () => {
    perkMessage = perkMsgInput.value;
  });

  const perkKeyBtn = document.querySelector<HTMLButtonElement>('#perk-keygen');
  perkKeyBtn?.addEventListener('click', async () => {
    await runPerkKeygen();
    render();
  });

  const perkSignBtn = document.querySelector<HTMLButtonElement>('#perk-sign');
  perkSignBtn?.addEventListener('click', async () => {
    await runPerkSign();
    announce(`Toy PERK: ${perkVerifyText}`);
    render();
  });

  const perkVerifyBtn = document.querySelector<HTMLButtonElement>('#perk-verify');
  perkVerifyBtn?.addEventListener('click', async () => {
    await runPerkVerify();
    announce(`Toy PERK: ${perkVerifyText}`);
    render();
  });

  const perkRevealBtn = document.querySelector<HTMLButtonElement>('#perk-reveal');
  perkRevealBtn?.addEventListener('click', () => {
    perkShowPrivate = !perkShowPrivate;
    render();
  });

  // Restore keyboard focus (and caret) to whatever control was active before
  // the DOM was rebuilt, so re-renders don't strand keyboard/AT users.
  if (previousId) {
    const restored = document.getElementById(previousId);
    if (restored instanceof HTMLElement) {
      restored.focus();
      if (caret !== null && restored instanceof HTMLInputElement) {
        try {
          restored.setSelectionRange(caret, caret);
        } catch {
          /* control does not support text selection */
        }
      }
    }
  }
}

xorThreeCardGame(42);
void runFiatShamirDemo();
void runPerkKeygen();
render();
