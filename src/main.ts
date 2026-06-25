import './style.css';
import {
  bytesToHex,
  commit,
  hexToBytes,
  merkleProof,
  partialReconstruct,
  reconstructSecret,
  shareSecret,
  verifyMerkleProof,
} from './sharing';
import { generateStatement, mpcRound, sign, type MPCParams, type Statement } from './mpcith';
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
};

const fsParams: MPCParams = { N: 8, tau: 4, q: 251 };
let fsStatement: Statement | null = null;
let fsWitness: number[] | null = null;
let fsMessage = 'Authenticated by Paul Clark, LCPL';
let fsSignatureTrace = '';
let fsHidden: number[] = [];

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
  exhibit2State.verificationText = message;
}

async function splitSecretStep(): Promise<void> {
  const secret = hexToBytes(exhibit2State.secretHex);
  if (secret.length === 0) {
    throw new Error('Secret cannot be empty');
  }
  exhibit2State.shares = await shareSecret(secret, exhibit2State.N);
  exhibit2State.round = null;
  exhibit2State.hiddenParty = null;
  exhibit2State.verificationText = 'Shares generated. Run MPC next.';
}

async function runMPCStep(): Promise<void> {
  const statementResult = await generateStatement(4, 3, exhibit2State.q);
  exhibit2State.statement = statementResult.statement;
  exhibit2State.witness = statementResult.witness;
  exhibit2State.round = await mpcRound(statementResult.statement, statementResult.witness, {
    N: exhibit2State.N,
    tau: 1,
    q: exhibit2State.q,
  });
  exhibit2State.hiddenParty = null;
  exhibit2State.verificationText = 'MPC views committed. Trigger challenge.';
}

function challengeStep(): void {
  if (!exhibit2State.round) {
    exhibit2State.verificationText = 'Run MPC before challenge.';
    return;
  }
  exhibit2State.hiddenParty = randomInt(exhibit2State.N);
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

  // All-but-one opening: the verifier checks every revealed view three ways,
  // then derives the one hidden party's output from the public target b.
  for (let i = 0; i < exhibit2State.N; i += 1) {
    if (i === hidden) {
      continue;
    }
    const view = round.views[i];

    // 1. Local consistency — the revealed output must equal A · share (mod q).
    if (!vecEqual(matVec(statement.A, view.share, q), view.output)) {
      exhibit2State.verificationText = `Verifier rejected: party ${i + 1} output ≠ A·share.`;
      return;
    }

    // 2. Commitment binding — re-commit share‖output under the revealed salt.
    const serialized = Uint8Array.from([...view.share, ...view.output]);
    const recommit = await commit(serialized, view.salt);
    if (bytesToHex(recommit.commitment) !== bytesToHex(round.commitments[i])) {
      exhibit2State.verificationText = `Verifier rejected: party ${i + 1} commitment mismatch.`;
      return;
    }

    // 3. Merkle membership — the commitment must be a leaf of the published root.
    const proof = await merkleProof(round.commitments, i);
    const inRoot = await verifyMerkleProof(round.commitments[i], i, proof.proof, round.merkleRoot);
    if (!inRoot) {
      exhibit2State.verificationText = `Verifier rejected: party ${i + 1} not under Merkle root.`;
      return;
    }

    for (let j = 0; j < summed.length; j += 1) {
      summed[j] = mod(summed[j] + view.output[j], q);
    }
    checked += 1;
  }

  const implied = statement.b.map((value, i) => mod(value - summed[i], q));
  exhibit2State.verificationText =
    `Verifier accepted all ${checked} revealed views — each commitment binds (SHA-256), sits under the Merkle root, ` +
    `and satisfies output = A·share. Implied hidden party ${hidden + 1} output (b − Σ revealed): [${implied.join(', ')}].`;
}

async function runFiatShamirDemo(): Promise<void> {
  const generated = await generateStatement(4, 3, fsParams.q);
  fsStatement = generated.statement;
  fsWitness = generated.witness;
  const message = encoder.encode(fsMessage);
  const signed = await sign(message, fsStatement, fsWitness, fsParams);
  fsSignatureTrace = signed.challengeDerivation;
  fsHidden = signed.signature.hiddenParties;
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
    const outputText = view ? `[${view.output.join(', ')}]` : 'pending';
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
        <p><strong>Share:</strong> ${shareText}</p>
        <p><strong>My output:</strong> ${outputText}</p>
        <p><strong>Salt:</strong> ${saltText}</p>
        <p><strong>Commitment:</strong> <code class="commitment" aria-label="Commitment hash for party ${i + 1}">${commitmentText}</code></p>
        <p class="status">Status: ● ${label}</p>
      </article>
    `);
  }
  return cards.join('');
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
  const perkEquation = perkKeypair
    ? perkEquationHolds(perkKeypair.publicKey, perkKeypair.privateKey.pi, perkParams.q)
    : false;

  const cardA = cardShares[0] ?? 17;
  const cardB = cardShares[1] ?? 63;
  const cardC = cardShares[2] ?? (17 ^ 63 ^ 42);
  const secret = cardA ^ cardB ^ cardC;
  const hiddenName = ['A', 'B', 'C'][cardChallenge] ?? 'A';

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
            <p>
              Cheating soundness: a single round catches a cheat with probability
              <span class="math">1&nbsp;&minus;&nbsp;1/N</span>; over
              <span class="math">&tau;</span> independent rounds a cheat slips through with only
              <span class="math">(1/N)<sup>&tau;</sup></span>.
            </p>
          </div>
          <button id="reshuffle-cards" type="button" aria-label="Reshuffle three-card secret shares">Reshuffle Shares</button>
        </div>
      </section>

      <section class="panel">
        <h2>Exhibit 2 — MPC Party Simulation</h2>
        <div class="controls">
          <label>Secret (hex)
            <input id="secret-hex" value="${exhibit2State.secretHex}" />
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
        <p class="verify-result" role="status" aria-live="polite">${exhibit2State.verificationText}</p>
      </section>

      <section class="panel">
        <h2>Exhibit 3 — Fiat-Shamir Signature</h2>
        <label>Message
          <input id="fs-message" value="${fsMessage}" />
        </label>
        <div class="button-row">
          <button id="run-fs" type="button" aria-label="Run Fiat Shamir signature derivation">Run Fiat-Shamir</button>
          <button id="tamper-fs" type="button" aria-label="Modify message and recompute challenge">Modify Message</button>
        </div>
        <div class="columns">
          <div>
            <h3>Interactive</h3>
            <pre>Prover -> Commit(views)
Verifier -> Challenge e
Prover -> Reveal all except e</pre>
          </div>
          <div>
            <h3>Fiat-Shamir</h3>
            <pre>e = SHA-256(message || commitments)
Signature = (roots, e, responses)
Verifier recomputes e and checks consistency</pre>
          </div>
        </div>
        <p>Hidden parties per round: ${fsHidden.length > 0 ? fsHidden.join(', ') : 'not generated'}</p>
        <pre class="trace">${fsSignatureTrace || 'Run the demo to show challenge derivation.'}</pre>
      </section>

      <section class="panel">
        <h2>Exhibit 4 — Toy PERK</h2>
        <p>
          Toy PERK relation: find a permutation <span class="math">&pi;</span> such that
          <span class="math">H&nbsp;&middot;&nbsp;&pi;(y)&nbsp;=&nbsp;b&nbsp;(mod&nbsp;q)</span>.
          This demo uses tiny parameters for visibility.
        </p>
        <div class="button-row">
          <button id="perk-keygen" type="button" aria-label="Generate toy PERK keypair">Generate PERK Keypair</button>
          <button id="perk-sign" type="button" aria-label="Sign message with toy PERK">Sign</button>
          <button id="perk-verify" type="button" aria-label="Verify toy PERK signature">Verify</button>
          <button id="perk-reveal" type="button" aria-label="Toggle visibility of private permutation">${perkShowPrivate ? 'Hide π' : 'Reveal π'}</button>
        </div>
        <label>Message
          <input id="perk-message" value="${perkMessage}" />
        </label>
        <p>Signature status: <strong class="${perkVerifyText.includes('VALID') ? 'ok' : 'bad'}">${perkVerifyText}</strong></p>
        <p>Key equation check <span class="math">H&nbsp;&middot;&nbsp;&pi;(y)&nbsp;=&nbsp;b</span>: ${perkEquation ? '✓ holds' : 'pending'}</p>
        <p>Estimated signature size: ~${size.bytes} bytes</p>
        <pre>${JSON.stringify(size.breakdown, null, 2)}</pre>
        <pre>${
          perkKeypair
            ? `public H rows: ${perkKeypair.publicKey.H.length}\npublic y: [${perkKeypair.publicKey.y.join(', ')}]\npublic b: [${perkKeypair.publicKey.b.join(', ')}]\n${
                perkShowPrivate ? `private pi: [${perkKeypair.privateKey.pi.join(', ')}]` : 'private pi: [hidden]'
              }`
            : 'Generate a keypair to view parameters.'
        }</pre>
      </section>

      <section class="panel">
        <h2>Exhibit 5 — Security Diversity</h2>
        <p>
          NIST Round 2 additional signatures include Mirath, PERK, RYDE, SDitH, MQOM, and FAEST.
          None are standardized as of 2026. They are under active cryptanalysis.
        </p>
        <div class="table-wrap">
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
      const partial = partialReconstruct(exhibit2State.shares, 0);
      const full = reconstructSecret(exhibit2State.shares);
      exhibit2State.verificationText = `Split complete. Partial XOR(no party 1): ${bytesToHex(partial)}. Full reconstruct: ${bytesToHex(full)}.`;
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

  const fsInput = document.querySelector<HTMLInputElement>('#fs-message');
  fsInput?.addEventListener('input', () => {
    fsMessage = fsInput.value;
  });

  const fsBtn = document.querySelector<HTMLButtonElement>('#run-fs');
  fsBtn?.addEventListener('click', async () => {
    await runFiatShamirDemo();
    render();
  });

  const tamperBtn = document.querySelector<HTMLButtonElement>('#tamper-fs');
  tamperBtn?.addEventListener('click', async () => {
    fsMessage = `${fsMessage} *`;
    await runFiatShamirDemo();
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
