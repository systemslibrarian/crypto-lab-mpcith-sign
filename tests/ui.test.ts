// @vitest-environment jsdom
import { webcrypto } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// jsdom ships getRandomValues but not always SubtleCrypto; use Node's WebCrypto
// so the demo's SHA-256 commitments work under test.
beforeEach(() => {
  vi.stubGlobal('crypto', webcrypto);
  document.documentElement.setAttribute('data-theme', 'dark');
  document.body.innerHTML =
    '<div id="sr-live" role="status" aria-live="polite"></div><div id="app"></div>';
  vi.resetModules();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

async function clickAndSettle(id: string): Promise<void> {
  (document.getElementById(id) as HTMLButtonElement | null)?.click();
  // Allow the async handler (which may await many SHA-256 commitments and
  // Merkle proofs) and its follow-up render() to run.
  for (let i = 0; i < 12; i += 1) {
    await tick();
  }
}

describe('Exhibit 2 UI', () => {
  it('renders the six exhibit panels on load', async () => {
    await import('../src/main.ts');
    await tick();
    // Five conceptual exhibits; Exhibit 2 is split into the party simulation
    // and the standalone "cheating prover" soundness experiment (2b).
    expect(document.querySelectorAll('.panel')).toHaveLength(6);
    expect(document.querySelector('.party-grid')).toBeTruthy();
  });

  // Regression: previously, raising N after a round was committed left
  // renderPartyCards()/verifyStep() indexing past the stale arrays and threw.
  it('does not crash when N is raised after running MPC, then verifying', async () => {
    await import('../src/main.ts');
    await tick();

    await clickAndSettle('split-secret');
    await clickAndSettle('run-mpc');

    const slider = document.getElementById('n-slider') as HTMLInputElement;
    slider.value = '8';
    slider.dispatchEvent(new Event('input', { bubbles: true }));
    await tick();

    // The stale round must have been cleared, and the grid must still render.
    expect(document.querySelector('.party-grid')).toBeTruthy();
    expect(document.querySelectorAll('.party-card')).toHaveLength(8);

    // Challenge + Verify against the cleared round must not throw.
    await clickAndSettle('run-challenge');
    await clickAndSettle('run-verify');

    // Verify safely short-circuits on the cleared round instead of throwing.
    expect(document.querySelector('.party-grid')).toBeTruthy();
    expect(document.querySelector('.verify-result')?.textContent ?? '').toMatch(/MPC/i);
  });

  it('exposes a persistent live region and a skip link target', async () => {
    await import('../src/main.ts');
    await tick();
    expect(document.getElementById('sr-live')).toBeTruthy();
    expect(document.getElementById('main')).toBeTruthy();
  });

  it('threads the typed secret into the witness/statement flow banner', async () => {
    await import('../src/main.ts');
    await tick();
    await clickAndSettle('run-mpc');
    // The flow banner shows secret → witness → public b, proving the typed
    // secret is what gets proven (not a discarded, freshly-randomized witness).
    const banner = document.querySelector('.flow-banner');
    expect(banner).toBeTruthy();
    // Default secret 0x2a → witness [42] (mod 251). b is A·x, published.
    expect(banner?.textContent ?? '').toMatch(/42/);
    expect(document.querySelector('.flow-banner code')?.textContent ?? '').toBeTruthy();
  });

  it('opens a zero-knowledge experiment after a full Verify', async () => {
    await import('../src/main.ts');
    await tick();
    await clickAndSettle('run-mpc');
    await clickAndSettle('run-challenge');
    await clickAndSettle('run-verify');
    // The ZK panel lists the true hidden share plus decoys, all "consistent".
    const zk = document.querySelector('.zk-details[open]');
    expect(zk).toBeTruthy();
    expect(zk?.textContent ?? '').toMatch(/equally consistent|consistent/i);
    // At least the true share row plus two decoys.
    expect(document.querySelectorAll('.zk-body tbody tr').length).toBeGreaterThanOrEqual(3);
  });

  it('runs the cheating-prover experiment and tallies caught vs slipped', async () => {
    await import('../src/main.ts');
    await tick();
    await clickAndSettle('cheat-100');
    // 100 attempts must all be accounted for as caught or slipped.
    const text = document.querySelector('.cheat-result')?.textContent ?? '';
    expect(text).toMatch(/100 attempts/);
    expect(text).toMatch(/caught/i);
    expect(text).toMatch(/slipped/i);
  });
});
