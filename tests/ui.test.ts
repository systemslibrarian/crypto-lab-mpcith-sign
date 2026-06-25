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
  // Allow the async handler and its follow-up render() to run.
  await tick();
  await tick();
  await tick();
}

describe('Exhibit 2 UI', () => {
  it('renders the five exhibits on load', async () => {
    await import('../src/main.ts');
    await tick();
    expect(document.querySelectorAll('.panel')).toHaveLength(5);
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
});
