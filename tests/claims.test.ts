// @vitest-environment jsdom
//
// Claims the page makes about OTHER schemes, checked against the standard that
// names them. The comparison table is the only place this demo quotes figures
// it did not compute, so the figures and the names are gated here.
//
// FIPS 204 Table 2 gives the parameter sets as ML-DSA-44 / ML-DSA-65 /
// ML-DSA-87, with signature sizes 2420 / 3309 / 4627 bytes. The lattice row was
// labelled "ML-DSA-2" — the Dilithium-era habit of naming the NIST security
// category — which is not a name FIPS 204 uses for anything.
//
// Kept in its own file rather than added to ui.test.ts so the sequence of
// mounts in that file is unchanged.
import { webcrypto } from 'node:crypto';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

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

it('labels the lattice comparison row with its FIPS 204 parameter-set name', async () => {
  await import('../src/main.ts');
  await tick();

  const rows = [...document.querySelectorAll('tbody tr')];
  const lattice = rows.filter((tr) => /Lattice/.test(tr.textContent ?? ''));
  expect(lattice).toHaveLength(1);

  const cells = [...lattice[0].querySelectorAll('td')].map((td) => td.textContent?.trim());
  expect(cells[0]).toBe('ML-DSA-44');
  expect(cells[1]).toBe('2,420 B');

  // "ML-DSA-2" is not a FIPS 204 name; "ML-DSA-44" does not contain it.
  expect(document.body.textContent ?? '').not.toContain('ML-DSA-2');
});
