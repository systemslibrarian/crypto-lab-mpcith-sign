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
// FIPS 205 Table 2 approves twelve SLH-DSA parameter sets, and every name
// carries the hash family that instantiates it: there is no "SLH-DSA-128s". The
// hash row was labelled that way. Its 7 856-byte signature is the right figure
// but does not identify a family — Table 2 pairs SLH-DSA-SHA2-128s and
// SLH-DSA-SHAKE-128s on one row (n=16, h=63, d=7, a=12, k=14, category 1, pk 32
// bytes, sig 7 856 bytes), so the two families are identical in size and the
// row carried no family of its own to preserve. SHA2 is therefore named, and the
// page says so beside the table.
//
// The Round 3 status sentence is gated here too: the advancement date and NIST
// IR 8610, which is where the rationale and the category grouping come from.
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

it('labels the hash comparison row with its FIPS 205 parameter-set name', async () => {
  await import('../src/main.ts');
  await tick();

  const rows = [...document.querySelectorAll('tbody tr')];
  const hash = rows.filter((tr) => (tr.querySelector('td')?.textContent ?? '').startsWith('SLH-DSA'));
  expect(hash).toHaveLength(1);

  const cells = [...hash[0].querySelectorAll('td')].map((td) => td.textContent?.trim());
  expect(cells[0]).toBe('SLH-DSA-SHA2-128s');
  expect(cells[1]).toBe('7,856 B');

  // No comparison cell may carry the family-less non-name. The note below the
  // table quotes it to explain the correction, so the scope is table cells.
  const cellLabels = [...document.querySelectorAll('td')].map((td) => td.textContent?.trim());
  expect(cellLabels).not.toContain('SLH-DSA-128s');
});

it('says why SHA2 is the family named, not SHAKE', async () => {
  await import('../src/main.ts');
  await tick();

  const text = (document.body.textContent ?? '').replace(/\s+/g, ' ');
  expect(text).toContain('FIPS 205 approves no parameter set called "SLH-DSA-128s"');
  expect(text).toContain('SLH-DSA-SHAKE-128s the same 7,856-byte signature');
  expect(document.querySelector('a[href="https://doi.org/10.6028/NIST.FIPS.205"]')).toBeTruthy();
});

it('dates the Round 3 advancement and cites NIST IR 8610 for it', async () => {
  await import('../src/main.ts');
  await tick();

  const text = (document.body.textContent ?? '').replace(/\s+/g, ' ');
  expect(text).toContain('On May 14, 2026');
  expect(text).toContain('nine additional-signature candidates to Round 3');
  expect(text).toContain('NIST IR 8610');
  // The grouping is IR 8610 Table 3's, cited to IR 8610 and to nothing else:
  // the CSRC round-3 page files FAEST under "Symmetric-based Signatures".
  expect(text).toContain('Table 3 groups all three of FAEST, MQOM and SDitH under MPC-in-the-Head');
  expect(text).not.toContain('Symmetric-based Signatures');
  expect(document.querySelector('a[href="https://doi.org/10.6028/NIST.IR.8610"]')).toBeTruthy();
  // The announcement is cited at its CSRC address, the one the rest of the fleet uses.
  expect(
    document.querySelector('a[href="https://csrc.nist.gov/News/2026/nist-advances-9-candidates-to-the-3rd-round-of-pqc"]'),
  ).toBeTruthy();
});

// The three MPCitH rows used to read "PERK-I (est.) ~6,000 B", "Mirath-I (est.)
// ~5,700 B" and "FAEST-I (est.) ~5,700 B". None of those figures matches any
// parameter set the schemes publish, and "(est.)" is not a source. Each row now
// names a parameter set from the scheme's current specification and quotes that
// document's own number:
//   PERK v2.2.0 (20/12/2025) Table 5:      PERK-1-Short    3.48 kB
//   Mirath v2.1.0 (23/09/2025) Table 8:    Mirath-1a-short 3,182 B
//   FAEST v3.0 (01/09/2026) Table 9.3:     FAEST-128s      4,066 B
it('quotes each MPCitH row from that scheme’s own current specification', async () => {
  await import('../src/main.ts');
  await tick();

  const rows = [...document.querySelectorAll('tbody tr')];
  const sigSize = (name: string) => {
    const row = rows.filter(
      (tr) => (tr.querySelector('td')?.textContent ?? '').trim() === name,
    );
    expect(row).toHaveLength(1);
    return [...row[0].querySelectorAll('td')].map((td) => td.textContent?.trim());
  };

  expect(sigSize('PERK-1-Short')[1]).toBe('3.48 kB');
  expect(sigSize('Mirath-1a-short')[1]).toBe('3,182 B');
  expect(sigSize('FAEST-128s')[1]).toBe('4,066 B');

  // No estimate may stand in for a published figure anywhere in the table.
  const cells = [...document.querySelectorAll('td')].map((td) => td.textContent?.trim() ?? '');
  expect(cells.some((c) => c.includes('(est.)'))).toBe(false);
  expect(cells.some((c) => c.startsWith('~'))).toBe(false);
  expect(cells).not.toContain('~6,000 B');
  expect(cells).not.toContain('~5,700 B');
});

it('says which specification and which round each MPCitH figure comes from', async () => {
  await import('../src/main.ts');
  await tick();

  const text = (document.body.textContent ?? '').replace(/\s+/g, ' ');
  expect(text).toContain('PERK v2.2.0');
  expect(text).toContain('Mirath v2.1.0');
  expect(text).toContain('FAEST v3.0');
  // FAEST advanced; PERK and Mirath did not, so they are not all one round.
  expect(text).toContain('FAEST v3.0 is the Round 3 submission');
  expect(text).toContain('Round 2 page');
  for (const href of [
    'https://pqc-perk.org/assets/downloads/perk-v2.2.0.pdf',
    'https://pqc-mirath.org/assets/downloads/mirath_v2.1.0.pdf',
    'https://faest.info/faest-spec-v3.0.pdf',
    'https://csrc.nist.gov/projects/pqc-dig-sig/round-2-additional-signatures',
  ]) {
    expect(document.querySelector(`a[href="${href}"]`)).toBeTruthy();
  }
});
