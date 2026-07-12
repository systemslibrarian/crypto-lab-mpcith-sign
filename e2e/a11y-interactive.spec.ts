import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function driveAll(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{animation:none!important;transition:none!important;opacity:1!important;}`,
  });
  // Drive Exhibit 2 full flow -> opens ZK panel.
  await page.locator('#run-mpc').click();
  await page.locator('#run-challenge').click();
  await page.locator('#run-verify').click();
  // Cheating tally.
  await page.locator('#cheat-100').click();
  // Fiat-Shamir diff (modify twice to get before/after + flips).
  await page.locator('#run-fs').click();
  await page.locator('#tamper-fs').click();
  await page.locator('#tamper-fs').click();
  // PERK permutation reveal.
  await page.locator('#perk-sign').click();
  await page.locator('#perk-reveal').click();
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test('no WCAG violations after driving every interaction (dark)', async ({ page }) => {
  await page.goto('.');
  await driveAll(page);
  await scan(page);
});

test('no WCAG violations after driving every interaction (light)', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await driveAll(page);
  await scan(page);
});
