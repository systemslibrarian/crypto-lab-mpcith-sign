import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys are already gated on the demo's own tests;
 * this gates them on accessibility the same way. Scans the full page in both
 * themes (dark default + light), with animations/opacity neutralized and every
 * collapsible/hidden region revealed so nothing is measured mid-fade.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function revealEverything(page: Page): Promise<void> {
  // Panels fade in via a `reveal` keyframe (opacity 0 -> 1); mid-fade opacity
  // produces phantom contrast failures. Neutralize all motion/opacity first.
  await page.addStyleTag({
    content: `*,*::before,*::after{
      animation:none!important;
      transition:none!important;
      opacity:1!important;
    }`,
  });

  await page.evaluate(() => {
    // Expand any native <details> (none today, but future-proof).
    for (const details of Array.from(document.querySelectorAll('details'))) {
      (details as HTMLDetailsElement).open = true;
    }
    // Reveal anything hidden via the [hidden] attribute or a display/.open toggle.
    for (const el of Array.from(document.querySelectorAll('[hidden]'))) {
      el.removeAttribute('hidden');
    }
  });
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

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await revealEverything(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await revealEverything(page);
  await scan(page);
});
