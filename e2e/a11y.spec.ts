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
  await page.emulateMedia({ reducedMotion: 'reduce' });

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

/**
 * SC 1.4.11 (non-text contrast): every text-entry control boundary (text
 * input, select, textarea) must reach 3:1 against the field's own fill AND
 * against the surface behind it, in both themes. The panels are translucent
 * and the page background is a gradient, so the "behind" surface is computed
 * by compositing the translucent ancestor layers over every opaque color that
 * can appear under them (gradient stops included) and taking the worst case.
 * Axe does not flag border-vs-surface, so this asserts it directly.
 */
async function controlBorderContrasts(page: Page): Promise<Array<{ id: string; ratio: number }>> {
  return page.evaluate(() => {
    type C = { r: number; g: number; b: number; a: number };
    const parse = (s: string): C => {
      const m = s.match(/rgba?\(([^)]+)\)/);
      if (!m) return { r: 0, g: 0, b: 0, a: 0 };
      const p = m[1].split(/[,\s/]+/).map(parseFloat);
      return { r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1 };
    };
    const over = (fg: C, bg: C): C => {
      const a = fg.a + bg.a * (1 - fg.a);
      return {
        r: (fg.r * fg.a + bg.r * bg.a * (1 - fg.a)) / a,
        g: (fg.g * fg.a + bg.g * bg.a * (1 - fg.a)) / a,
        b: (fg.b * fg.a + bg.b * bg.a * (1 - fg.a)) / a,
        a,
      };
    };
    const lum = (c: C) => {
      const f = (v: number) => {
        v /= 255;
        return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
      };
      return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b);
    };
    const ratio = (a: C, b: C) => {
      const [hi, lo] = lum(a) > lum(b) ? [lum(a), lum(b)] : [lum(b), lum(a)];
      return (hi + 0.05) / (lo + 0.05);
    };
    /** Every opaque surface that can sit directly under `el`'s border. */
    const surfacesBehind = (el: Element): C[] => {
      const layers: C[] = []; // translucent ancestor layers, innermost first
      const bases: C[] = [];
      for (let n = el.parentElement; n; n = n.parentElement) {
        const cs = getComputedStyle(n);
        const bg = parse(cs.backgroundColor);
        const grad = cs.backgroundImage && cs.backgroundImage !== 'none';
        if (bg.a >= 1 && !grad) {
          bases.push(bg);
          break;
        }
        if (grad) {
          const stops = [...cs.backgroundImage.matchAll(/rgba?\([^)]+\)/g)].map((m) =>
            parse(m[0]),
          );
          const opaqueStops = stops.filter((s) => s.a >= 1);
          const translucentStops = stops.filter((s) => s.a < 1);
          const baseCands: C[] = opaqueStops.length
            ? opaqueStops
            : [bg.a >= 1 ? bg : { r: 255, g: 255, b: 255, a: 1 }];
          for (const b of baseCands) {
            bases.push(b);
            // Translucent radial tints can brighten any base stop.
            for (const t of translucentStops) bases.push(over(t, b));
          }
          break;
        }
        if (bg.a > 0) layers.push(bg);
      }
      if (bases.length === 0) bases.push({ r: 255, g: 255, b: 255, a: 1 });
      return bases.map((b) => {
        let out = b;
        for (let i = layers.length - 1; i >= 0; i--) out = over(layers[i], out);
        return out;
      });
    };
    const out: Array<{ id: string; ratio: number }> = [];
    document
      .querySelectorAll<HTMLElement>("select, textarea, input[type='text']")
      .forEach((el) => {
        const r = el.getBoundingClientRect();
        if (r.width === 0 || r.height === 0) return;
        const cs = getComputedStyle(el);
        if (parseFloat(cs.borderTopWidth) === 0) return;
        const borderRaw = parse(cs.borderTopColor);
        const fillRaw = parse(cs.backgroundColor);
        let worst = Infinity;
        for (const surface of surfacesBehind(el)) {
          const fill = fillRaw.a > 0 ? over(fillRaw, surface) : surface;
          const border = over(over(borderRaw, fill), surface);
          worst = Math.min(worst, ratio(border, surface), ratio(border, fill));
        }
        out.push({ id: el.id || el.tagName.toLowerCase(), ratio: worst });
      });
    return out;
  });
}

async function assertControlBorders(page: Page): Promise<void> {
  await revealEverything(page);
  const results = await controlBorderContrasts(page);
  expect(results.length).toBeGreaterThan(0);
  for (const { id, ratio } of results) {
    expect(ratio, `#${id} border contrast`).toBeGreaterThanOrEqual(3);
  }
}

async function checkGradientContrast(page: Page): Promise<void> {
  const badElements = await page.evaluate(() => {
    type C = { r: number; g: number; b: number; a: number };
    const parse = (s: string): C => {
      if (s.startsWith('color(srgb')) {
        const m = s.match(/color\(srgb ([\d.]+) ([\d.]+) ([\d.]+)(?: \/ ([\d.]+))?\)/);
        if (m) return { r: parseFloat(m[1])*255, g: parseFloat(m[2])*255, b: parseFloat(m[3])*255, a: m[4] ? parseFloat(m[4]) : 1 };
      }
      const m = s.match(/rgba?\(([^)]+)\)/);
      if (!m) return { r: 0, g: 0, b: 0, a: 0 };
      const p = m[1].split(/[,\s/]+/).map(parseFloat);
      return { r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1 };
    };
    const over = (fg: C, bg: C): C => {
      const a = fg.a + bg.a * (1 - fg.a);
      if (a === 0) return { r: 0, g: 0, b: 0, a: 0 };
      return {
        r: (fg.r * fg.a + bg.r * bg.a * (1 - fg.a)) / a,
        g: (fg.g * fg.a + bg.g * bg.a * (1 - fg.a)) / a,
        b: (fg.b * fg.a + bg.b * bg.a * (1 - fg.a)) / a,
        a,
      };
    };
    const lum = (c: C) => {
      const f = (v: number) => {
        v /= 255;
        return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
      };
      return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b);
    };
    const ratio = (a: C, b: C) => {
      const [hi, lo] = lum(a) > lum(b) ? [lum(a), lum(b)] : [lum(b), lum(a)];
      return (hi + 0.05) / (lo + 0.05);
    };

    const surfacesBehind = (el: Element): C[] => {
      const layers: C[] = []; 
      const bases: C[] = [];
      for (let n = el.parentElement; n; n = n.parentElement) {
        const cs = getComputedStyle(n);
        const bg = parse(cs.backgroundColor);
        const grad = cs.backgroundImage && cs.backgroundImage !== 'none' && cs.backgroundImage.includes('gradient');
        if (bg.a >= 1 && !grad) {
          bases.push(bg);
          break;
        }
        if (grad) {
          const stops = [...cs.backgroundImage.matchAll(/rgba?\([^)]+\)/g)].map((m) =>
            parse(m[0]),
          );
          const opaqueStops = stops.filter((s) => s.a >= 1);
          const translucentStops = stops.filter((s) => s.a < 1 && s.a > 0);
          
          if (opaqueStops.length > 0 || bg.a >= 1) {
            const baseCands = opaqueStops.length ? opaqueStops : [bg];
            for (const b of baseCands) {
              bases.push(b);
              for (const t of translucentStops) bases.push(over(t, b));
            }
            break;
          } else {
            for (const t of translucentStops) layers.push(t);
            continue;
          }
        }
        if (bg.a > 0) layers.push(bg);
      }
      if (bases.length === 0) bases.push({ r: 255, g: 255, b: 255, a: 1 });
      return bases.map((b) => {
        let out = b;
        for (let i = layers.length - 1; i >= 0; i--) out = over(layers[i], out);
        return out;
      });
    };

    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null);
    let node: Node | null;
    const fails = [];
    while ((node = walker.nextNode())) {
      if (!node.nodeValue || !node.nodeValue.trim()) continue;
      const el = node.parentElement;
      if (!el || el.closest('svg') || el.getBoundingClientRect().width === 0) continue;
      
      const cs = getComputedStyle(el);
      let hasGradient = false;
      for (let n: HTMLElement | null = el; n; n = n.parentElement) {
        if (getComputedStyle(n).backgroundImage.includes('gradient')) {
          hasGradient = true; break;
        }
        if (parse(getComputedStyle(n).backgroundColor).a >= 1) break;
      }
      if (!hasGradient) continue;

      const fg = parse(cs.color);
      let worst = Infinity;
      for (const surface of surfacesBehind(el)) {
        worst = Math.min(worst, ratio(fg, surface));
      }
      if (worst < 4.5) {
        fails.push({ text: node.nodeValue.trim().substring(0, 30), ratio: worst });
      }
    }
    return fails;
  });
  expect(badElements).toEqual([]);
}

test('text-entry control borders reach 3:1 in dark theme (SC 1.4.11)', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('h1')).toBeVisible();
  await assertControlBorders(page);
});

test('text-entry control borders reach 3:1 in light theme (SC 1.4.11)', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await expect(page.locator('h1')).toBeVisible();
  await assertControlBorders(page);
});

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('h1')).toBeVisible();
  await revealEverything(page);
  await scan(page);
  await checkGradientContrast(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await expect(page.locator('h1')).toBeVisible();
  await revealEverything(page);
  await scan(page);
  await checkGradientContrast(page);
});
