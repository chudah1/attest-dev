import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { chromium } from 'playwright-core';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '../..');
const chromePath = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';

const contentTypes = new Map([
  ['.html', 'text/html; charset=utf-8'],
  ['.js', 'application/javascript; charset=utf-8'],
  ['.json', 'application/json; charset=utf-8'],
  ['.css', 'text/css; charset=utf-8'],
  ['.svg', 'image/svg+xml'],
  ['.ico', 'image/x-icon'],
]);

function serveStatic(rootDir) {
  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url || '/', 'http://localhost');
      const pathname = decodeURIComponent(url.pathname);
      let relative = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
      if (relative.endsWith('/')) relative += 'index.html';
      const filePath = path.join(rootDir, 'docs', relative);

      if (!filePath.startsWith(rootDir)) {
        res.writeHead(403);
        res.end('forbidden');
        return;
      }

      const body = await fs.readFile(filePath);
      res.writeHead(200, {
        'Content-Type': contentTypes.get(path.extname(filePath)) || 'application/octet-stream',
      });
      res.end(body);
    } catch {
      res.writeHead(404);
      res.end('not found');
    }
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}

test('waitlist page embeds the Tally early access form', async (t) => {
  const server = await serveStatic(repoRoot);
  const address = server.address();
  const port = address && typeof address === 'object' ? address.port : 0;
  const browser = await chromium.launch({ executablePath: chromePath, headless: true });
  const page = await browser.newPage();

  t.after(async () => {
    await browser.close();
    await new Promise((resolve, reject) => server.close((err) => err ? reject(err) : resolve()));
  });

  await page.goto(`http://localhost:${port}/waitlist/`);

  await page.getByRole('heading', { name: /start seeing what your agents do/i }).waitFor();
  const frame = page.locator('iframe[data-tally-src]');
  await frame.waitFor();
  const src = await frame.getAttribute('data-tally-src');
  assert.ok(src.startsWith('https://tally.so/'), 'Tally embed src should point to tally.so');
  const docsHref = await page.getByRole('link', { name: /docs/i }).getAttribute('href');
  assert.equal(docsHref, '../docs/');
});
