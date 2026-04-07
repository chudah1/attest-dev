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
      let filePath;
      if (pathname.startsWith('/testdata/')) {
        filePath = path.join(rootDir, 'docs', pathname.replace(/^\/+/, ''));
      } else {
        let relative = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
        if (relative.endsWith('/')) relative += 'index.html';
        filePath = path.join(rootDir, 'docs', relative);
      }

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

async function withVerifyPage(t, fn) {
  const server = await serveStatic(repoRoot);
  const address = server.address();
  const port = address && typeof address === 'object' ? address.port : 0;
  const browser = await chromium.launch({ executablePath: chromePath, headless: true });
  const context = await browser.newContext();

  t.after(async () => {
    await context.close();
    await browser.close();
    await new Promise((resolve, reject) => server.close((err) => err ? reject(err) : resolve()));
  });

  const page = await context.newPage();
  await page.goto(`http://localhost:${port}/verify/`);
  await fn(page);
}

test('public verify page validates the sample evidence packet', async (t) => {
  await withVerifyPage(t, async (page) => {
    await page.locator('#load-sample-btn').click();
    await page.getByText('Sample packet loaded').waitFor();
    await page.getByRole('button', { name: /verify packet/i }).click();

    await page.locator('#status-chip.status-pass').getByText('Verified').waitFor();
    await page.locator('#result-grid').getByText('Matches canonical packet').waitFor();
    await page.locator('#result-grid').getByText('RS256 signature valid').waitFor();
    await page.locator('#result-grid').getByText('Append-only chain intact').waitFor();
    await page.locator('#meta-block').getByText('org_test_fixture').waitFor();
  });
});

test('public verify page detects tampered packet content', async (t) => {
  await withVerifyPage(t, async (page) => {
    await page.locator('#load-sample-btn').click();
    await page.getByText('Sample packet loaded').waitFor();

    const packetArea = page.locator('#packet-input');
    const packet = JSON.parse(await packetArea.inputValue());
    packet.summary.result = 'revoked';
    await packetArea.fill(JSON.stringify(packet, null, 2));

    await page.getByRole('button', { name: /verify packet/i }).click();

    await page.locator('#status-chip.status-fail').getByText('Issues').waitFor();
    await page.locator('#result-grid').getByText('Hash mismatch detected').waitFor();
    await page.locator('#result-grid').getByText('Signature invalid or missing').waitFor();
  });
});
