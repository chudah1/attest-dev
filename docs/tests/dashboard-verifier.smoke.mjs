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
const fixtureDir = path.join(repoRoot, 'testdata', 'evidence');
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
      const relative = pathname === '/' ? 'docs/dashboard.html' : pathname.replace(/^\/+/, '');
      const filePath = path.join(rootDir, relative);

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

async function loadJSON(name) {
  const raw = await fs.readFile(path.join(fixtureDir, name), 'utf8');
  return JSON.parse(raw);
}

function makeOrg(packet) {
  return {
    id: packet.org.id,
    name: packet.org.name,
    status: 'active',
    created_at: packet.generated_at,
  };
}

async function withDashboard(t, packetMutator, fn) {
  const packet = await loadJSON('packet.json');
  const jwks = await loadJSON('jwks.json');
  if (packetMutator) packetMutator(packet);
  const org = makeOrg(packet);
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

  await context.addInitScript((savedKey) => {
    window.localStorage.setItem('attest_key', savedKey);
  }, 'att_live_fixture');

  await context.route('https://api.attestdev.com/**', async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === '/v1/org') {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(org) });
      return;
    }
    if (url.pathname.endsWith('/audit')) {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(packet.events) });
      return;
    }
    if (url.pathname.endsWith('/evidence')) {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(packet) });
      return;
    }
    if (url.pathname === `/orgs/${packet.org.id}/jwks.json`) {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(jwks) });
      return;
    }
    await route.fulfill({ status: 404, contentType: 'application/json', body: JSON.stringify({ error: 'not found' }) });
  });

  const page = await context.newPage();
  await page.goto(`http://localhost:${port}/docs/dashboard.html`);
  await page.getByRole('button', { name: /audit log/i }).click();
  await page.locator('#task-id-input').fill(packet.task.att_tid);
  await page.getByRole('button', { name: /search events/i }).click();
  await page.getByText('Verification details').waitFor();

  await fn(page);
}

test('dashboard verifier passes for the signed fixture packet', async (t) => {
  await withDashboard(t, null, async (page) => {
    await page.getByRole('button', { name: /verify packet/i }).click();
    await page.locator('.verification-status.success').getByText('Verified on site').waitFor();
    await page.locator('.verification-panel').getByText('Matches canonical packet').waitFor();
    await page.locator('.verification-panel').getByText('RS256 signature valid').waitFor();
    await page.locator('.verification-panel').getByText('Append-only chain intact').waitFor();
  });
});

test('dashboard verifier fails for a tampered fixture packet', async (t) => {
  await withDashboard(t, (packet) => {
    packet.summary.result = 'revoked';
  }, async (page) => {
    await page.getByRole('button', { name: /verify packet/i }).click();
    await page.locator('.verification-status.error').getByText('Verification failed').waitFor();
    await page.locator('.verification-panel').getByText('Hash mismatch detected').waitFor();
    await page.locator('.verification-panel').getByText('Signature invalid or missing').waitFor();
  });
});
