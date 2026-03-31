import test from 'node:test';
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
      const relative = pathname === '/' ? 'docs/demo.html' : pathname.replace(/^\/+/, '');
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

async function withDemoPage(t, fn) {
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
  await page.goto(`http://localhost:${port}/docs/demo.html`);
  await fn(page);
}

test('demo compares insecure compromise path against Attest containment', async (t) => {
  await withDemoPage(t, async (page) => {
    await page.getByRole('button', { name: /launch both pipelines/i }).click();
    await page.getByText('Children delegated').waitFor();

    await page.getByRole('button', { name: /compromised orchestrator pivots/i }).click();
    await page.getByText('Pivot succeeded').waitFor();
    await page.getByText('Pivot blocked').waitFor();

    await page.getByRole('button', { name: /try shutdown \/ revoke/i }).click();
    await page.getByText('Shutdown failed').waitFor();
    await page.getByText('Tree revoked').waitFor();

    await page.getByRole('button', { name: /generate contrast summary/i }).click();
    await page.getByText('Contrast summary generated').waitFor();
    await page.locator('#verify-panel').getByText('Without scoping: CRM write went through').waitFor();

    await page.getByRole('button', { name: /generate evidence packet/i }).click();
    await page.getByText('Evidence packet generated').waitFor();
    await page.locator('#packet-box').getByText('attest.evidence_packet').waitFor();
    await page.locator('#evidence-grid').getByText('Ready for export').waitFor();
  });
});
