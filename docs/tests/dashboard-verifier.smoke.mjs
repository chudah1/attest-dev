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

function makeReportHTML(packet, template) {
  const templates = {
    audit: {
      title: 'Attest Evidence Report',
      eyebrow: 'Agent Authorization Evidence Report',
    },
    soc2: {
      title: 'Attest SOC 2 Evidence Report',
      eyebrow: 'SOC 2 Control Evidence',
    },
    incident: {
      title: 'Attest Incident Review Report',
      eyebrow: 'Incident Review Packet',
    },
  };
  const selected = templates[template] || templates.audit;
  return `<!DOCTYPE html>
  <html lang="en">
    <head>
      <meta charset="utf-8" />
      <title>${selected.title}</title>
    </head>
    <body>
      <h1>${selected.eyebrow}</h1>
      <p>${packet.task.att_tid}</p>
      <p>${packet.integrity.packet_hash}</p>
    </body>
  </html>`;
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
  const context = await browser.newContext({ acceptDownloads: true });

  t.after(async () => {
    await context.close();
    await browser.close();
    await new Promise((resolve, reject) => server.close((err) => err ? reject(err) : resolve()));
  });

  await context.addInitScript((savedKey) => {
    window.localStorage.setItem('attest_key', savedKey);
  }, 'att_live_fixture');

  await context.addInitScript(() => {
    const blobStore = new Map();
    let blobCounter = 0;
    const originalCreateObjectURL = URL.createObjectURL.bind(URL);
    const originalRevokeObjectURL = URL.revokeObjectURL.bind(URL);
    const originalAnchorClick = HTMLAnchorElement.prototype.click;

    window.__blobStore = blobStore;
    window.__lastOpenedURL = null;
    window.__lastDownload = null;

    URL.createObjectURL = (blob) => {
      const url = `blob:smoke-${++blobCounter}`;
      blob.text().then((text) => {
        blobStore.set(url, { text, type: blob.type });
      });
      return url;
    };

    URL.revokeObjectURL = (url) => {
      const existing = blobStore.get(url);
      if (existing) {
        blobStore.set(url, { ...existing, revoked: true });
      }
      if (typeof originalRevokeObjectURL === 'function') {
        try { originalRevokeObjectURL(url); } catch {}
      }
    };

    window.open = (url) => {
      window.__lastOpenedURL = url;
      return null;
    };

    HTMLAnchorElement.prototype.click = function clickIntercept() {
      if (this.download) {
        window.__lastDownload = {
          url: this.href,
          filename: this.download,
        };
        return;
      }
      return originalAnchorClick.call(this);
    };

    window.__readBlobText = async (url) => {
      for (let i = 0; i < 50; i += 1) {
        const entry = blobStore.get(url);
        if (entry && typeof entry.text === 'string') {
          return entry;
        }
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
      return null;
    };
  });

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
    if (url.pathname.endsWith('/report')) {
      const template = url.searchParams.get('template') || 'audit';
      await route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body: makeReportHTML(packet, template) });
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

  await fn(page, packet);
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

test('dashboard open report uses the selected template and rendered packet details', async (t) => {
  await withDashboard(t, null, async (page, packet) => {
    await page.locator('#report-template-select').selectOption('soc2');
    await page.getByRole('button', { name: /open report/i }).click();

    await page.getByText('Evidence report opened').waitFor();

    const openedURL = await page.waitForFunction(() => window.__lastOpenedURL);
    const blobEntry = await page.evaluate(async (url) => window.__readBlobText(url), await openedURL.jsonValue());

    assert.ok(blobEntry, 'expected a captured report blob');
    assert.equal(blobEntry.type, 'text/html');
    assert.match(blobEntry.text, /Attest SOC 2 Evidence Report/);
    assert.match(blobEntry.text, /SOC 2 Control Evidence/);
    assert.match(blobEntry.text, new RegExp(packet.task.att_tid));
    assert.match(blobEntry.text, new RegExp(packet.integrity.packet_hash));
  });
});

test('dashboard export packet downloads canonical evidence JSON', async (t) => {
  await withDashboard(t, null, async (page, packet) => {
    await page.getByRole('button', { name: /export packet/i }).click();

    await page.getByText('Evidence packet exported').waitFor();

    const downloadInfoHandle = await page.waitForFunction(() => window.__lastDownload);
    const downloadInfo = await downloadInfoHandle.jsonValue();
    const blobEntry = await page.evaluate(async (url) => window.__readBlobText(url), downloadInfo.url);

    assert.ok(blobEntry, 'expected a captured evidence blob');
    assert.equal(blobEntry.type, 'application/json');
    assert.equal(downloadInfo.filename, `attest-evidence-${packet.integrity.packet_hash.slice(0, 12)}.json`);

    const exportedPacket = JSON.parse(blobEntry.text);
    assert.equal(exportedPacket.task.att_tid, packet.task.att_tid);
    assert.equal(exportedPacket.integrity.packet_hash, packet.integrity.packet_hash);
    assert.equal(exportedPacket.integrity.signature_algorithm, 'RS256');
  });
});
