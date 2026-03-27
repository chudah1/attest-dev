import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const fixtureDir = path.resolve(__dirname, '../../../testdata/evidence');

const { AttestClient } = await import('../dist/index.js');

async function loadFixture(name) {
  const raw = await fs.readFile(path.join(fixtureDir, name), 'utf8');
  return JSON.parse(raw);
}

test('verifyEvidencePacket accepts the signed fixture packet', async () => {
  const packet = await loadFixture('packet.json');
  const jwks = await loadFixture('jwks.json');

  const client = new AttestClient({ baseUrl: 'https://api.attestdev.com', apiKey: 'att_live_fixture' });
  const result = await client.verifyEvidencePacket(packet, jwks);

  assert.equal(result.valid, true);
  assert.equal(result.hashValid, true);
  assert.equal(result.signatureValid, true);
  assert.equal(result.auditChainValid, true);
  assert.deepEqual(result.warnings, []);
});

test('verifyEvidencePacket rejects a tampered packet body', async () => {
  const packet = await loadFixture('packet.json');
  const jwks = await loadFixture('jwks.json');
  packet.summary.result = 'revoked';

  const client = new AttestClient({ baseUrl: 'https://api.attestdev.com', apiKey: 'att_live_fixture' });
  const result = await client.verifyEvidencePacket(packet, jwks);

  assert.equal(result.valid, false);
  assert.equal(result.hashValid, false);
  assert.equal(result.signatureValid, false);
  assert.match(result.warnings.join('\n'), /packet hash mismatch/);
});

test('verifyEvidencePacket rejects a broken audit chain', async () => {
  const packet = await loadFixture('packet.json');
  const jwks = await loadFixture('jwks.json');
  packet.events[1].prev_hash = 'deadbeef'.repeat(8);

  const client = new AttestClient({ baseUrl: 'https://api.attestdev.com', apiKey: 'att_live_fixture' });
  const result = await client.verifyEvidencePacket(packet, jwks);

  assert.equal(result.valid, false);
  assert.equal(result.auditChainValid, false);
  assert.match(result.warnings.join('\n'), /audit chain break/);
});
