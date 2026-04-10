import { useEffect, useMemo, useRef, useState } from 'react';

const API = import.meta.env.VITE_API_BASE_URL || 'https://api.attestdev.com';
const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';
const KEY_STORAGE = 'attest_key';
const SITE_URL_STORAGE = 'attest-site-url';
const IS_LOCAL_HOST =
  typeof window !== 'undefined' &&
  /^(localhost|127\.0\.0\.1)$/.test(window.location.hostname);
const SITE_OVERRIDE =
  typeof window !== 'undefined'
    ? new URLSearchParams(window.location.search).get('site_url') || window.localStorage.getItem(SITE_URL_STORAGE) || ''
    : '';
const SITE_BASE_URL = (SITE_OVERRIDE || import.meta.env.VITE_SITE_BASE_URL || (IS_LOCAL_HOST ? new URL('/docs', window.location.origin).toString() : 'https://attestdev.com')).replace(/\/$/, '');
const SITE_HOME_URL = `${SITE_BASE_URL}/`;
const SITE_DEMO_URL = `${SITE_BASE_URL}/demo/`;
const PAGES = [
  { key: 'overview', label: 'Overview', icon: '◉' },
  { key: 'audit', label: 'Audit Log', icon: '≡' },
  { key: 'revoke', label: 'Revoke', icon: '✕' },
  { key: 'settings', label: 'Settings', icon: '⚙' },
];

function pick(obj, lower, upper, fallback = '—') {
  return obj?.[lower] ?? obj?.[upper] ?? fallback;
}

function formatDate(value, mode = 'date') {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return mode === 'datetime' ? date.toLocaleString() : date.toLocaleDateString();
}

function maskKey(key) {
  if (!key) return '—';
  const parts = key.split('_');
  if (parts.length >= 3) return `${parts[0]}_${parts[1]}_${'•'.repeat(parts[2].length)}`;
  return '•'.repeat(key.length);
}

function shortValue(value, prefix = 14, suffix = 10) {
  if (!value) return '—';
  if (value.length <= prefix + suffix + 3) return value;
  return `${value.slice(0, prefix)}...${value.slice(-suffix)}`;
}

function resultClass(result) {
  switch ((result || '').toLowerCase()) {
    case 'revoked':
      return 'result-revoked';
    case 'expired':
      return 'result-expired';
    default:
      return 'result-active';
  }
}

function eventBadgeClass(eventType) {
  switch ((eventType || '').toLowerCase()) {
    case 'issued':
      return 'badge-issued';
    case 'delegated':
      return 'badge-delegated';
    case 'revoked':
      return 'badge-revoked';
    case 'action':
      return 'badge-action';
    default:
      return 'badge-lifecycle';
  }
}

function collectObservedScopes(credentials) {
  const seen = new Set();
  const scopes = [];
  for (const credential of credentials || []) {
    for (const scope of Array.isArray(credential.scope) ? credential.scope : []) {
      if (!seen.has(scope)) {
        seen.add(scope);
        scopes.push(scope);
      }
    }
  }
  return scopes;
}

function buildVerificationSnippets(packet) {
  const orgId = packet?.org?.id || 'org_id';
  const jwksUrl = `${API}/orgs/${orgId}/jwks.json`;
  return {
    jwksUrl,
    typescript: [
      "import { verifyEvidencePacket, loadJWKS } from '@attest-dev/sdk';",
      '',
      "const packet = JSON.parse(await Bun.file('packet.json').text());",
      `const jwks = await loadJWKS('${jwksUrl}');`,
      'const result = await verifyEvidencePacket(packet, jwks);',
      'console.log(result.valid);',
    ].join('\n'),
    python: [
      'from attest import verify_evidence_packet, load_jwks',
      'import json',
      '',
      "with open('packet.json') as f:",
      '    packet = json.load(f)',
      '',
      `jwks = load_jwks('${jwksUrl}')`,
      'result = verify_evidence_packet(packet, jwks)',
      'print(result.valid)',
    ].join('\n'),
  };
}

async function sha256Hex(bytes) {
  const digest = await window.crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

function decodeBase64Url(value) {
  const normalized = String(value).replaceAll('-', '+').replaceAll('_', '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  const raw = atob(padded);
  return Uint8Array.from(raw, (char) => char.charCodeAt(0));
}

function canonicalizeEvidencePacket(packet) {
  const clone = JSON.parse(JSON.stringify(packet || {}));
  const integrity = clone.integrity || {};
  clone.integrity = integrity;
  integrity.packet_hash = '';
  delete integrity.signature_algorithm;
  delete integrity.signature_kid;
  delete integrity.packet_signature;
  return JSON.stringify(clone);
}

function validateAuditEvents(events) {
  const warnings = [];
  if (!Array.isArray(events) || events.length === 0) return warnings;
  if ((events[0]?.prev_hash || '') !== GENESIS_HASH) {
    warnings.push('first audit event does not use the genesis previous hash');
  }
  for (let i = 1; i < events.length; i += 1) {
    const prev = events[i - 1];
    const current = events[i];
    if (prev && current && current.prev_hash !== prev.entry_hash) {
      warnings.push(`audit chain break between event ${prev.id ?? i} and ${current.id ?? i + 1}`);
    }
  }
  return warnings;
}

async function verifyEvidencePacketInBrowser(packet, jwks) {
  const canonicalJson = canonicalizeEvidencePacket(packet);
  const encoded = new TextEncoder().encode(canonicalJson);
  const computedHash = await sha256Hex(encoded);
  const hashValid = computedHash === (packet.integrity?.packet_hash || '');
  const warnings = [];

  if (!hashValid) {
    warnings.push(`packet hash mismatch: expected ${packet.integrity?.packet_hash || '—'}, computed ${computedHash}`);
  }

  let signatureValid = false;
  const signatureAlgorithm = packet.integrity?.signature_algorithm;
  const signatureKid = packet.integrity?.signature_kid;
  const packetSignature = packet.integrity?.packet_signature;

  if (!signatureAlgorithm || !signatureKid || !packetSignature) {
    warnings.push('packet signature metadata missing');
  } else if (signatureAlgorithm !== 'RS256') {
    warnings.push(`unsupported signature algorithm: ${signatureAlgorithm}`);
  } else {
    const jwk = (jwks.keys || []).find((key) => key.kid === signatureKid) || (jwks.keys || [])[0];
    if (!jwk) {
      warnings.push('no verification key found in JWKS');
    } else {
      try {
        const key = await window.crypto.subtle.importKey(
          'jwk',
          jwk,
          { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
          false,
          ['verify'],
        );
        signatureValid = await window.crypto.subtle.verify(
          { name: 'RSASSA-PKCS1-v1_5' },
          key,
          decodeBase64Url(packetSignature),
          encoded,
        );
        if (!signatureValid) warnings.push('packet signature verification failed');
      } catch (error) {
        warnings.push(`packet signature verification failed: ${String(error)}`);
      }
    }
  }

  const auditWarnings = validateAuditEvents(packet.events || []);
  warnings.push(...auditWarnings);
  const auditChainValid = Boolean(packet.integrity?.audit_chain_valid) && auditWarnings.length === 0;
  if (!packet.integrity?.audit_chain_valid && auditWarnings.length === 0) {
    warnings.push('packet reports invalid audit chain');
  }

  return {
    status: hashValid && signatureValid && auditChainValid ? 'success' : 'error',
    valid: hashValid && signatureValid && auditChainValid,
    hashValid,
    signatureValid,
    auditChainValid,
    warnings,
  };
}

async function parseJSONOrError(res) {
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.error || `Request failed: HTTP ${res.status}`);
  }
  return data;
}

function copyText(value, onDone) {
  navigator.clipboard.writeText(value).then(onDone);
}

function downloadBlob(name, blob) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function App() {
  const [page, setPage] = useState('overview');
  const [apiKey, setApiKey] = useState('');
  const [org, setOrg] = useState(null);
  const [loginKey, setLoginKey] = useState('');
  const [loginError, setLoginError] = useState('');
  const [authLoading, setAuthLoading] = useState(true);
  const [loginPending, setLoginPending] = useState(false);
  const [showKey, setShowKey] = useState(false);
  const [toast, setToast] = useState(null);
  const [taskId, setTaskId] = useState('');
  const [reportTemplate, setReportTemplate] = useState('audit');
  const [auditLoading, setAuditLoading] = useState(false);
  const [auditError, setAuditError] = useState('');
  const [auditTaskId, setAuditTaskId] = useState('');
  const [auditEvents, setAuditEvents] = useState([]);
  const [evidencePacket, setEvidencePacket] = useState(null);
  const [evidenceVerification, setEvidenceVerification] = useState(null);
  const [revokeJti, setRevokeJti] = useState('');
  const [revokeBy, setRevokeBy] = useState('');
  const [taskList, setTaskList] = useState([]);
  const [taskListLoading, setTaskListLoading] = useState(false);
  const [taskListError, setTaskListError] = useState('');
  const [taskListFilters, setTaskListFilters] = useState({
    userId: '',
    agentId: '',
    status: 'all',
  });
  const toastTimer = useRef(null);

  useEffect(() => {
    const saved = localStorage.getItem(KEY_STORAGE);
    if (!saved) {
      setAuthLoading(false);
      return;
    }

    let active = true;
    loadOrg(saved)
      .then((data) => {
        if (!active) return;
        setApiKey(saved);
        setOrg(data);
      })
      .catch(() => {
        if (!active) return;
        localStorage.removeItem(KEY_STORAGE);
      })
      .finally(() => {
        if (active) setAuthLoading(false);
      });

    return () => {
      active = false;
    };
  }, []);

  useEffect(() => () => {
    if (toastTimer.current) clearTimeout(toastTimer.current);
  }, []);

  const showToast = (message, type = 'success') => {
    if (toastTimer.current) clearTimeout(toastTimer.current);
    setToast({ message, type });
    toastTimer.current = setTimeout(() => setToast(null), 3000);
  };

  async function loadOrg(key) {
    const res = await fetch(`${API}/v1/org`, {
      headers: { Authorization: `Bearer ${key}` },
    });
    return parseJSONOrError(res);
  }

  async function fetchTaskList(filters = taskListFilters) {
    if (!apiKey) return;

    setTaskListLoading(true);
    setTaskListError('');

    try {
      const params = new URLSearchParams({ limit: '12' });
      if (filters.userId.trim()) params.set('user_id', filters.userId.trim());
      if (filters.agentId.trim()) params.set('agent_id', filters.agentId.trim());
      if (filters.status && filters.status !== 'all') params.set('status', filters.status);

      const res = await fetch(`${API}/v1/tasks?${params.toString()}`, {
        headers: { Authorization: `Bearer ${apiKey}` },
      });
      const data = await parseJSONOrError(res);
      setTaskList(Array.isArray(data) ? data : []);
    } catch (error) {
      setTaskList([]);
      setTaskListError(error.message || 'Failed to load recent tasks.');
    } finally {
      setTaskListLoading(false);
    }
  }

  const orgView = useMemo(() => {
    if (!org) return null;
    return {
      name: pick(org, 'name', 'Name'),
      id: pick(org, 'id', 'ID'),
      status: pick(org, 'status', 'Status', 'active'),
      createdAt: pick(org, 'created_at', 'CreatedAt', ''),
    };
  }, [org]);

  async function handleLogin(event) {
    event?.preventDefault();
    const key = loginKey.trim();
    if (!key) return;

    setLoginPending(true);
    setLoginError('');
    try {
      const data = await loadOrg(key);
      localStorage.setItem(KEY_STORAGE, key);
      setApiKey(key);
      setOrg(data);
      setLoginKey('');
      setPage('overview');
    } catch {
      setLoginError('Invalid access key. Please try again.');
    } finally {
      setLoginPending(false);
    }
  }

  function handleLogout() {
    localStorage.removeItem(KEY_STORAGE);
    setApiKey('');
    setOrg(null);
    setShowKey(false);
    setAuditTaskId('');
    setAuditEvents([]);
    setEvidencePacket(null);
    setEvidenceVerification(null);
    setAuditError('');
    setTaskId('');
    setTaskList([]);
    setTaskListError('');
  }

  useEffect(() => {
    if (!apiKey) return;
    fetchTaskList();
  }, [apiKey]);

  async function fetchAudit(targetTaskId = taskId.trim()) {
    if (!targetTaskId) return;

    setAuditLoading(true);
    setAuditError('');
    setEvidenceVerification(null);

    try {
      const auditRes = await fetch(`${API}/v1/tasks/${encodeURIComponent(targetTaskId)}/audit`, {
        headers: { Authorization: `Bearer ${apiKey}` },
      });
      const events = await parseJSONOrError(auditRes);
      if (!Array.isArray(events) || events.length === 0) {
        setAuditTaskId(targetTaskId);
        setAuditEvents([]);
        setEvidencePacket(null);
        setAuditError('No events found for this task tree.');
        return;
      }

      setAuditTaskId(targetTaskId);
      setAuditEvents(events);

      try {
        const evidenceRes = await fetch(`${API}/v1/tasks/${encodeURIComponent(targetTaskId)}/evidence`, {
          headers: { Authorization: `Bearer ${apiKey}` },
        });
        if (evidenceRes.ok) {
          setEvidencePacket(await evidenceRes.json());
        } else {
          setEvidencePacket(null);
        }
      } catch {
        setEvidencePacket(null);
      }
    } catch (error) {
      setAuditTaskId(targetTaskId);
      setAuditEvents([]);
      setEvidencePacket(null);
      setAuditError(error.message || 'Failed to load evidence events.');
    } finally {
      setAuditLoading(false);
    }
  }

  async function ensureEvidencePacket(targetTaskId) {
    if (evidencePacket && auditTaskId === targetTaskId) return evidencePacket;

    const res = await fetch(`${API}/v1/tasks/${encodeURIComponent(targetTaskId)}/evidence`, {
      headers: { Authorization: `Bearer ${apiKey}` },
    });
    const packet = await parseJSONOrError(res);
    setEvidencePacket(packet);
    setAuditTaskId(targetTaskId);
    return packet;
  }

  async function handleVerifyOnSite() {
    const targetTaskId = taskId.trim();
    if (!targetTaskId) {
      showToast('Enter a task ID first', 'error');
      return;
    }

    try {
      if (auditTaskId !== targetTaskId || !auditEvents.length) {
        await fetchAudit(targetTaskId);
      }

      const packet = await ensureEvidencePacket(targetTaskId);
      if (!packet?.org?.id) {
        showToast('Packet is missing org metadata', 'error');
        return;
      }
      if (!window.crypto?.subtle) {
        showToast('This browser cannot verify signatures with Web Crypto', 'error');
        return;
      }

      const jwksRes = await fetch(`${API}/orgs/${encodeURIComponent(packet.org.id)}/jwks.json`);
      if (!jwksRes.ok) {
        showToast(`Failed to load JWKS: HTTP ${jwksRes.status}`, 'error');
        return;
      }

      const jwks = await jwksRes.json();
      const result = await verifyEvidencePacketInBrowser(packet, jwks);
      setEvidenceVerification(result);
      showToast(result.valid ? 'Packet verified on site' : 'Verification found issues', result.valid ? 'success' : 'error');
    } catch (error) {
      setEvidenceVerification({
        status: 'error',
        hashValid: false,
        signatureValid: false,
        auditChainValid: false,
        warnings: [error.message || 'Unexpected verification failure in the browser'],
        valid: false,
      });
      showToast('Verification failed', 'error');
    }
  }

  async function handleDownloadEvidence() {
    const targetTaskId = taskId.trim();
    if (!targetTaskId) {
      showToast('Enter a task ID first', 'error');
      return;
    }
    try {
      const packet = await ensureEvidencePacket(targetTaskId);
      const packetHash = packet.integrity?.packet_hash || targetTaskId;
      downloadBlob(`attest-evidence-${String(packetHash).slice(0, 12)}.json`, new Blob([JSON.stringify(packet, null, 2)], { type: 'application/json' }));
      showToast('Evidence packet exported', 'success');
    } catch (error) {
      showToast(error.message || 'Evidence export failed', 'error');
    }
  }

  async function handleOpenReport(mode = 'view') {
    const targetTaskId = taskId.trim();
    if (!targetTaskId) {
      showToast('Enter a task ID first', 'error');
      return;
    }
    try {
      const reportUrl = `${API}/v1/tasks/${encodeURIComponent(targetTaskId)}/report?template=${encodeURIComponent(reportTemplate)}${mode === 'print' ? '&mode=print' : ''}`;
      const res = await fetch(reportUrl, {
        headers: { Authorization: `Bearer ${apiKey}` },
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error || 'Report generation failed');
      }
      const html = await res.text();
      const blob = new Blob([html], { type: 'text/html' });
      const url = URL.createObjectURL(blob);
      window.open(url, '_blank', 'noopener,noreferrer');
      setTimeout(() => URL.revokeObjectURL(url), 60_000);
      showToast(mode === 'print' ? 'Print-friendly report opened' : 'Evidence report opened', 'success');
    } catch (error) {
      showToast(error.message || 'Network error', 'error');
    }
  }

  async function handleRevoke() {
    if (!revokeJti.trim()) return;
    try {
      const res = await fetch(`${API}/v1/credentials/${encodeURIComponent(revokeJti.trim())}`, {
        method: 'DELETE',
        headers: {
          Authorization: `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ revoked_by: revokeBy.trim() || 'dashboard' }),
      });
      if (res.status !== 204) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error || 'Revocation failed');
      }
      setRevokeJti('');
      setRevokeBy('');
      fetchTaskList();
      showToast('Credential revoked', 'success');
    } catch (error) {
      showToast(error.message || 'Network error', 'error');
    }
  }

  function handleOpenTask(taskSummary) {
    const targetTaskId = taskSummary?.att_tid || taskSummary?.task_id || taskSummary?.taskId || '';
    if (!targetTaskId) return;
    setTaskId(targetTaskId);
    setPage('audit');
    fetchAudit(targetTaskId);
  }

  function copyVerificationValue(kind) {
    if (!evidencePacket) {
      showToast('Load an evidence packet first', 'error');
      return;
    }
    const snippets = buildVerificationSnippets(evidencePacket);
    const value = kind === 'typescript' ? snippets.typescript : kind === 'python' ? snippets.python : snippets.jwksUrl;
    const label = kind === 'typescript'
      ? 'TypeScript verify snippet copied'
      : kind === 'python'
        ? 'Python verify snippet copied'
        : 'JWKS URL copied';
    copyText(value, () => showToast(label, 'success'));
  }

  if (authLoading) {
    return <div className="loading-shell">Loading dashboard…</div>;
  }

  if (!orgView || !apiKey) {
    return (
      <div className="login-screen">
        <form className="login-card" onSubmit={handleLogin}>
          <div className="logo">Attest<span>.</span></div>
          <p>Sign in with your org access key to inspect task trees, audit trails, and revocations.</p>
          <label htmlFor="api-key-input">Access key</label>
          <input
            id="api-key-input"
            type="password"
            placeholder="att_live_..."
            autoComplete="off"
            value={loginKey}
            onChange={(event) => setLoginKey(event.target.value)}
          />
          {loginError ? <div className="error-msg shown">{loginError}</div> : null}
          <button className="btn btn-primary" type="submit" disabled={loginPending}>
            {loginPending ? 'Verifying…' : 'Continue'}
          </button>
        </form>
      </div>
    );
  }

  const verificationSnippets = evidencePacket ? buildVerificationSnippets(evidencePacket) : null;

  return (
    <>
      <nav className="top-nav">
        <div className="nav-brand">
          <div className="nav-logo">Attest<span>.</span></div>
          <div className="nav-context">Dashboard</div>
        </div>
        <div className="nav-right">
          <div className="org-chip">Workspace: <strong>{orgView.name}</strong></div>
          <a className="btn btn-ghost btn-sm" href={SITE_HOME_URL} target="_blank" rel="noreferrer">Site</a>
          <button className="btn btn-ghost btn-sm" type="button" onClick={handleLogout}>Sign out</button>
        </div>
      </nav>

      <div className="layout">
        <aside className="sidebar">
          {PAGES.map((item) => (
            <button
              key={item.key}
              className={`sidebar-item ${page === item.key ? 'active' : ''}`}
              type="button"
              onClick={() => setPage(item.key)}
            >
              <span className="icon">{item.icon}</span>
              {item.label}
            </button>
          ))}
        </aside>

        <main className="content">
          {page === 'overview' ? (
            <OverviewPage
              org={orgView}
              apiKey={apiKey}
              showKey={showKey}
              setShowKey={setShowKey}
              taskList={taskList}
              taskListLoading={taskListLoading}
              taskListError={taskListError}
              taskListFilters={taskListFilters}
              setTaskListFilters={setTaskListFilters}
              onRefreshTasks={() => fetchTaskList()}
              onOpenTask={handleOpenTask}
              onCopyKey={() => copyText(apiKey, () => showToast('Access key copied', 'success'))}
              onGoAudit={() => setPage('audit')}
              onGoRevoke={() => setPage('revoke')}
            />
          ) : null}

          {page === 'audit' ? (
            <AuditPage
              taskId={taskId}
              setTaskId={setTaskId}
              reportTemplate={reportTemplate}
              setReportTemplate={setReportTemplate}
              auditLoading={auditLoading}
              auditError={auditError}
              auditEvents={auditEvents}
              evidencePacket={evidencePacket}
              evidenceVerification={evidenceVerification}
              verificationSnippets={verificationSnippets}
              taskList={taskList}
              taskListLoading={taskListLoading}
              taskListError={taskListError}
              taskListFilters={taskListFilters}
              setTaskListFilters={setTaskListFilters}
              onRefreshTasks={() => fetchTaskList()}
              onOpenTask={handleOpenTask}
              onSearch={() => fetchAudit()}
              onVerify={handleVerifyOnSite}
              onOpenReport={() => handleOpenReport('view')}
              onPrint={() => handleOpenReport('print')}
              onExport={handleDownloadEvidence}
              onCopyVerification={copyVerificationValue}
            />
          ) : null}

          {page === 'revoke' ? (
            <RevokePage
              revokeJti={revokeJti}
              revokeBy={revokeBy}
              setRevokeJti={setRevokeJti}
              setRevokeBy={setRevokeBy}
              onRevoke={handleRevoke}
            />
          ) : null}

          {page === 'settings' ? (
            <SettingsPage org={orgView} />
          ) : null}
        </main>
      </div>

      {toast ? <div className={`toast show ${toast.type}`}>{toast.message}</div> : null}
    </>
  );
}

function OverviewPage({
  org,
  apiKey,
  showKey,
  setShowKey,
  taskList,
  taskListLoading,
  taskListError,
  taskListFilters,
  setTaskListFilters,
  onRefreshTasks,
  onOpenTask,
  onCopyKey,
  onGoAudit,
  onGoRevoke,
}) {
  return (
    <section className="page-section">
      <div className="page-header">
        <div className="page-kicker">Workspace control plane</div>
        <div className="page-title">Overview</div>
        <div className="page-subtitle">Manage delegated authority for this workspace. Review active credentials, inspect evidence, and revoke a task tree when needed.</div>
      </div>

      <div className="hero-shell overview-hero">
        <div className="hero-card-main">
          <div className="hero-card-label">Control posture</div>
          <h2 className="hero-card-title">Keep agent authority readable, narrow, and easy to shut down.</h2>
          <p className="hero-card-copy">
            This dashboard is the operator surface for Attest. Look up a task tree, inspect the evidence packet, verify it in-browser, and revoke the full chain when something should stop immediately.
          </p>
          <div className="hero-card-pills">
            <span className="hero-pill">Signed evidence</span>
            <span className="hero-pill">Delegation history</span>
            <span className="hero-pill">On-site verification</span>
            <span className="hero-pill">Cascade revoke</span>
          </div>
          <div className="hero-action-grid">
            <button className="action-tile" type="button" onClick={onGoAudit}>
              <span className="action-tile-kicker">Review</span>
              <strong>Inspect task tree</strong>
              <span>Search a task ID, load the packet, and check the full authority timeline.</span>
            </button>
            <button className="action-tile" type="button" onClick={onGoRevoke}>
              <span className="action-tile-kicker">Contain</span>
              <strong>Revoke chain</strong>
              <span>Invalidate a credential and its descendants from one operator action.</span>
            </button>
            <a className="action-tile" href={SITE_DEMO_URL}>
              <span className="action-tile-kicker">Walkthrough</span>
              <strong>Open demo</strong>
              <span>Show the before-and-after failure mode for compromised orchestrators.</span>
            </a>
          </div>
        </div>

        <div className="hero-rail">
          <div className="rail-panel">
            <div className="card-title">Workspace snapshot</div>
            <div className="mini-stat-grid">
              <div className="mini-stat">
                <span className="stat-label">Authority state</span>
                <strong className="stat-value green">Active</strong>
              </div>
              <div className="mini-stat">
                <span className="stat-label">Workspace ID</span>
                <strong className="mono-inline">{shortValue(org.id, 10, 8)}</strong>
              </div>
              <div className="mini-stat">
                <span className="stat-label">Provisioned</span>
                <strong>{formatDate(org.createdAt)}</strong>
              </div>
              <div className="mini-stat">
                <span className="stat-label">Surface</span>
                <strong>Audit-ready</strong>
              </div>
            </div>
          </div>

          <div className="rail-panel">
            <div className="card-title">Operator notes</div>
            <div className="rail-list">
              <div className="rail-list-item">Use the audit view when you need the full event stream, packet hash, and report exports in one place.</div>
              <div className="rail-list-item">Use revoke when a root credential should shut down the whole descendant tree immediately.</div>
              <div className="rail-list-item">The public verifier and print report stay in sync with what you see here.</div>
            </div>
          </div>
        </div>
      </div>

      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-label">Authority state</div>
          <div className="stat-value green">Active</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Workspace ID</div>
          <div className="stat-value mono-inline">{org.id}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Provisioned</div>
          <div className="stat-value date">{formatDate(org.createdAt)}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Control surface</div>
          <div className="stat-value">Ready</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Recent task trees</div>
          <div className="stat-value">{taskList.length}</div>
        </div>
      </div>

      <div className="overview-grid">
        <div className="card">
          <div className="card-title">Access key</div>
          <div className="key-row">
            <div className="key-display">{showKey ? apiKey : maskKey(apiKey)}</div>
            <button className="btn btn-ghost btn-sm" type="button" onClick={() => setShowKey((current) => !current)}>{showKey ? 'Hide' : 'Show'}</button>
            <button className="btn btn-ghost btn-sm" type="button" onClick={onCopyKey}>Copy</button>
          </div>
        </div>

        <div className="card">
          <div className="card-title">Quick actions</div>
          <div className="quick-actions">
            <button className="btn btn-ghost btn-sm" type="button" onClick={onGoAudit}>Inspect task tree</button>
            <button className="btn btn-ghost btn-sm" type="button" onClick={onGoRevoke}>Revoke chain</button>
            <a className="btn btn-ghost btn-sm" href={SITE_DEMO_URL}>Open demo</a>
          </div>
          <p className="inline-note">Best next move: load a real task ID and verify the evidence packet in-browser before you share it.</p>
        </div>
      </div>

      <TaskInboxCard
        title="Recent task trees"
        subtitle="Recover recent work by user, agent, or revocation state without needing the original att_tid."
        tasks={taskList}
        loading={taskListLoading}
        error={taskListError}
        filters={taskListFilters}
        onChangeFilters={setTaskListFilters}
        onRefresh={onRefreshTasks}
        onOpenTask={onOpenTask}
      />
    </section>
  );
}

function AuditPage({
  taskId,
  setTaskId,
  reportTemplate,
  setReportTemplate,
  auditLoading,
  auditError,
  auditEvents,
  evidencePacket,
  evidenceVerification,
  verificationSnippets,
  taskList,
  taskListLoading,
  taskListError,
  taskListFilters,
  setTaskListFilters,
  onRefreshTasks,
  onOpenTask,
  onSearch,
  onVerify,
  onOpenReport,
  onPrint,
  onExport,
  onCopyVerification,
}) {
  const summary = evidencePacket?.summary || {};
  const task = evidencePacket?.task || {};
  const integrity = evidencePacket?.integrity || {};
  const credentials = evidencePacket?.credentials || [];
  const identity = evidencePacket?.identity || {};
  const observedScopes = collectObservedScopes(credentials);
  const eventCount = task.event_count || auditEvents.length || 0;
  const lastEvent = auditEvents[auditEvents.length - 1];

  return (
    <section className="page-section">
      <div className="page-header">
        <div className="page-kicker">Evidence review</div>
        <div className="page-title">Audit Log</div>
        <div className="page-subtitle">Look up a task tree by `att_tid` and review the sequence of issued, delegated, and revoked events that prove authority.</div>
      </div>

      <div className="audit-hero">
        <div className="hero-card-main">
          <div className="hero-card-label">Current workflow</div>
          <h2 className="hero-card-title">Move from task ID to proof without leaving the dashboard.</h2>
          <p className="hero-card-copy">
            Search the task tree, load the signed packet, verify it on site, then open a readable report or export the canonical JSON artifact.
          </p>
          <div className="hero-card-pills">
            <span className="hero-pill">Hash + signature</span>
            <span className="hero-pill">Audit chain</span>
            <span className="hero-pill">Report export</span>
            <span className="hero-pill">Print-ready</span>
          </div>
        </div>
        <div className="hero-rail">
          <div className="rail-panel">
            <div className="card-title">Loaded task</div>
            <div className="mini-stat-grid">
              <div className="mini-stat">
                <span className="stat-label">Task ID</span>
                <strong className="mono-inline">{task.att_tid ? shortValue(task.att_tid, 10, 8) : '—'}</strong>
              </div>
              <div className="mini-stat">
                <span className="stat-label">Status</span>
                <strong>{summary.result || 'Not loaded'}</strong>
              </div>
              <div className="mini-stat">
                <span className="stat-label">Events</span>
                <strong>{eventCount}</strong>
              </div>
              <div className="mini-stat">
                <span className="stat-label">Integrity</span>
                <strong>{evidencePacket ? (integrity.audit_chain_valid ? 'Valid' : 'Check packet') : 'Pending'}</strong>
              </div>
            </div>
          </div>
        </div>
      </div>

      <TaskInboxCard
        title="Recent workspace tasks"
        subtitle="Pick a recent task tree and jump straight into its packet, report, and timeline."
        tasks={taskList}
        loading={taskListLoading}
        error={taskListError}
        filters={taskListFilters}
        onChangeFilters={setTaskListFilters}
        onRefresh={onRefreshTasks}
        onOpenTask={onOpenTask}
        compact
      />

      <div className="card">
        <div className="search-row">
          <div className="search-input-shell">
            <div className="search-input-label">Task tree</div>
            <input
              id="task-id-input"
              type="search"
              value={taskId}
              onChange={(event) => setTaskId(event.target.value)}
              placeholder="Paste `att_tid` from a credential or evidence packet"
              onKeyDown={(event) => {
                if (event.key === 'Enter') onSearch();
              }}
            />
          </div>
          <div className="toolbar-field">
            <div className="toolbar-label">Report view</div>
            <select id="report-template-select" value={reportTemplate} onChange={(event) => setReportTemplate(event.target.value)}>
              <option value="audit">Audit report</option>
              <option value="soc2">SOC 2 report</option>
              <option value="incident">Incident report</option>
            </select>
          </div>
        </div>

        <div className="toolbar-actions">
          <button className="btn btn-toolbar-primary" type="button" onClick={onSearch}>
            <span className="btn-mark">≡</span>
            <span className="btn-text"><small>Timeline</small><span>{auditLoading ? 'Loading…' : 'Search events'}</span></span>
          </button>
          <button className="btn btn-toolbar-secondary" type="button" onClick={onVerify}>
            <span className="btn-mark">✓</span>
            <span className="btn-text"><small>On-site</small><span>Verify packet</span></span>
          </button>
          <button className="btn btn-toolbar-secondary" type="button" onClick={onOpenReport}>
            <span className="btn-mark">↗</span>
            <span className="btn-text"><small>Readable</small><span>Open report</span></span>
          </button>
          <button className="btn btn-toolbar-secondary" type="button" onClick={onPrint}>
            <span className="btn-mark">⎙</span>
            <span className="btn-text"><small>PDF-ready</small><span>Print report</span></span>
          </button>
          <button className="btn btn-toolbar-tertiary" type="button" onClick={onExport}>
            <span className="btn-mark">↓</span>
            <span className="btn-text"><small>Canonical</small><span>Export packet</span></span>
          </button>
        </div>

        <div className="audit-results">
          {auditLoading ? <div className="empty">Loading…</div> : null}
          {!auditLoading && auditError ? <div className="empty">{auditError}</div> : null}
          {!auditLoading && !auditError && !auditEvents.length ? <div className="empty">Enter a task ID to view its evidence trail.</div> : null}

          {!auditLoading && !auditError && auditEvents.length ? (
            <div className="audit-stack">
              {evidencePacket ? (
                <div className="evidence-preview">
                  <div className="results-divider">Task summary</div>
                  <div className="evidence-summary-grid">
                    <div className="evidence-summary-card">
                      <div className="label">Task status</div>
                      <div className="value"><span className={`result-pill ${resultClass(summary.result)}`}>{summary.result || 'active'}</span></div>
                    </div>
                    <div className="evidence-summary-card">
                      <div className="label">Authority tree</div>
                      <div className="value">{task.credential_count || credentials.length} credential{(task.credential_count || credentials.length) === 1 ? '' : 's'}</div>
                    </div>
                    <div className="evidence-summary-card">
                      <div className="label">Runtime events</div>
                      <div className="value">{eventCount} event{eventCount === 1 ? '' : 's'}</div>
                    </div>
                    <div className="evidence-summary-card">
                      <div className="label">Integrity</div>
                      <div className="value">{integrity.audit_chain_valid ? 'Audit chain valid' : 'Audit chain invalid'}</div>
                    </div>
                  </div>

                  <div className="evidence-detail-card">
                    <div>
                      <div className="detail-section-title">Evidence packet</div>
                      <div className="detail-grid">
                        <DetailItem label="Task ID" value={task.att_tid} mono />
                        <DetailItem label="Root credential" value={task.root_jti} mono />
                        <DetailItem label="Original user" value={identity.user_id || task.att_uid} mono />
                        <DetailItem label="Packet hash" value={shortValue(integrity.packet_hash)} title={integrity.packet_hash} mono />
                        <DetailItem label="Instruction hash" value={shortValue(task.instruction_hash)} title={task.instruction_hash} mono />
                        <DetailItem label="Last activity" value={lastEvent?.created_at ? new Date(lastEvent.created_at).toLocaleString() : '—'} />
                      </div>
                    </div>
                    <div>
                      <div className="detail-section-title">Observed scopes</div>
                      <div className="scope-list">
                        {observedScopes.length ? observedScopes.map((scope) => <span key={scope} className="scope-chip">{scope}</span>) : <span className="scope-chip">No scope captured</span>}
                      </div>
                      <div className="side-detail-grid">
                        <DetailItem label="Root agent" value={task.root_agent_id || '—'} />
                        <DetailItem label="Report view" value={reportTemplate === 'soc2' ? 'SOC 2 report' : reportTemplate === 'incident' ? 'Incident report' : 'Audit report'} />
                      </div>
                      <div className="preview-note">
                        {summary.scope_violations || summary.revocations || summary.approvals
                          ? `${summary.scope_violations || 0} scope violation(s), ${summary.approvals || 0} approval-linked event(s), and ${summary.revocations || 0} revocation event(s) are present in this packet.`
                          : 'This task is clean so far: no scope violations, approval interruptions, or revocations are present in the current packet.'}
                      </div>
                    </div>
                  </div>

                  <VerificationPanel
                    packet={evidencePacket}
                    verification={evidenceVerification}
                    snippets={verificationSnippets}
                    onCopyVerification={onCopyVerification}
                  />
                </div>
              ) : null}

              <div className="timeline-shell">
                <div className="timeline-header">
                  <div className="timeline-title">Authority timeline</div>
                  <div className="timeline-meta">{auditEvents.length} recorded event{auditEvents.length === 1 ? '' : 's'}</div>
                </div>
                <table className="audit-table">
                  <thead>
                    <tr>
                      <th>Event</th>
                      <th>JTI</th>
                      <th>Agent</th>
                      <th>User</th>
                      <th>Scope</th>
                      <th>Time</th>
                    </tr>
                  </thead>
                  <tbody>
                    {auditEvents.map((event, index) => (
                      <tr key={`${event.id || event.entry_hash || event.created_at || index}`}>
                        <td><span className={`event-badge ${eventBadgeClass(event.event_type)}`}>{event.event_type || 'event'}</span></td>
                        <td className="mono">{event.jti ? `${event.jti.slice(0, 8)}…` : '—'}</td>
                        <td>{event.agent_id || '—'}</td>
                        <td>{event.user_id || '—'}</td>
                        <td className="mono">{Array.isArray(event.scope) && event.scope.length ? event.scope.join(', ') : '—'}</td>
                        <td className="muted">{event.created_at ? new Date(event.created_at).toLocaleTimeString() : '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </section>
  );
}

function TaskInboxCard({
  title,
  subtitle,
  tasks,
  loading,
  error,
  filters,
  onChangeFilters,
  onRefresh,
  onOpenTask,
  compact = false,
}) {
  return (
    <section className={`card task-inbox-card${compact ? ' compact' : ''}`}>
      <div className="task-inbox-head">
        <div>
          <div className="card-title">{title}</div>
          <div className="task-inbox-subtitle">{subtitle}</div>
        </div>
        <button className="btn btn-ghost btn-sm" type="button" onClick={onRefresh}>
          Refresh
        </button>
      </div>

      <div className="task-filter-row">
        <div className="toolbar-field">
          <div className="toolbar-label">User</div>
          <input
            type="search"
            value={filters.userId}
            placeholder="alice@example.com"
            onChange={(event) => onChangeFilters((current) => ({ ...current, userId: event.target.value }))}
            onKeyDown={(event) => {
              if (event.key === 'Enter') onRefresh();
            }}
          />
        </div>
        <div className="toolbar-field">
          <div className="toolbar-label">Agent</div>
          <input
            type="search"
            value={filters.agentId}
            placeholder="planner"
            onChange={(event) => onChangeFilters((current) => ({ ...current, agentId: event.target.value }))}
            onKeyDown={(event) => {
              if (event.key === 'Enter') onRefresh();
            }}
          />
        </div>
        <div className="toolbar-field">
          <div className="toolbar-label">Status</div>
          <select
            value={filters.status}
            onChange={(event) => onChangeFilters((current) => ({ ...current, status: event.target.value }))}
          >
            <option value="all">All tasks</option>
            <option value="active">Active</option>
            <option value="revoked">Revoked</option>
          </select>
        </div>
      </div>

      {loading ? <div className="empty">Loading recent tasks…</div> : null}
      {!loading && error ? <div className="empty">{error}</div> : null}
      {!loading && !error && !tasks.length ? <div className="empty">No task trees match the current filters.</div> : null}

      {!loading && !error && tasks.length ? (
        <div className="task-list">
          {tasks.map((task) => (
            <button key={task.att_tid} className="task-row" type="button" onClick={() => onOpenTask(task)}>
              <div className="task-row-main">
                <div className="task-row-topline">
                  <strong className="mono-inline">{shortValue(task.att_tid, 10, 8)}</strong>
                  <span className={`result-pill ${task.revoked ? 'result-revoked' : 'result-active'}`}>
                    {task.revoked ? 'revoked' : 'active'}
                  </span>
                </div>
                <div className="task-row-copy">
                  <span>User {task.att_uid || '—'}</span>
                  <span>Root agent {task.root_agent_id || '—'}</span>
                  <span>{task.event_count || 0} events</span>
                  <span>{task.credential_count || 0} credentials</span>
                </div>
              </div>
              <div className="task-row-meta">
                <span className="muted-text">{task.last_event_type || 'event'}</span>
                <span>{formatDate(task.last_event_at, 'datetime')}</span>
              </div>
            </button>
          ))}
        </div>
      ) : null}
    </section>
  );
}

function VerificationPanel({ packet, verification, snippets, onCopyVerification }) {
  const integrity = packet.integrity || {};
  const orgId = packet.org?.id || '—';
  const jwksUrl = `${API}/orgs/${orgId}/jwks.json`;
  const status = verification?.status || 'idle';
  const warnings = verification?.warnings || [];
  const statusLabel = status === 'success'
    ? 'Verified on site'
    : status === 'error'
      ? 'Verification failed'
      : 'Ready to verify';
  const verificationCopy = status === 'idle'
    ? 'Run verification here to validate the packet hash, RS256 signature, and append-only audit chain against your org JWKS without leaving the dashboard.'
    : status === 'success'
      ? 'This packet passed hash, signature, and audit-chain checks in the browser against the org JWKS.'
      : 'The packet did not pass one or more verification checks. Review the warnings below before sharing it externally.';

  return (
    <div className="verification-panel">
      <div className="verification-header">
        <div className="verification-title">Verification details</div>
        <div className={`verification-status ${status}`}>{statusLabel}</div>
      </div>

      <div className="verification-grid">
        <VerificationCheck
          label="Packet hash"
          value={status === 'idle' ? 'Not checked yet' : verification?.hashValid ? 'Matches canonical packet' : 'Hash mismatch detected'}
          state={status === 'idle' ? 'idle' : verification?.hashValid ? 'success' : 'error'}
        />
        <VerificationCheck
          label="Signature"
          value={status === 'idle' ? 'Not checked yet' : verification?.signatureValid ? 'RS256 signature valid' : 'Signature invalid or missing'}
          state={status === 'idle' ? 'idle' : verification?.signatureValid ? 'success' : 'error'}
        />
        <VerificationCheck
          label="Audit chain"
          value={status === 'idle' ? 'Not checked yet' : verification?.auditChainValid ? 'Append-only chain intact' : 'Audit chain inconsistency found'}
          state={status === 'idle' ? 'idle' : verification?.auditChainValid ? 'success' : 'error'}
        />
      </div>

      <div className="verification-meta">
        <DetailItem label="Signing key" value={shortValue(integrity.signature_kid || '—', 12, 8)} title={integrity.signature_kid} mono />
        <DetailItem label="Algorithm" value={integrity.signature_algorithm || '—'} />
        <DetailItem label="JWKS URL" value={shortValue(jwksUrl, 22, 18)} title={jwksUrl} mono />
      </div>

      <div className="verification-copy">{verificationCopy}</div>
      <div className="verification-actions">
        <div className="verification-action-row">
          <button className="verification-action-btn" type="button" onClick={() => onCopyVerification('jwks')}>Copy <code>JWKS URL</code></button>
          <button className="verification-action-btn" type="button" onClick={() => onCopyVerification('typescript')}>Copy <code>TypeScript</code> snippet</button>
          <button className="verification-action-btn" type="button" onClick={() => onCopyVerification('python')}>Copy <code>Python</code> snippet</button>
        </div>
        <div className="verification-snippet">
          <div className="verification-snippet-head">
            <div className="verification-snippet-label">TypeScript verify snippet</div>
            <button className="verification-copy-btn" type="button" onClick={() => onCopyVerification('typescript')}>Copy</button>
          </div>
          <pre>{snippets?.typescript}</pre>
        </div>
        <div className="verification-snippet">
          <div className="verification-snippet-head">
            <div className="verification-snippet-label">Python verify snippet</div>
            <button className="verification-copy-btn" type="button" onClick={() => onCopyVerification('python')}>Copy</button>
          </div>
          <pre>{snippets?.python}</pre>
        </div>
      </div>
      {warnings.length ? (
        <ul className="verification-warning-list">
          {warnings.map((warning) => <li key={warning}>{warning}</li>)}
        </ul>
      ) : null}
    </div>
  );
}

function VerificationCheck({ label, value, state }) {
  return (
    <div className={`verification-check ${state === 'error' ? 'error' : state === 'success' ? 'success' : ''}`}>
      <div className="label">{label}</div>
      <div className="value">{value}</div>
    </div>
  );
}

function DetailItem({ label, value, title, mono = false }) {
  return (
    <div className="detail-item" title={title || value || ''}>
      <div className="label">{label}</div>
      <div className={`value ${mono ? 'mono' : ''}`}>{value || '—'}</div>
    </div>
  );
}

function RevokePage({ revokeJti, revokeBy, setRevokeJti, setRevokeBy, onRevoke }) {
  return (
    <section className="page-section">
      <div className="page-header">
        <div className="page-kicker">Containment</div>
        <div className="page-title">Revoke Credential</div>
        <div className="page-subtitle">Revoking the root invalidates the full descendant tree. Use this when an agent should lose authority immediately.</div>
      </div>
      <div className="card">
        <p className="muted-text">
          Revoking a credential invalidates it and all descendants in its chain immediately.
        </p>
        <div className="revoke-form">
          <div className="field">
            <label>Credential JTI</label>
            <input id="revoke-jti" type="text" value={revokeJti} onChange={(event) => setRevokeJti(event.target.value)} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" />
          </div>
          <div className="field compact">
            <label>Revoked by</label>
            <input id="revoke-by" type="text" value={revokeBy} onChange={(event) => setRevokeBy(event.target.value)} placeholder="compliance:operator" />
          </div>
          <button className="btn btn-danger" type="button" onClick={onRevoke}>Revoke</button>
        </div>
      </div>
    </section>
  );
}

function SettingsPage({ org }) {
  return (
    <section className="page-section">
      <div className="page-header">
        <div className="page-kicker">Workspace metadata</div>
        <div className="page-title">Settings</div>
        <div className="page-subtitle">Workspace metadata and the current API endpoint. Nothing here changes the standalone behavior.</div>
      </div>
      <div className="card">
        <div className="card-title">Workspace</div>
        <table className="settings-table">
          <tbody>
            <tr><td>Name</td><td>{org.name}</td></tr>
            <tr><td>Workspace ID</td><td className="mono">{org.id}</td></tr>
            <tr><td>Status</td><td>{org.status}</td></tr>
            <tr><td>Created</td><td>{formatDate(org.createdAt, 'datetime')}</td></tr>
          </tbody>
        </table>
      </div>
      <div className="card">
        <div className="card-title">API endpoint</div>
        <div className="mono">{API}</div>
      </div>
    </section>
  );
}

export default App;
