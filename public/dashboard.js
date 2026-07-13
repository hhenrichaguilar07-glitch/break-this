// dashboard.js — 2FA management + audit feed + logout.
// All state-changing calls send a fresh CSRF token. Audit rows are rendered
// with textContent (never innerHTML) so a script-looking stored value can't
// inject markup — Layer 14 safety.

const el = (id) => document.getElementById(id);

const twofaStatus = el('twofaStatus');
const twofaSetup = el('twofaSetup');
const twofaQr = el('twofaQr');
const twofaOn = el('twofaOn');
const twofaMsg = el('twofaMsg');
const qrImg = el('qrImg');
const secretText = el('secretText');
const codeInput = el('twofaCode');
const auditList = el('auditList');

async function getCsrfToken() {
  const res = await fetch('/api/csrf');
  const data = await res.json();
  return data.csrfToken;
}

async function postJson(url, body) {
  const csrfToken = await getCsrfToken();
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-csrf-token': csrfToken,
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = {};
  try { data = await res.json(); } catch (_) { /* no body */ }
  return { res, data };
}

function setMsg(text, ok) {
  twofaMsg.textContent = text || '';
  twofaMsg.classList.toggle('ok', !!ok);
}

function show(node) { node.classList.remove('hidden'); }
function hide(node) { node.classList.add('hidden'); }

// Reflect the current 2FA state: either offer setup, or offer disable.
async function loadStatus() {
  try {
    const res = await fetch('/api/2fa/status');
    const data = await res.json();
    hide(twofaQr);
    if (data.enabled) {
      twofaStatus.textContent = 'Two-factor authentication is ON for this account.';
      hide(twofaSetup);
      show(twofaOn);
    } else {
      twofaStatus.textContent = 'Two-factor authentication is OFF. Turn it on for account-takeover protection.';
      show(twofaSetup);
      hide(twofaOn);
    }
  } catch (err) {
    twofaStatus.textContent = 'Could not load 2FA status.';
  }
}

// Begin enrollment: get a fresh secret + QR, then wait for a confirming code.
async function startSetup() {
  setMsg('');
  try {
    const { res, data } = await postJson('/api/2fa/setup');
    if (!res.ok || !data.ok) {
      setMsg(data.error || 'Could not start 2FA setup.');
      return;
    }
    secretText.textContent = data.secret;
    // Cache-bust so the browser always fetches the QR for the new secret.
    qrImg.src = '/api/2fa/qr?t=' + encodeURIComponent(String(performance.now()));
    hide(twofaSetup);
    show(twofaQr);
    if (codeInput) { codeInput.value = ''; codeInput.focus(); }
  } catch (err) {
    setMsg('Network error. Please try again.');
  }
}

// Confirm the code and flip 2FA on.
async function enableTwofa() {
  setMsg('');
  const token = (codeInput.value || '').trim();
  if (!/^\d{6}$/.test(token)) {
    setMsg('Enter the 6-digit code from your app.');
    return;
  }
  try {
    const { res, data } = await postJson('/api/2fa/enable', { token });
    if (res.ok && data.ok) {
      setMsg('Two-factor authentication enabled.', true);
      await loadStatus();
    } else {
      setMsg(data.error || 'Could not enable 2FA.');
    }
  } catch (err) {
    setMsg('Network error. Please try again.');
  }
}

async function disableTwofa() {
  setMsg('');
  try {
    const { res, data } = await postJson('/api/2fa/disable');
    if (res.ok && data.ok) {
      setMsg('Two-factor authentication turned off.', true);
      await loadStatus();
    } else {
      setMsg(data.error || 'Could not disable 2FA.');
    }
  } catch (err) {
    setMsg('Network error. Please try again.');
  }
}

// Load the last 20 audit events. Built entirely with textContent — safe.
async function loadAudit() {
  try {
    const res = await fetch('/api/audit');
    const data = await res.json();
    auditList.textContent = '';
    if (!data.entries || !data.entries.length) {
      const li = document.createElement('li');
      li.textContent = 'No activity yet.';
      auditList.appendChild(li);
      return;
    }
    for (const e of data.entries) {
      const li = document.createElement('li');

      const when = document.createElement('span');
      const ts = Number(e.created_at) * 1000;
      when.textContent = Number.isFinite(ts) ? new Date(ts).toLocaleString() : '';

      const ev = document.createElement('span');
      ev.className = 'ev ' + (e.success ? 'ok' : 'fail');
      ev.textContent = e.event;

      const who = document.createElement('span');
      who.textContent = e.username ? String(e.username) : '-';

      const ip = document.createElement('span');
      ip.textContent = e.ip ? String(e.ip) : '';

      li.append(when, ev, who, ip);
      auditList.appendChild(li);
    }
  } catch (err) {
    auditList.textContent = '';
    const li = document.createElement('li');
    li.textContent = 'Could not load activity.';
    auditList.appendChild(li);
  }
}

// Wire up buttons.
const startBtn = el('startTwofa');
const enableBtn = el('enableTwofa');
const disableBtn = el('disableTwofa');
const logoutBtn = el('logoutBtn');

if (startBtn) startBtn.addEventListener('click', startSetup);
if (enableBtn) enableBtn.addEventListener('click', enableTwofa);
if (disableBtn) disableBtn.addEventListener('click', disableTwofa);
if (codeInput) {
  codeInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); enableTwofa(); }
  });
}

if (logoutBtn) {
  logoutBtn.addEventListener('click', async () => {
    try {
      await postJson('/api/logout');
    } finally {
      window.location.href = '/';
    }
  });
}

// Initial load.
loadStatus();
loadAudit();
