// dashboard.js — 2FA management + audit feed + logout.
// Perf: CSRF token comes from the page's <meta> tag and is cached for the whole
// session (the dashboard never regenerates the session), so state-changing
// calls need no extra /api/csrf round-trip. Audit rows use textContent only.

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

let cachedCsrf = (document.querySelector('meta[name="csrf-token"]') || {}).content || null;

async function getCsrfToken(force) {
  if (cachedCsrf && !force) return cachedCsrf;
  const res = await fetch('/api/csrf');
  cachedCsrf = (await res.json()).csrfToken;
  return cachedCsrf;
}

async function postJson(url, body) {
  const send = async (token) =>
    fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-csrf-token': token },
      body: body ? JSON.stringify(body) : undefined,
    });
  let res = await send(await getCsrfToken());
  if (res.status === 403) res = await send(await getCsrfToken(true));
  let data = {};
  try { data = await res.json(); } catch (_) { /* no body */ }
  return { res, data };
}

function setMsg(text, ok) {
  twofaMsg.textContent = text || '';
  twofaMsg.classList.toggle('ok', !!ok);
}

const show = (node) => node.classList.remove('hidden');
const hide = (node) => node.classList.add('hidden');

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

async function startSetup() {
  setMsg('');
  try {
    const { res, data } = await postJson('/api/2fa/setup');
    if (!res.ok || !data.ok) {
      setMsg(data.error || 'Could not start 2FA setup.');
      return;
    }
    secretText.textContent = data.secret;
    qrImg.src = '/api/2fa/qr?t=' + encodeURIComponent(String(performance.now()));
    hide(twofaSetup);
    show(twofaQr);
    if (codeInput) { codeInput.value = ''; codeInput.focus(); }
  } catch (err) {
    setMsg('Network error. Please try again.');
  }
}

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

// Last 20 audit events, built with textContent (XSS-safe).
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

el('startTwofa') && el('startTwofa').addEventListener('click', startSetup);
el('enableTwofa') && el('enableTwofa').addEventListener('click', enableTwofa);
el('disableTwofa') && el('disableTwofa').addEventListener('click', disableTwofa);
if (codeInput) {
  codeInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); enableTwofa(); }
  });
}

const logoutBtn = el('logoutBtn');
if (logoutBtn) {
  logoutBtn.addEventListener('click', async () => {
    try { await postJson('/api/logout'); }
    finally { window.location.href = '/'; }
  });
}

loadStatus();
loadAudit();
