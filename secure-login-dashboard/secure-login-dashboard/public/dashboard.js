// dashboard.js — 2FA management, live audit feed, and logout.
// Audit rows are rendered with textContent (never innerHTML), so stored
// values like IP/username can't inject HTML even if an attacker planted them.

const $ = (id) => document.getElementById(id);

async function getCsrfToken() {
  const res = await fetch('/api/csrf');
  const data = await res.json();
  return data.csrfToken;
}

async function loadStatus() {
  const res = await fetch('/api/2fa/status');
  const { enabled } = await res.json();
  $('twofaStatus').textContent = enabled
    ? '2FA is ON — a code is required at every login.'
    : '2FA is OFF — add it for a second layer of protection.';
  $('twofaSetup').classList.toggle('hidden', enabled);
  $('twofaOn').classList.toggle('hidden', !enabled);
  $('twofaQr').classList.add('hidden');
}

async function loadAudit() {
  const res = await fetch('/api/audit');
  const { entries } = await res.json();
  const list = $('auditList');
  list.textContent = '';
  if (!entries.length) {
    const li = document.createElement('li');
    li.textContent = 'No activity yet.';
    list.appendChild(li);
    return;
  }
  for (const e of entries) {
    const li = document.createElement('li');
    const when = new Date(e.created_at * 1000).toLocaleString();
    const who = e.username ? ` (${e.username})` : '';
    li.textContent = `${when} — ${e.event}${who} — ${e.ip || ''} ${e.success ? '\u2713' : '\u2717'}`;
    list.appendChild(li);
  }
}

$('startTwofa').addEventListener('click', async () => {
  $('twofaMsg').textContent = '';
  const csrfToken = await getCsrfToken();
  const res = await fetch('/api/2fa/setup', {
    method: 'POST',
    headers: { 'x-csrf-token': csrfToken },
  });
  const data = await res.json();
  if (!res.ok) { $('twofaMsg').textContent = data.error || 'Could not start setup.'; return; }
  $('secretText').textContent = data.secret;
  $('qrImg').src = '/api/2fa/qr?ts=' + Date.now(); // cache-bust
  $('twofaSetup').classList.add('hidden');
  $('twofaQr').classList.remove('hidden');
});

$('enableTwofa').addEventListener('click', async () => {
  $('twofaMsg').textContent = '';
  const csrfToken = await getCsrfToken();
  const res = await fetch('/api/2fa/enable', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfToken },
    body: JSON.stringify({ token: $('twofaCode').value.trim() }),
  });
  const data = await res.json();
  if (res.ok && data.ok) {
    await loadStatus();
    $('twofaMsg').textContent = '2FA enabled.';
  } else {
    $('twofaMsg').textContent = data.error || 'Could not enable 2FA.';
  }
});

$('disableTwofa').addEventListener('click', async () => {
  $('twofaMsg').textContent = '';
  const csrfToken = await getCsrfToken();
  const res = await fetch('/api/2fa/disable', {
    method: 'POST',
    headers: { 'x-csrf-token': csrfToken },
  });
  const data = await res.json();
  if (res.ok && data.ok) {
    await loadStatus();
    $('twofaMsg').textContent = '2FA turned off.';
  } else {
    $('twofaMsg').textContent = data.error || 'Could not disable 2FA.';
  }
});

$('logoutBtn').addEventListener('click', async () => {
  try {
    const csrfToken = await getCsrfToken();
    await fetch('/api/logout', { method: 'POST', headers: { 'x-csrf-token': csrfToken } });
  } finally {
    window.location.href = '/';
  }
});

loadStatus();
loadAudit();
