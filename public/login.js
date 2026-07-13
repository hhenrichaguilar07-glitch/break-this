// login.js — two-step login (password -> optional 2FA code).
// Perf: the CSRF token is read from a <meta> tag the server embedded in the
// page (no network round-trip). We only fall back to /api/csrf if it's missing
// or the server rejects a stale token (which happens after session.regenerate).

const form = document.getElementById('loginForm');
const msg = document.getElementById('msg');
const twofaStep = document.getElementById('twofaStep');
const twofaCode = document.getElementById('twofaCode');
const verifyBtn = document.getElementById('verifyTwofa');

let cachedCsrf = (document.querySelector('meta[name="csrf-token"]') || {}).content || null;

async function getCsrfToken(force) {
  if (cachedCsrf && !force) return cachedCsrf;
  const res = await fetch('/api/csrf');
  cachedCsrf = (await res.json()).csrfToken;
  return cachedCsrf;
}

// POST JSON with the cached CSRF token; on a 403 (stale token) refetch once.
async function postJson(url, body) {
  const send = async (token) =>
    fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-csrf-token': token },
      body: JSON.stringify(body),
    });
  let res = await send(await getCsrfToken());
  if (res.status === 403) res = await send(await getCsrfToken(true));
  let data = {};
  try { data = await res.json(); } catch (_) { /* no body */ }
  return { res, data };
}

function showError(text) {
  msg.classList.remove('ok');
  msg.textContent = text;
}

function enterTwoFactorStep() {
  form.classList.add('hidden');
  twofaStep.classList.remove('hidden');
  showError('');
  msg.textContent = 'Enter the 6-digit code from your authenticator app.';
  twofaCode.value = '';
  twofaCode.focus();
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  showError('');
  try {
    const { res, data } = await postJson('/api/login', {
      username: document.getElementById('username').value,
      password: document.getElementById('password').value,
    });

    if (res.ok && data.twoFactorRequired) {
      // Session regenerated on the server — our cached token is now stale.
      cachedCsrf = null;
      enterTwoFactorStep();
    } else if (res.ok && data.ok && data.redirect) {
      window.location.href = data.redirect; // real login OR decoy
    } else {
      showError(data.error || 'Login failed.');
    }
  } catch (err) {
    showError('Network error. Please try again.');
  }
});

async function submitTwoFactor() {
  showError('');
  const token = (twofaCode.value || '').trim();
  if (!/^\d{6}$/.test(token)) {
    showError('Enter the 6-digit code.');
    return;
  }
  try {
    const { res, data } = await postJson('/api/login/2fa', { token });
    if (res.ok && data.ok && data.redirect) {
      window.location.href = data.redirect;
    } else {
      showError(data.error || 'Verification failed.');
    }
  } catch (err) {
    showError('Network error. Please try again.');
  }
}

if (verifyBtn) verifyBtn.addEventListener('click', submitTwoFactor);
if (twofaCode) {
  twofaCode.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); submitTwoFactor(); }
  });
}
