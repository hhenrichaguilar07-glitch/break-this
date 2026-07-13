// login.js — handles the two-step login form.
//   Step 1: username + password  -> POST /api/login
//   Step 2: 6-digit 2FA code      -> POST /api/login/2fa   (only if 2FA is on)
// Errors are shown inline (never a blocking alert), and the CSRF token is
// fetched fresh and sent as a header on every state-changing request.

const form = document.getElementById('loginForm');
const msg = document.getElementById('msg');
const twofaStep = document.getElementById('twofaStep');
const twofaCode = document.getElementById('twofaCode');
const verifyBtn = document.getElementById('verifyTwofa');

async function getCsrfToken() {
  const res = await fetch('/api/csrf');
  const data = await res.json();
  return data.csrfToken;
}

function showError(text) {
  msg.classList.remove('ok');
  msg.textContent = text;
}

// Reveal the 2FA prompt and hide the password form.
function enterTwoFactorStep() {
  form.classList.add('hidden');
  twofaStep.classList.remove('hidden');
  msg.classList.remove('ok');
  msg.textContent = 'Enter the 6-digit code from your authenticator app.';
  twofaCode.value = '';
  twofaCode.focus();
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  showError('');

  try {
    const csrfToken = await getCsrfToken();

    const res = await fetch('/api/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-csrf-token': csrfToken,
      },
      body: JSON.stringify({
        username: document.getElementById('username').value,
        password: document.getElementById('password').value,
      }),
    });

    const data = await res.json();

    if (res.ok && data.twoFactorRequired) {
      // Password was correct but 2FA is enabled — ask for the code.
      enterTwoFactorStep();
    } else if (res.ok && data.ok && data.redirect) {
      // Either a full login (no 2FA) or the decoy redirect for attack payloads.
      window.location.href = data.redirect;
    } else {
      // Generic message on purpose — don't reveal which field was wrong.
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
    const csrfToken = await getCsrfToken();
    const res = await fetch('/api/login/2fa', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-csrf-token': csrfToken,
      },
      body: JSON.stringify({ token }),
    });

    const data = await res.json();

    if (res.ok && data.ok && data.redirect) {
      window.location.href = data.redirect;
    } else {
      showError(data.error || 'Verification failed.');
    }
  } catch (err) {
    showError('Network error. Please try again.');
  }
}

if (verifyBtn) {
  verifyBtn.addEventListener('click', submitTwoFactor);
}
if (twofaCode) {
  twofaCode.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      submitTwoFactor();
    }
  });
}
