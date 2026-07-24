// login.js — handles the two-step login: password, then (if enabled) 2FA code.
// Errors show inline; CSRF token is fetched fresh for each request.

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

// Step 1: username + password
form.addEventListener('submit', async (event) => {
  event.preventDefault();
  msg.textContent = '';
  try {
    const csrfToken = await getCsrfToken();
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfToken },
      body: JSON.stringify({
        username: document.getElementById('username').value,
        password: document.getElementById('password').value,
      }),
    });
    const data = await res.json();

    if (res.ok && data.twoFactorRequired) {
      // Password was correct; now ask for the authenticator code.
      form.classList.add('hidden');
      twofaStep.classList.remove('hidden');
      twofaCode.focus();
    } else if (res.ok && data.ok) {
      window.location.href = data.redirect || '/dashboard';
    } else {
      msg.textContent = data.error || 'Login failed.';
    }
  } catch (err) {
    msg.textContent = 'Network error. Please try again.';
  }
});

// Step 2: 2FA code
verifyBtn.addEventListener('click', async () => {
  msg.textContent = '';
  try {
    const csrfToken = await getCsrfToken();
    const res = await fetch('/api/login/2fa', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfToken },
      body: JSON.stringify({ token: twofaCode.value.trim() }),
    });
    const data = await res.json();
    if (res.ok && data.ok) {
      window.location.href = data.redirect || '/dashboard';
    } else {
      msg.textContent = data.error || 'Verification failed.';
    }
  } catch (err) {
    msg.textContent = 'Network error. Please try again.';
  }
});
