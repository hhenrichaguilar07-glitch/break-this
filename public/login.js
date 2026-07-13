// login.js — handles the login form.
// Notice: errors are shown inline in the page (never a blocking alert popup),
// and the CSRF token is fetched fresh and sent as a header.

const form = document.getElementById('loginForm');
const msg = document.getElementById('msg');

async function getCsrfToken() {
  const res = await fetch('/api/csrf');
  const data = await res.json();
  return data.csrfToken;
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  msg.textContent = '';

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

    if (res.ok && data.ok) {
      window.location.href = data.redirect || '/dashboard';
    } else {
      // The server intentionally returns a generic message — don't reveal
      // whether it was the username or the password that was wrong.
      msg.textContent = data.error || 'Login failed.';
    }
  } catch (err) {
    msg.textContent = 'Network error. Please try again.';
  }
});
