// dashboard.js — handles logout (a state-changing action, so it needs the CSRF token).

const logoutBtn = document.getElementById('logoutBtn');

logoutBtn.addEventListener('click', async () => {
  try {
    const csrfRes = await fetch('/api/csrf');
    const { csrfToken } = await csrfRes.json();

    await fetch('/api/logout', {
      method: 'POST',
      headers: { 'x-csrf-token': csrfToken },
    });
  } finally {
    // Whatever happens, send the user back to the login page.
    window.location.href = '/';
  }
});
