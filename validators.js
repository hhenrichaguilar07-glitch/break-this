// validators.js — Layer 12: password strength rules.
// Reuse checkPasswordStrength() anywhere a password is set (seeding, and any
// future registration/change-password flow).

// A tiny sample blocklist. In a real system you'd check against a large list
// (e.g. the "Have I Been Pwned" breached-password set).
const COMMON_PASSWORDS = new Set([
  'password', 'password1', 'password123', '12345678', '123456789',
  'qwerty123', 'admin', 'admin123', 'letmein', 'iloveyou', 'welcome1',
]);

function checkPasswordStrength(password) {
  if (typeof password !== 'string') {
    return { ok: false, message: 'Password must be text.' };
  }
  if (password.length < 10) {
    return { ok: false, message: 'Password must be at least 10 characters.' };
  }
  if (password.length > 200) {
    return { ok: false, message: 'Password is too long.' };
  }
  if (!/[a-z]/.test(password)) {
    return { ok: false, message: 'Add at least one lowercase letter.' };
  }
  if (!/[A-Z]/.test(password)) {
    return { ok: false, message: 'Add at least one uppercase letter.' };
  }
  if (!/[0-9]/.test(password)) {
    return { ok: false, message: 'Add at least one number.' };
  }
  if (!/[^A-Za-z0-9]/.test(password)) {
    return { ok: false, message: 'Add at least one symbol (e.g. ! ? # $).' };
  }
  if (COMMON_PASSWORDS.has(password.toLowerCase())) {
    return { ok: false, message: 'That password is too common — pick something unique.' };
  }
  return { ok: true, message: 'Strong password.' };
}

module.exports = { checkPasswordStrength };
