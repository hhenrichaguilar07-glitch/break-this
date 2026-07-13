// validators.js — input validation helpers.
//
// LAYER 5: allow-list validation of the login username/password (centralized
// so the rules live in one place and are easy to test).
// LAYER 12: password-strength rules, enforced when an account is seeded (and
// reusable for any future sign-up flow).

// --- Layer 5: login allow-list ---
// Only letters, digits, underscore and dot are allowed in a username.
const USERNAME_RE = /^[a-zA-Z0-9_.]+$/;

const LIMITS = {
  username: { min: 3, max: 32 },
  password: { min: 1, max: 200 },
};

function isValidUsername(username) {
  return (
    typeof username === 'string' &&
    username.length >= LIMITS.username.min &&
    username.length <= LIMITS.username.max &&
    USERNAME_RE.test(username)
  );
}

function isValidPassword(password) {
  return (
    typeof password === 'string' &&
    password.length >= LIMITS.password.min &&
    password.length <= LIMITS.password.max
  );
}

function validateLogin(username, password) {
  return isValidUsername(username) && isValidPassword(password);
}

// --- Layer 12: password strength ---
// A small blocklist of the most common passwords. Case-insensitive.
const COMMON_PASSWORDS = new Set([
  'password', 'password1', 'password123', 'passw0rd', '123456', '1234567',
  '12345678', '123456789', 'qwerty', 'qwerty123', 'abc123', 'admin',
  'admin123', 'root', 'toor', 'letmein', 'welcome', 'welcome1', 'monkey',
  'iloveyou', 'dragon', 'sunshine', 'princess', 'football', 'baseball',
  '111111', '000000', '123123', 'changeme', 'secret', 'test1234',
]);

// Returns an array of unmet requirements (empty array = strong enough).
function passwordStrengthErrors(pw) {
  const errors = [];
  if (typeof pw !== 'string' || pw.length < 10) errors.push('at least 10 characters');
  if (!/[a-z]/.test(pw)) errors.push('a lowercase letter');
  if (!/[A-Z]/.test(pw)) errors.push('an uppercase letter');
  if (!/[0-9]/.test(pw)) errors.push('a number');
  if (!/[^A-Za-z0-9]/.test(pw)) errors.push('a symbol');
  if (typeof pw === 'string' && COMMON_PASSWORDS.has(pw.toLowerCase())) {
    errors.push('not a common/guessable password');
  }
  return errors;
}

function isStrongPassword(pw) {
  return passwordStrengthErrors(pw).length === 0;
}

module.exports = {
  USERNAME_RE,
  LIMITS,
  isValidUsername,
  isValidPassword,
  validateLogin,
  COMMON_PASSWORDS,
  passwordStrengthErrors,
  isStrongPassword,
};
