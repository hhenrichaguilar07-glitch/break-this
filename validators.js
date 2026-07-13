// validators.js — LAYER 5: INPUT VALIDATION (allow-list, not block-list).
//
// Pulled into its own module so the rules live in one place, are easy to
// unit-test, and can be reused by any route. The idea: reject anything that
// isn't a plausible username/password *before* it ever reaches the database or
// the credential check. An allow-list ("only these characters are OK") is far
// safer than a block-list ("ban these bad characters"), because you can't
// forget to ban something.

// Only letters, digits, underscore and dot are allowed in a username.
// Anything else (quotes, spaces, angle brackets, SQL metacharacters) is out.
const USERNAME_RE = /^[a-zA-Z0-9_.]+$/;

// Length bounds. The upper caps also blunt oversized-input abuse.
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

// Convenience: both must be valid for a login attempt to proceed.
function validateLogin(username, password) {
  return isValidUsername(username) && isValidPassword(password);
}

module.exports = {
  USERNAME_RE,
  LIMITS,
  isValidUsername,
  isValidPassword,
  validateLogin,
};
