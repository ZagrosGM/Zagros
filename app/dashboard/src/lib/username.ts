// Random username generator: letters + digits,
// cryptographically uniform, configurable length. Crypto.getRandomValues is
// available in EVERY context (unlike crypto.subtle it is not secure-context
// gated), which matters for plain-HTTP panels.
const LETTERS = "abcdefghijklmnopqrstuvwxyz";
const DIGITS = "0123456789";
const ALPHABET = LETTERS + DIGITS;

function rand(maxExclusive: number): number {
  if (typeof crypto !== "undefined" && crypto.getRandomValues) {
    // rejection sampling — no modulo bias
    const buf = new Uint32Array(1);
    const limit = Math.floor(0x1_0000_0000 / maxExclusive) * maxExclusive;
    do {
      crypto.getRandomValues(buf);
    } while (buf[0] >= limit);
    return buf[0] % maxExclusive;
  }
  return Math.floor(Math.random() * maxExclusive);
}

/** A random username of exactly `length` chars: starts with a letter (safe
 *  for every downstream regex) and always contains at least one digit, so
 *  "letters + digits" is a property, not a coincidence. */
export function randomUsername(length: number): string {
  const n = Math.max(2, Math.min(32, Math.floor(length) || 8));
  const chars: string[] = new Array(n);
  chars[0] = LETTERS[rand(LETTERS.length)];
  for (let i = 1; i < n; i++) chars[i] = ALPHABET[rand(ALPHABET.length)];
  const digitAt = 1 + rand(n - 1);
  chars[digitAt] = DIGITS[rand(DIGITS.length)];
  return chars.join("");
}
