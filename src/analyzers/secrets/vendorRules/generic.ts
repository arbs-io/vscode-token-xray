import { SecretRule, SecretRuleContext } from '../types'

// Generic / non-vendor-specific rules. The canonical PEM private-key rule
// is intentionally kept in `rules.ts` for backwards compatibility — the rules
// below cover the remaining surfaces called out by the `secret-generic`
// backlog item: JWT-shaped strings landing in `.env` files (warning), and
// high-entropy random-looking strings (info).

const JWT_SHAPE = /\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b/g

const ENV_FILENAME_RE = /(^|[\\/])\.env(\.[A-Za-z0-9_.-]+)?$/

export function isEnvFilename(filename: string | undefined): boolean {
  if (!filename) return false
  return ENV_FILENAME_RE.test(filename)
}

const JWT_IN_ENV_FILE: SecretRule = {
  id: 'secret.generic.jwtInEnv',
  vendor: 'generic',
  name: 'JWT-shaped string in .env file',
  pattern: JWT_SHAPE,
  severity: 'warning',
  description:
    'A JWT-shaped string was found in an environment file. Tokens belong in a secret manager — committing a `.env` with a real JWT can leak access for any service that accepts it.',
  docUrl: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
  validate: (_raw, ctx) => isEnvFilename(ctx.filename),
}

// High-entropy token-shaped strings. Matches contiguous runs of
// base64-url / base64 / hex characters, then validates with Shannon entropy.
// Length must be >= 20 to limit noise on short identifiers (UUIDs, git
// short shas, etc), and entropy must exceed 4.5 bits/char.
const HIGH_ENTROPY_CANDIDATE = /[A-Za-z0-9+/=_-]{20,}/g

export const HIGH_ENTROPY_MIN_LENGTH = 20
export const HIGH_ENTROPY_THRESHOLD = 4.5

export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0
  const freq = new Map<string, number>()
  for (const ch of s) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1)
  }
  let h = 0
  const len = s.length
  for (const count of freq.values()) {
    const p = count / len
    h -= p * Math.log2(p)
  }
  return h
}

export function isHighEntropyToken(raw: string): boolean {
  if (raw.length < HIGH_ENTROPY_MIN_LENGTH) return false
  // Require at least three distinct character classes to suppress
  // obvious non-secrets like long all-lowercase identifiers.
  const classes = countCharClasses(raw)
  if (classes < 3) return false
  return shannonEntropy(raw) > HIGH_ENTROPY_THRESHOLD
}

function countCharClasses(raw: string): number {
  let classes = 0
  if (/[a-z]/.test(raw)) classes++
  if (/[A-Z]/.test(raw)) classes++
  if (/[0-9]/.test(raw)) classes++
  if (/[+/=_-]/.test(raw)) classes++
  return classes
}

const HIGH_ENTROPY_STRING: SecretRule = {
  id: 'secret.generic.highEntropy',
  vendor: 'generic',
  name: 'High-entropy string',
  pattern: HIGH_ENTROPY_CANDIDATE,
  severity: 'info',
  description:
    'String with high Shannon entropy and length >= 20 — looks like an opaque token, hash, or random secret. Review whether it belongs in source.',
  docUrl: 'https://en.wikipedia.org/wiki/Entropy_(information_theory)',
  validate: (raw: string, _ctx: SecretRuleContext) => isHighEntropyToken(raw),
}

export const GENERIC_SECRET_RULES: SecretRule[] = [JWT_IN_ENV_FILE, HIGH_ENTROPY_STRING]
