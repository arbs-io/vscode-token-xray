import { describe, expect, it } from 'vitest'
import { scanForSecrets } from '../scanner'
import {
  GENERIC_SECRET_RULES,
  HIGH_ENTROPY_MIN_LENGTH,
  HIGH_ENTROPY_THRESHOLD,
  isEnvFilename,
  isHighEntropyToken,
  shannonEntropy,
} from './generic'

const opts = { rules: GENERIC_SECRET_RULES }

// A real-looking 3-segment JWT (HS256-shaped; payload is `{"sub":"42"}`).
const JWT =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0MiJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'

describe('isEnvFilename', () => {
  it('matches bare .env', () => {
    expect(isEnvFilename('.env')).toBe(true)
  })

  it('matches .env.local / .env.production', () => {
    expect(isEnvFilename('.env.local')).toBe(true)
    expect(isEnvFilename('.env.production')).toBe(true)
    expect(isEnvFilename('.env.staging.prod')).toBe(true)
  })

  it('matches .env nested in a directory path', () => {
    expect(isEnvFilename('/repo/app/.env')).toBe(true)
    expect(isEnvFilename('apps/web/.env.local')).toBe(true)
    expect(isEnvFilename(String.raw`C:\repo\.env.production`)).toBe(true)
  })

  it('does not match unrelated filenames', () => {
    expect(isEnvFilename('config.json')).toBe(false)
    expect(isEnvFilename('.envrc')).toBe(false)
    expect(isEnvFilename('readme.md')).toBe(false)
    expect(isEnvFilename(undefined)).toBe(false)
    expect(isEnvFilename('')).toBe(false)
  })
})

describe('shannonEntropy', () => {
  it('returns 0 for empty input', () => {
    expect(shannonEntropy('')).toBe(0)
  })

  it('returns 0 for a single repeated character', () => {
    expect(shannonEntropy('aaaaaaaaaa')).toBe(0)
  })

  it('returns 1 for a balanced two-symbol stream', () => {
    expect(shannonEntropy('abab')).toBeCloseTo(1, 5)
  })

  it('returns higher entropy for more random strings', () => {
    const random = 'Z9q!K3vP@1xRm$7L^bWnC&5jT'
    const uniform = 'aaaaaaaaaaaaaaaaaaaaaaaaa'
    expect(shannonEntropy(random)).toBeGreaterThan(shannonEntropy(uniform))
  })

  it('approaches log2(n) for a string of all-distinct characters', () => {
    const s = 'abcdefgh'
    expect(shannonEntropy(s)).toBeCloseTo(3, 5)
  })
})

describe('isHighEntropyToken', () => {
  it('rejects short strings even when entropy is high', () => {
    expect(isHighEntropyToken('aB3$x')).toBe(false)
  })

  it('rejects long but low-entropy strings', () => {
    expect(isHighEntropyToken('aaaaaaaaaaaaaaaaaaaaaa')).toBe(false)
  })

  it('rejects strings with too few character classes', () => {
    // all lowercase letters, >= 20 chars, but only one class
    expect(isHighEntropyToken('abcdefghijklmnopqrstuvwxyz')).toBe(false)
  })

  it('accepts a 32-char hex secret with mixed case and digits', () => {
    // Mixed case + digits = 3 classes; randomly arranged → high entropy.
    expect(isHighEntropyToken('aB3xZ7qK9mP1vR5L8nT2cW6jY4hF0gDs')).toBe(true)
  })

  it('exposes its tuning constants for reuse', () => {
    expect(HIGH_ENTROPY_MIN_LENGTH).toBe(20)
    expect(HIGH_ENTROPY_THRESHOLD).toBe(4.5)
  })
})

describe('GENERIC_SECRET_RULES — JWT in .env file', () => {
  it('flags a JWT-shaped string when filename is .env', () => {
    const hit = scanForSecrets(`API_TOKEN=${JWT}`, {
      ...opts,
      context: { filename: '/repo/.env' },
    }).find((h) => h.rule.id === 'secret.generic.jwtInEnv')
    expect(hit?.rule.severity).toBe('warning')
    expect(hit?.text).toBe(JWT)
  })

  it('flags JWT in .env.production', () => {
    const hits = scanForSecrets(`TOKEN=${JWT}`, {
      ...opts,
      context: { filename: 'apps/web/.env.production' },
    })
    expect(hits.some((h) => h.rule.id === 'secret.generic.jwtInEnv')).toBe(true)
  })

  it('does NOT flag a JWT outside an .env file', () => {
    const hits = scanForSecrets(`API_TOKEN=${JWT}`, {
      ...opts,
      context: { filename: 'src/auth.ts' },
    })
    expect(hits.some((h) => h.rule.id === 'secret.generic.jwtInEnv')).toBe(false)
  })

  it('does NOT flag when no filename context is provided', () => {
    const hits = scanForSecrets(JWT, opts)
    expect(hits.some((h) => h.rule.id === 'secret.generic.jwtInEnv')).toBe(false)
  })

  it('does not match a 2-segment string (not a JWT)', () => {
    const hits = scanForSecrets(`foo=eyJhbGci.eyJzdWIi`, {
      ...opts,
      context: { filename: '.env' },
    })
    expect(hits.some((h) => h.rule.id === 'secret.generic.jwtInEnv')).toBe(false)
  })
})

describe('GENERIC_SECRET_RULES — high-entropy strings', () => {
  it('flags a 32-char random-looking secret as info', () => {
    const text = 'token = aB3xZ7qK9mP1vR5L8nT2cW6jY4hF0gDs'
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.generic.highEntropy'
    )
    expect(hit?.rule.severity).toBe('info')
  })

  it('does not flag low-entropy long strings', () => {
    const hits = scanForSecrets('a'.repeat(40), opts)
    expect(hits.some((h) => h.rule.id === 'secret.generic.highEntropy')).toBe(false)
  })

  it('does not flag short strings', () => {
    const hits = scanForSecrets('aB3xZ7q', opts)
    expect(hits.some((h) => h.rule.id === 'secret.generic.highEntropy')).toBe(false)
  })

  it('does not flag strings with too few character classes (lowercase only)', () => {
    const hits = scanForSecrets('abcdefghijklmnopqrstuvwxyzabcdefghij', opts)
    expect(hits.some((h) => h.rule.id === 'secret.generic.highEntropy')).toBe(false)
  })

  it('flags base64-shaped opaque tokens', () => {
    // length 44, mixed case + digits + base64 punctuation
    const text = 'opaque=mF_9.B5f-4.1JqM/n=ZJk2Wq3yLpDsT8vNcXuRyHfGaBVc'
    const hits = scanForSecrets(text, opts)
    // candidate regex stops at '.', so this should produce multiple substrings
    // — at least one of which has high entropy
    expect(hits.some((h) => h.rule.id === 'secret.generic.highEntropy')).toBe(true)
  })
})

describe('GENERIC_SECRET_RULES — coverage', () => {
  it('all rules use the global flag', () => {
    for (const r of GENERIC_SECRET_RULES) {
      expect(r.pattern.flags).toContain('g')
    }
  })

  it('all rules are namespaced under secret.generic', () => {
    for (const r of GENERIC_SECRET_RULES) {
      expect(r.id.startsWith('secret.generic.')).toBe(true)
    }
  })
})
