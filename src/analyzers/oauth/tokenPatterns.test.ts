import { describe, expect, it } from 'vitest'
import { findTokens, TOKEN_PATTERNS } from './tokenPatterns'

const SAMPLES: Record<string, string> = {
  'github.pat.classic': 'ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  // 22 chars + '_' + 59 chars = 82 chars after the github_pat_ prefix
  'github.pat.fineGrained':
    'github_pat_0123456789ABCDEFGHIJKL_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  'github.oauth.userToServer': 'ghu_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
  'github.oauth.serverToServer': 'ghs_cccccccccccccccccccccccccccccccccccc',
  'github.oauth.access': 'gho_dddddddddddddddddddddddddddddddddddd',
  'github.oauth.refresh':
    'ghr_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
  'slack.bot': 'xoxb-1234567890-1234567890-1234567890-abc123def456',
  'slack.user': 'xoxp-1234567890-1234567890-1234567890-abc123def456',
  'slack.workspace': 'xoxa-2-1234567890-1234567890-1234567890-abc123def456',
  'slack.refresh': 'xoxr-1234567890-1234567890-1234567890-abc123def456',
  'slack.app': 'xapp-1-A1B2C3-1234567890-abcdef0123456789abcdef0123456789ab',
  'stripe.secret.live': 'sk_live_aaaaaaaaaaaaaaaaaaaaaaaa',
  'stripe.secret.test': 'sk_test_bbbbbbbbbbbbbbbbbbbbbbbb',
  'stripe.restricted.live': 'rk_live_cccccccccccccccccccccccc',
  'stripe.restricted.test': 'rk_test_dddddddddddddddddddddddd',
  'stripe.publishable.live': 'pk_live_eeeeeeeeeeeeeeeeeeeeeeee',
  'stripe.publishable.test': 'pk_test_ffffffffffffffffffffffff',
}

describe('TOKEN_PATTERNS', () => {
  it('has a regex with the global flag for each pattern', () => {
    for (const p of TOKEN_PATTERNS) {
      expect(p.pattern.flags).toContain('g')
    }
  })

  it('has a positive sample for every pattern', () => {
    for (const p of TOKEN_PATTERNS) {
      expect(SAMPLES, `missing sample for ${p.id}`).toHaveProperty(p.id)
    }
  })
})

describe('findTokens — positive', () => {
  for (const p of TOKEN_PATTERNS) {
    it(`matches ${p.id}`, () => {
      const sample = SAMPLES[p.id]
      const hits = findTokens(`prefix ${sample} suffix`)
      const ids = hits.map((h) => h.pattern.id)
      expect(ids).toContain(p.id)
    })
  }
})

describe('findTokens — negative', () => {
  it('does not match plain text', () => {
    expect(findTokens('hello world, this is a long string without tokens.')).toEqual([])
  })

  it('does not match GitHub-ish prefixes that are too short', () => {
    expect(findTokens('ghp_short')).toEqual([])
  })

  it('does not match arbitrary URLs', () => {
    expect(findTokens('https://example.com/api/v1/widgets/abc')).toEqual([])
  })

  it('does not match Stripe-ish prefix without the right alphabet length', () => {
    expect(findTokens('sk_live_ABC')).toEqual([])
  })

  it('returns empty for empty input', () => {
    expect(findTokens('')).toEqual([])
  })
})

describe('findTokens — multiple', () => {
  it('finds multiple distinct tokens in one document', () => {
    const text = `GitHub: ${SAMPLES['github.pat.classic']}\nStripe: ${SAMPLES['stripe.secret.live']}`
    const ids = findTokens(text).map((h) => h.pattern.id)
    expect(ids).toContain('github.pat.classic')
    expect(ids).toContain('stripe.secret.live')
  })

  it('records correct offsets for each hit', () => {
    const sample = SAMPLES['github.pat.classic']
    const text = `before-${sample}-after`
    const [hit] = findTokens(text)
    expect(hit.start).toBe(text.indexOf(sample))
    expect(hit.end).toBe(hit.start + sample.length)
  })
})
