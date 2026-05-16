import { describe, expect, it } from 'vitest'
import { OAuthTokenAnalyzer } from './analyzer'

const GH_PAT = 'ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
const STRIPE_SECRET = 'sk_live_aaaaaaaaaaaaaaaaaaaaaaaa'
const STRIPE_PUB = 'pk_test_ffffffffffffffffffffffff'

describe('OAuthTokenAnalyzer', () => {
  const analyzer = new OAuthTokenAnalyzer()

  it('detects a GitHub PAT in source-code-like text', () => {
    const text = `const token = "${GH_PAT}"`
    const matches = analyzer.detect(text)
    expect(matches.map((m) => m.text)).toContain(GH_PAT)
  })

  it('returns nothing for inert text', () => {
    expect(analyzer.detect('hello world')).toEqual([])
    expect(analyzer.detect('')).toEqual([])
  })

  it('produces an error finding for a Stripe live secret key', () => {
    const [match] = analyzer.detect(STRIPE_SECRET)
    const result = analyzer.analyze(match)
    expect(result.findings).toHaveLength(1)
    expect(result.findings[0].severity).toBe('error')
    expect(result.findings[0].id).toBe('oauth.stripe.secret.live')
  })

  it('produces an info finding for a Stripe publishable key (designed to be public)', () => {
    const [match] = analyzer.detect(STRIPE_PUB)
    const result = analyzer.analyze(match)
    expect(result.findings[0].severity).toBe('info')
  })

  it('renders a Token section with vendor / kind / prefix / length', () => {
    const [match] = analyzer.detect(GH_PAT)
    const result = analyzer.analyze(match)
    expect(result.sections[0].id).toBe('token')
    const keys = result.sections[0].rows.map((r) => r.key)
    expect(keys).toEqual(expect.arrayContaining(['vendor', 'kind', 'prefix', 'length']))
  })

  it('includes environment row for Stripe tokens', () => {
    const [match] = analyzer.detect(STRIPE_SECRET)
    const result = analyzer.analyze(match)
    const env = result.sections[0].rows.find((r) => r.key === 'environment')
    expect(env?.value).toBe('live')
  })

  it('throws when analyze is called with text that does not match any pattern', () => {
    expect(() => analyzer.analyze({ text: 'plain text' })).toThrow()
  })
})
