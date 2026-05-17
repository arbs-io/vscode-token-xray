import { describe, expect, it } from 'vitest'
import { SecretAnalyzer } from './analyzer'

const PEM = [
  '-----BEGIN RSA PRIVATE KEY-----',
  'MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu',
  'KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm',
  '-----END RSA PRIVATE KEY-----',
].join('\n')

describe('SecretAnalyzer', () => {
  const analyzer = new SecretAnalyzer()

  it('detects a PEM private key', () => {
    const matches = analyzer.detect(`file content\n${PEM}\n`)
    expect(matches).toHaveLength(1)
  })

  it('returns empty for inert text', () => {
    expect(analyzer.detect('hello world')).toEqual([])
    expect(analyzer.detect('')).toEqual([])
  })

  it('produces a section with rule / vendor / severity / preview', () => {
    const [match] = analyzer.detect(PEM)
    const result = analyzer.analyze(match)
    expect(result.analyzerId).toBe('secret')
    expect(result.kind).toBe('generic')
    const keys = result.sections[0].rows.map((r) => r.key)
    expect(keys).toEqual(expect.arrayContaining(['rule', 'vendor', 'severity', 'length', 'preview']))
  })

  it('emits an error finding with the rule id', () => {
    const [match] = analyzer.detect(PEM)
    const result = analyzer.analyze(match)
    expect(result.findings).toHaveLength(1)
    expect(result.findings[0].id).toBe('secret.privateKey.pem')
    expect(result.findings[0].severity).toBe('error')
  })

  it('redacts long matches in the preview row', () => {
    const [match] = analyzer.detect(PEM)
    const result = analyzer.analyze(match)
    const preview = result.sections[0].rows.find((r) => r.key === 'preview')
    expect(preview?.value as string).toContain('…')
    expect((preview?.value as string).length).toBeLessThan(PEM.length)
  })

  it('throws when analyze is called with text that does not match any rule', () => {
    expect(() => analyzer.analyze({ text: 'plain text' })).toThrow()
  })
})
