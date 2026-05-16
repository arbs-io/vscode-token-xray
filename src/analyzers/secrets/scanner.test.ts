import { describe, expect, it } from 'vitest'
import { findingsForSecrets, scanForSecrets } from './scanner'
import { SecretRule } from './types'

const PEM_KEY = [
  '-----BEGIN RSA PRIVATE KEY-----',
  'MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu',
  'KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm',
  '-----END RSA PRIVATE KEY-----',
].join('\n')

const FAKE_RULE: SecretRule = {
  id: 'demo.fixed',
  vendor: 'demo',
  name: 'Demo',
  pattern: /SECRET-[A-Z0-9]+/g,
  severity: 'warning',
  description: 'demo secret',
}

const VALIDATED_RULE: SecretRule = {
  id: 'demo.validated',
  vendor: 'demo',
  name: 'Validated',
  pattern: /TEST-[A-Z0-9]+/g,
  severity: 'warning',
  description: 'test',
  validate: (raw) => raw.endsWith('-OK'),
}

describe('scanForSecrets', () => {
  it('finds a built-in PEM private key', () => {
    const hits = scanForSecrets(`junk\n${PEM_KEY}\nmore`)
    expect(hits).toHaveLength(1)
    expect(hits[0].rule.id).toBe('secret.privateKey.pem')
    expect(hits[0].start).toBeGreaterThan(0)
  })

  it('returns empty for inert text', () => {
    expect(scanForSecrets('hello world')).toEqual([])
    expect(scanForSecrets('')).toEqual([])
  })

  it('respects maxBytes', () => {
    expect(scanForSecrets(PEM_KEY, { maxBytes: 10 })).toEqual([])
  })

  it('uses the supplied rule set when provided', () => {
    const hits = scanForSecrets('SECRET-ABC and SECRET-XYZ', { rules: [FAKE_RULE] })
    expect(hits).toHaveLength(2)
  })

  it('supports rule-level validate to filter false positives', () => {
    const hits = scanForSecrets('TEST-FAIL and TEST-OK and TEST-PASS', { rules: [VALIDATED_RULE] })
    expect(hits.map((h) => h.text)).toEqual(['TEST-OK'])
  })

  it('deduplicates overlapping hits from the same rule', () => {
    const overlapping: SecretRule = { ...FAKE_RULE, id: 'demo.over', pattern: /SECRET/g }
    const hits = scanForSecrets('SECRET', { rules: [overlapping] })
    expect(hits).toHaveLength(1)
  })

  it('drops info-severity hits fully overlapped by a higher-severity hit', () => {
    const errorRule: SecretRule = {
      id: 'demo.outer',
      vendor: 'demo',
      name: 'outer',
      pattern: /OUTER-[A-Z0-9]+/g,
      severity: 'error',
      description: 'outer',
    }
    const infoRule: SecretRule = {
      id: 'demo.inner',
      vendor: 'demo',
      name: 'inner',
      pattern: /[A-Z0-9]{3,}/g,
      severity: 'info',
      description: 'inner',
    }
    const hits = scanForSecrets('OUTER-ABC123', { rules: [errorRule, infoRule] })
    expect(hits.map((h) => h.rule.id)).toEqual(['demo.outer'])
  })

  it('keeps info-severity hits that do NOT overlap higher-severity ones', () => {
    const errorRule: SecretRule = {
      id: 'demo.left',
      vendor: 'demo',
      name: 'left',
      pattern: /ERR/g,
      severity: 'error',
      description: 'left',
    }
    const infoRule: SecretRule = {
      id: 'demo.right',
      vendor: 'demo',
      name: 'right',
      pattern: /INFO/g,
      severity: 'info',
      description: 'right',
    }
    const hits = scanForSecrets('ERR and INFO', { rules: [errorRule, infoRule] })
    expect(hits.map((h) => h.rule.id).sort()).toEqual(['demo.left', 'demo.right'])
  })

  it('keeps two info-severity hits on the same range (info does not suppress info)', () => {
    const a: SecretRule = {
      id: 'demo.a',
      vendor: 'demo',
      name: 'a',
      pattern: /XYZ/g,
      severity: 'info',
      description: 'a',
    }
    const b: SecretRule = {
      id: 'demo.b',
      vendor: 'demo',
      name: 'b',
      pattern: /XYZ/g,
      severity: 'info',
      description: 'b',
    }
    const hits = scanForSecrets('XYZ', { rules: [a, b] })
    expect(hits).toHaveLength(2)
  })
})

describe('findingsForSecrets', () => {
  it('produces a Finding per hit with sensitive range', () => {
    const findings = findingsForSecrets(PEM_KEY)
    expect(findings).toHaveLength(1)
    expect(findings[0].id).toBe('secret.privateKey.pem')
    expect(findings[0].severity).toBe('error')
    expect(findings[0].range?.end).toBeGreaterThan(findings[0].range!.start)
  })

  it('honours sensitiveSpan when provided', () => {
    const RULE_WITH_SPAN: SecretRule = {
      id: 'demo.span',
      vendor: 'demo',
      name: 'span',
      pattern: /key=([A-Z0-9]+)/g,
      severity: 'warning',
      description: 'demo',
      sensitiveSpan: (raw) => ({ start: raw.indexOf('=') + 1, end: raw.length }),
    }
    const text = 'key=SUPERSECRET123'
    const findings = findingsForSecrets(text, { rules: [RULE_WITH_SPAN] })
    expect(findings[0].range?.start).toBe(text.indexOf('SUPERSECRET'))
    expect(findings[0].range?.end).toBe(text.length)
  })
})
