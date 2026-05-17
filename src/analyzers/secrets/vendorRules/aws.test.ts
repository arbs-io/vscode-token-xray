import { describe, expect, it } from 'vitest'
import { scanForSecrets } from '../scanner'
import { AWS_SECRET_RULES } from './aws'

const opts = { rules: AWS_SECRET_RULES }

describe('AWS_SECRET_RULES — access key ID (AKIA)', () => {
  it('matches a well-formed AKIA key', () => {
    const hits = scanForSecrets('aws_key = AKIAIOSFODNN7EXAMPLE', opts)
    expect(hits.find((h) => h.rule.id === 'secret.aws.accessKeyId')?.rule.severity).toBe('error')
  })

  it('does not match AKIA-prefixed lowercase / short strings', () => {
    expect(scanForSecrets('AKIAabc', opts)).toEqual([])
    expect(scanForSecrets('AKIASHORT', opts)).toEqual([])
  })

  it('does not match other AWS unique-id prefixes', () => {
    expect(scanForSecrets('AROAIOSFODNN7EXAMPLE', opts).map((h) => h.rule.id)).not.toContain(
      'secret.aws.accessKeyId'
    )
  })
})

describe('AWS_SECRET_RULES — session access key (ASIA)', () => {
  it('matches an ASIA-prefixed key as warning', () => {
    const hits = scanForSecrets('cred = ASIAIOSFODNN7EXAMPLE', opts)
    const h = hits.find((x) => x.rule.id === 'secret.aws.sessionAccessKeyId')
    expect(h?.rule.severity).toBe('warning')
  })
})

describe('AWS_SECRET_RULES — secret access key', () => {
  const VALID_40 = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'

  it('matches AWS_SECRET_ACCESS_KEY= label', () => {
    const hits = scanForSecrets(`AWS_SECRET_ACCESS_KEY=${VALID_40}`, opts)
    expect(hits.find((h) => h.rule.id === 'secret.aws.secretAccessKey')?.rule.severity).toBe('error')
  })

  it('matches aws_secret_access_key: label', () => {
    const hits = scanForSecrets(`aws_secret_access_key: "${VALID_40}"`, opts)
    expect(hits.some((h) => h.rule.id === 'secret.aws.secretAccessKey')).toBe(true)
  })

  it('matches camelCase secretAccessKey label', () => {
    const hits = scanForSecrets(`{ "secretAccessKey": "${VALID_40}" }`, opts)
    expect(hits.some((h) => h.rule.id === 'secret.aws.secretAccessKey')).toBe(true)
  })

  it('sensitiveSpan points to the value, not the label', () => {
    const text = `AWS_SECRET_ACCESS_KEY=${VALID_40}`
    const [hit] = scanForSecrets(text, opts).filter(
      (h) => h.rule.id === 'secret.aws.secretAccessKey'
    )
    expect(text.slice(hit.sensitiveStart, hit.sensitiveEnd)).toBe(VALID_40)
  })

  it('does not match a 40-char string without a label', () => {
    expect(scanForSecrets(VALID_40, opts).filter((h) => h.rule.id === 'secret.aws.secretAccessKey')).toEqual([])
  })
})

describe('AWS_SECRET_RULES — ARN', () => {
  it('flags an ARN with a real-looking account ID', () => {
    const hits = scanForSecrets('arn:aws:iam::987654321098:user/alice', opts)
    expect(hits.find((h) => h.rule.id === 'secret.aws.arn')?.rule.severity).toBe('info')
  })

  it('suppresses well-known AWS-documentation example account IDs', () => {
    const hits = scanForSecrets('arn:aws:iam::123456789012:user/example', opts)
    expect(hits.find((h) => h.rule.id === 'secret.aws.arn')).toBeUndefined()
  })

  it('matches partitioned ARNs (aws-cn, aws-us-gov)', () => {
    const hits = scanForSecrets('arn:aws-cn:s3:::my-bucket/foo', opts)
    // s3 ARNs don't have an account id; this should NOT match the pattern
    expect(hits.find((h) => h.rule.id === 'secret.aws.arn')).toBeUndefined()
  })
})

describe('AWS_SECRET_RULES — coverage', () => {
  it('all rules use the global flag', () => {
    for (const r of AWS_SECRET_RULES) {
      expect(r.pattern.flags).toContain('g')
    }
  })

  it('all rules have ids namespaced under secret.aws', () => {
    for (const r of AWS_SECRET_RULES) {
      expect(r.id.startsWith('secret.aws.')).toBe(true)
    }
  })
})
