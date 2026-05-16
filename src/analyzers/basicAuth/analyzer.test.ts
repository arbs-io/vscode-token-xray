import { describe, expect, it } from 'vitest'
import { BasicAuthAnalyzer } from './analyzer'

function b64(s: string): string {
  return Buffer.from(s, 'utf-8').toString('base64')
}

const ANALYZER = new BasicAuthAnalyzer()

describe('BasicAuthAnalyzer.detect — header form', () => {
  it('matches `Authorization: Basic <b64>`', () => {
    const cred = b64('alice:wonderland')
    const text = `GET /api HTTP/1.1\nAuthorization: Basic ${cred}\nAccept: */*`
    const matches = ANALYZER.detect(text)
    expect(matches).toHaveLength(1)
    expect(matches[0].text).toBe(`Authorization: Basic ${cred}`)
    expect(matches[0].range?.start).toBe(text.indexOf('Authorization'))
  })

  it('matches case-insensitively (`AUTHORIZATION: BASIC …`)', () => {
    const cred = b64('alice:wonderland')
    const text = `AUTHORIZATION: BASIC ${cred}`
    expect(ANALYZER.detect(text)).toHaveLength(1)
  })

  it('matches `Authorization=Basic <b64>` (some logs / curl -H reps)', () => {
    const cred = b64('alice:wonderland')
    const matches = ANALYZER.detect(`Authorization=Basic ${cred}`)
    expect(matches).toHaveLength(1)
  })

  it('still matches when the credential is malformed (so analyze can flag it)', () => {
    // 'not-base64!' fails the alphabet check, so it won't match. But a
    // base64 string that decodes to non-`user:pass` should still match the
    // header form — the analyzer surfaces a `basic.cred.malformed` finding.
    const bogus = b64('hello-no-colon-here-just-a-long-token')
    const matches = ANALYZER.detect(`Authorization: Basic ${bogus}`)
    expect(matches).toHaveLength(1)
  })

  it('returns no matches for plain text or empty input', () => {
    expect(ANALYZER.detect('hello world')).toEqual([])
    expect(ANALYZER.detect('')).toEqual([])
  })

  it('returns no matches for an Authorization Bearer header', () => {
    expect(ANALYZER.detect('Authorization: Bearer eyJhbGciOi…')).toEqual([])
  })

  it('finds multiple Authorization headers in a single document', () => {
    const a = b64('alice:wonderland')
    const b = b64('bob:builder')
    const text = `Authorization: Basic ${a}\nAuthorization: Basic ${b}`
    expect(ANALYZER.detect(text)).toHaveLength(2)
  })
})

describe('BasicAuthAnalyzer.detect — labelled forms', () => {
  it('matches BASIC_AUTH_CREDS=<b64> in env files', () => {
    const cred = b64('admin:hunter2-very-long-pw')
    const text = `# .env\nBASIC_AUTH_CREDS=${cred}\nPORT=3000`
    const matches = ANALYZER.detect(text)
    expect(matches).toHaveLength(1)
    expect(matches[0].text).toContain('BASIC_AUTH_CREDS=')
  })

  it('matches BASIC_AUTH_CREDENTIALS=<b64> alias', () => {
    const cred = b64('admin:hunter2-very-long-pw')
    expect(ANALYZER.detect(`BASIC_AUTH_CREDENTIALS=${cred}`)).toHaveLength(1)
  })

  it('matches a quoted env value', () => {
    const cred = b64('admin:hunter2-very-long-pw')
    expect(ANALYZER.detect(`BASIC_AUTH_CREDS="${cred}"`)).toHaveLength(1)
  })

  it('matches a YAML-style "auth: <b64>" key', () => {
    const cred = b64('alice:wonderland')
    expect(ANALYZER.detect(`auth: ${cred}`)).toHaveLength(1)
  })

  it('matches an INI-style "credentials = <b64>" key', () => {
    const cred = b64('alice:wonderland')
    expect(ANALYZER.detect(`credentials = ${cred}`)).toHaveLength(1)
  })

  it('matches the conservative set of label aliases (auth, authorization, basicAuth, basic-auth, basic_auth, creds)', () => {
    const cred = b64('alice:wonderland')
    expect(ANALYZER.detect(`basicAuth: ${cred}`)).toHaveLength(1)
    expect(ANALYZER.detect(`basic-auth: ${cred}`)).toHaveLength(1)
    expect(ANALYZER.detect(`basic_auth: ${cred}`)).toHaveLength(1)
    expect(ANALYZER.detect(`authorization: ${cred}`)).toHaveLength(1)
    expect(ANALYZER.detect(`creds = ${cred}`)).toHaveLength(1)
  })

  it('does NOT match unrelated labels that merely contain "auth" as a substring', () => {
    const cred = b64('alice:wonderland-this-is-long')
    // `authToken` / `oauth_token` / `authMethod` etc. should not match —
    // the spec wants conservative behaviour on the bare label form.
    expect(ANALYZER.detect(`authToken: ${cred}`)).toEqual([])
    expect(ANALYZER.detect(`oauth_token = ${cred}`)).toEqual([])
    expect(ANALYZER.detect(`authMethod = ${cred}`)).toEqual([])
  })

  it('does NOT match labelled values whose decoded form is not a user:pass pair', () => {
    // 'requiredX' is base64-alphabet, length 9 — passes the regex but
    // base64-decodes to bytes that contain no colon → label-form skips it.
    expect(ANALYZER.detect('authentication: requiredX')).toEqual([])
  })

  it('does NOT match short non-credentials like "auth: yes"', () => {
    expect(ANALYZER.detect('auth: yes')).toEqual([])
  })

  it('does NOT match a label without a colon or equals separator', () => {
    const cred = b64('alice:wonderland')
    expect(ANALYZER.detect(`auth   ${cred}`)).toEqual([])
  })

  it('does NOT match an env label whose value does not decode to user:pass', () => {
    // `requiredX` is valid base64 alphabet, length 9, but decodes to
    // 0xAD 0xEA 0x95 0xCA 0xB5 0xC1 — no colon, so the env-form skips it.
    expect(ANALYZER.detect('BASIC_AUTH_CREDS=requiredX')).toEqual([])
  })

  it('does NOT match label embedded in a larger identifier', () => {
    // `OAUTH_TOKEN=…` should not match `AUTH_BASIC` / `BASIC_AUTH` — the
    // `(?<![A-Za-z0-9_])` lookbehind keeps us out of trouble.
    const cred = b64('a:b-this-must-be-longer-to-pass')
    expect(ANALYZER.detect(`OAUTH_TOKEN=${cred}`)).toEqual([])
  })
})

describe('BasicAuthAnalyzer.detect — dedup / ranges', () => {
  it('reports a single hit when env and kv shapes overlap', () => {
    const cred = b64('alice:wonderland')
    // Two competing regexes both want to match this — env wins because it
    // is checked first and the kv regex won't claim an overlapping range.
    const matches = ANALYZER.detect(`BASIC_AUTH_CREDS=${cred}`)
    expect(matches).toHaveLength(1)
  })

  it('provides byte ranges that cover the whole matched header span', () => {
    const cred = b64('alice:wonderland')
    const prefix = 'PREFIX '
    const text = `${prefix}Authorization: Basic ${cred}`
    const [match] = ANALYZER.detect(text)
    expect(match.range?.start).toBe(prefix.length)
    expect(match.range?.end).toBe(text.length)
  })

  it('reports a single hit when env and kv regexes both match the same span (AUTHORIZATION=<b64>)', () => {
    // `AUTHORIZATION=<b64>` matches both the env-style regex and the kv
    // regex. The first-claim-wins logic must keep us to one finding.
    const cred = b64('alice:wonderland')
    const matches = ANALYZER.detect(`AUTHORIZATION=${cred}`)
    expect(matches).toHaveLength(1)
  })
})

describe('BasicAuthAnalyzer.analyze', () => {
  it('produces a Credentials section with username and masked password rows', () => {
    const cred = b64('alice:wonderland')
    const [match] = ANALYZER.detect(`Authorization: Basic ${cred}`)
    const result = ANALYZER.analyze(match)
    expect(result.analyzerId).toBe('basicAuth')
    expect(result.kind).toBe('HTTP Basic')
    expect(result.sections).toHaveLength(1)
    expect(result.sections[0].id).toBe('credentials')
    const keys = result.sections[0].rows.map((r) => r.key)
    expect(keys).toEqual(['username', 'password (masked)'])
    const user = result.sections[0].rows.find((r) => r.key === 'username')
    const pass = result.sections[0].rows.find((r) => r.key === 'password (masked)')
    expect(user?.value).toBe('alice')
    expect(pass?.value).toBe('********nd')
  })

  it('emits a basic.cred.plaintext finding (error) with username and masked password in the message', () => {
    const cred = b64('alice:wonderland')
    const [match] = ANALYZER.detect(`Authorization: Basic ${cred}`)
    const result = ANALYZER.analyze(match)
    const finding = result.findings.find((f) => f.id === 'basic.cred.plaintext')
    expect(finding?.severity).toBe('error')
    expect(finding?.message).toContain('"alice"')
    expect(finding?.message).toContain('********nd')
    expect(finding?.message).not.toContain('wonderland')
  })

  it('emits basic.cred.malformed (warning) when the header credential cannot be decoded', () => {
    const bogus = b64('no-colon-just-text-this-is-long')
    const [match] = ANALYZER.detect(`Authorization: Basic ${bogus}`)
    const result = ANALYZER.analyze(match)
    expect(result.kind).toBe('HTTP Basic (malformed)')
    expect(result.findings.find((f) => f.id === 'basic.cred.malformed')?.severity).toBe('warning')
    expect(result.findings.find((f) => f.id === 'basic.cred.plaintext')).toBeUndefined()
  })

  it('analyzes a labelled env match correctly', () => {
    const cred = b64('admin:hunter2-very-long-pw')
    const [match] = ANALYZER.detect(`BASIC_AUTH_CREDS=${cred}`)
    const result = ANALYZER.analyze(match)
    expect(result.sections[0].rows.find((r) => r.key === 'username')?.value).toBe('admin')
    expect(result.findings.some((f) => f.id === 'basic.cred.plaintext')).toBe(true)
  })

  it('accepts a bare base64 credential when called directly (e.g. via inspect command)', () => {
    const cred = b64('alice:wonderland')
    const result = ANALYZER.analyze({ text: cred })
    expect(result.sections[0].rows.find((r) => r.key === 'username')?.value).toBe('alice')
  })

  it('analyzes a kv-form match correctly (auth: <cred>)', () => {
    const cred = b64('alice:wonderland')
    const [match] = ANALYZER.detect(`auth: ${cred}`)
    expect(match).toBeDefined()
    const result = ANALYZER.analyze(match)
    expect(result.sections[0].rows.find((r) => r.key === 'username')?.value).toBe('alice')
  })

  it('extracts a credential from a kv string passed directly to analyze', () => {
    // Drives the LABEL_KV_REGEX branch of extractCredential().
    const cred = b64('alice:wonderland')
    const result = ANALYZER.analyze({ text: `creds: ${cred}` })
    expect(result.sections[0].rows.find((r) => r.key === 'username')?.value).toBe('alice')
  })

  it('throws when given a string that has no recognisable credential', () => {
    expect(() => ANALYZER.analyze({ text: 'not a credential at all' })).toThrow(/HTTP Basic credential/i)
  })

  it('exposes username and the masked password in the raw payload', () => {
    const cred = b64('alice:wonderland')
    const result = ANALYZER.analyze({ text: `Authorization: Basic ${cred}` })
    expect(result.raw).toEqual({ user: 'alice', passwordMasked: '********nd' })
  })

  it('returns an undefined raw payload for malformed credentials', () => {
    const bogus = b64('no-colon-just-text-this-is-long')
    const result = ANALYZER.analyze({ text: `Authorization: Basic ${bogus}` })
    expect(result.raw).toBeUndefined()
  })
})
