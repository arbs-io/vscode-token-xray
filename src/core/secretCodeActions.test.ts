import { describe, expect, it } from 'vitest'
import { DiagnosticDto, DiagnosticRangeDto } from './diagnostics'
import {
  DEFAULT_ENV_EXAMPLE_FILE,
  REDACT_PLACEHOLDER,
  findingsToCodeActionDtos,
  isSecretDiagnostic,
} from './secretCodeActions'

function range(
  startLine: number,
  startColumn: number,
  endLine: number,
  endColumn: number
): DiagnosticRangeDto {
  return { startLine, startColumn, endLine, endColumn }
}

function secretDto(code: string, r: DiagnosticRangeDto, message = 'leak'): DiagnosticDto {
  return { source: 'secret', code, message, severity: 'error', range: r }
}

describe('isSecretDiagnostic', () => {
  it('accepts source=secret + code starting with secret.', () => {
    expect(isSecretDiagnostic(secretDto('secret.aws.accessKey', range(0, 0, 0, 1)))).toBe(true)
  })

  it('rejects non-secret source', () => {
    expect(
      isSecretDiagnostic({
        source: 'jwt',
        code: 'secret.aws.accessKey',
        message: 'm',
        severity: 'error',
        range: range(0, 0, 0, 1),
      })
    ).toBe(false)
  })

  it('rejects mismatched code namespace', () => {
    expect(
      isSecretDiagnostic({
        source: 'secret',
        code: 'jwt.alg.none',
        message: 'm',
        severity: 'error',
        range: range(0, 0, 0, 1),
      })
    ).toBe(false)
  })
})

describe('findingsToCodeActionDtos (empty / negative)', () => {
  it('returns [] for an empty findings list', () => {
    expect(findingsToCodeActionDtos([], 'irrelevant')).toEqual([])
  })

  it('ignores non-secret findings', () => {
    const text = 'eyJ.eyJ.'
    const dto: DiagnosticDto = {
      source: 'jwt',
      code: 'jwt.alg.none',
      message: 'alg=none',
      severity: 'error',
      range: range(0, 0, 0, text.length),
    }
    expect(findingsToCodeActionDtos([dto], text)).toEqual([])
  })

  it('skips secret findings with a degenerate (zero-length) range', () => {
    const text = 'AKIAIOSFODNN7EXAMPLE'
    const dto = secretDto('secret.aws.accessKey', range(0, 5, 0, 5))
    expect(findingsToCodeActionDtos([dto], text)).toEqual([])
  })

  it('skips secret findings whose range falls outside the document', () => {
    const text = 'short'
    const dto = secretDto('secret.aws.accessKey', range(5, 0, 5, 5))
    expect(findingsToCodeActionDtos([dto], text)).toEqual([])
  })
})

describe('findingsToCodeActionDtos (redact)', () => {
  it('emits a Redact action that replaces the whole span with matching-length asterisks', () => {
    const text = 'leak=AKIAIOSFODNN7EXAMPLE\n'
    const r = range(0, 5, 0, 25) // "AKIAIOSFODNN7EXAMPLE" — length 20
    const dto = secretDto('secret.aws.accessKey', r)
    const actions = findingsToCodeActionDtos([dto], text)
    const redact = actions.find((a) => a.title === 'Redact secret')
    expect(redact).toBeDefined()
    expect(redact!.kind).toBe('quickfix')
    expect(redact!.edits).toHaveLength(1)
    expect(redact!.edits[0].range).toEqual(r)
    expect(redact!.edits[0].newText).toBe('*'.repeat(20))
    expect(redact!.findingId).toBe('secret.aws.accessKey')
    expect(redact!.sideEffects).toBeUndefined()
  })

  it('uses a minimum of 3 asterisks for very short spans', () => {
    const text = 'k=ab'
    const r = range(0, 2, 0, 4) // span length 2
    const actions = findingsToCodeActionDtos([secretDto('secret.demo.tiny', r)], text)
    const redact = actions.find((a) => a.title === 'Redact secret')
    expect(redact!.edits[0].newText).toBe('***')
  })

  it('honours a non-whole sensitiveSpan range (range narrower than the full match)', () => {
    // Mirrors the rules.ts pattern where rules emit findings whose range is
    // the *sensitive span* (the secret value) rather than the full match.
    const text = 'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
    const valueStart = text.indexOf('wJal')
    const r = range(0, valueStart, 0, text.length)
    const actions = findingsToCodeActionDtos(
      [secretDto('secret.aws.secretAccessKey', r)],
      text
    )
    const redact = actions.find((a) => a.title === 'Redact secret')
    expect(redact!.edits[0].newText).toBe('*'.repeat(text.length - valueStart))
    // The label "AWS_SECRET_ACCESS_KEY" before the `=` must remain.
    expect(redact!.edits[0].range.startColumn).toBe(valueStart)
  })
})

describe('findingsToCodeActionDtos (move to .env.example)', () => {
  it('emits an action whose edit replaces the secret with <REDACTED>', () => {
    const text = 'API_KEY=AKIAIOSFODNN7EXAMPLE'
    const start = text.indexOf('AKIA')
    const dto = secretDto('secret.aws.accessKey', range(0, start, 0, text.length))
    const actions = findingsToCodeActionDtos([dto], text)
    const move = actions.find((a) => a.title.startsWith('Move to '))
    expect(move).toBeDefined()
    expect(move!.title).toBe(`Move to ${DEFAULT_ENV_EXAMPLE_FILE}`)
    expect(move!.edits[0].newText).toBe(REDACT_PLACEHOLDER)
  })

  it('produces an appendToFile side-effect targeting .env.example', () => {
    const text = 'API_KEY=AKIAIOSFODNN7EXAMPLE'
    const start = text.indexOf('AKIA')
    const dto = secretDto('secret.aws.accessKey', range(0, start, 0, text.length))
    const actions = findingsToCodeActionDtos([dto], text)
    const move = actions.find((a) => a.title.startsWith('Move to '))!
    expect(move.sideEffects).toHaveLength(1)
    expect(move.sideEffects![0]).toEqual({
      kind: 'appendToFile',
      file: DEFAULT_ENV_EXAMPLE_FILE,
      line: `API_KEY=${REDACT_PLACEHOLDER}`,
    })
  })

  it('derives the env key from a "KEY: value" YAML-style label', () => {
    const text = 'AUTH0_CLIENT_SECRET: someSecretValue123'
    const start = text.indexOf('someSecret')
    const dto = secretDto('secret.auth0.clientSecret', range(0, start, 0, text.length))
    const move = findingsToCodeActionDtos([dto], text).find((a) =>
      a.title.startsWith('Move to ')
    )!
    expect(move.sideEffects![0].line).toBe(`AUTH0_CLIENT_SECRET=${REDACT_PLACEHOLDER}`)
  })

  it('derives the env key from a JSON-style "KEY": "value" label', () => {
    const text = '{"GITHUB_TOKEN":"ghp_abc123"}'
    const start = text.indexOf('ghp_')
    const dto = secretDto('secret.github.token', range(0, start, 0, start + 'ghp_abc123'.length))
    const move = findingsToCodeActionDtos([dto], text).find((a) =>
      a.title.startsWith('Move to ')
    )!
    expect(move.sideEffects![0].line).toBe(`GITHUB_TOKEN=${REDACT_PLACEHOLDER}`)
  })

  it('falls back to a rule-derived env key when no label is found', () => {
    const text = 'just a bare AKIAIOSFODNN7EXAMPLE in the middle of prose'
    const start = text.indexOf('AKIA')
    const dto = secretDto(
      'secret.aws.accessKey',
      range(0, start, 0, start + 'AKIAIOSFODNN7EXAMPLE'.length)
    )
    const move = findingsToCodeActionDtos([dto], text).find((a) =>
      a.title.startsWith('Move to ')
    )!
    // ruleIdToEnvKey('secret.aws.accessKey') → 'SECRET_AWS_ACCESS_KEY'
    expect(move.sideEffects![0].line).toBe(`SECRET_AWS_ACCESS_KEY=${REDACT_PLACEHOLDER}`)
  })

  it('handles an "export KEY=value" shell-style label', () => {
    const text = 'export STRIPE_API_KEY=sk_live_abcdef\n'
    const start = text.indexOf('sk_live')
    const dto = secretDto('secret.stripe.apiKey', range(0, start, 0, start + 'sk_live_abcdef'.length))
    const move = findingsToCodeActionDtos([dto], text).find((a) =>
      a.title.startsWith('Move to ')
    )!
    expect(move.sideEffects![0].line).toBe(`STRIPE_API_KEY=${REDACT_PLACEHOLDER}`)
  })
})

describe('findingsToCodeActionDtos (multi-finding inputs)', () => {
  it('emits two actions per qualifying finding', () => {
    const text = [
      'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE',
      'AUTH0_CLIENT_SECRET=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789',
    ].join('\n')
    const awsStart = text.indexOf('AKIA')
    const a0Start = text.indexOf('AbCd')
    const dtos: DiagnosticDto[] = [
      secretDto('secret.aws.accessKey', range(0, awsStart, 0, awsStart + 'AKIAIOSFODNN7EXAMPLE'.length)),
      secretDto(
        'secret.auth0.clientSecret',
        range(1, a0Start - (text.indexOf('\n') + 1), 1, text.length - (text.indexOf('\n') + 1))
      ),
    ]
    const actions = findingsToCodeActionDtos(dtos, text)
    expect(actions).toHaveLength(4) // 2 actions × 2 findings
    expect(actions.filter((a) => a.findingId === 'secret.aws.accessKey')).toHaveLength(2)
    expect(actions.filter((a) => a.findingId === 'secret.auth0.clientSecret')).toHaveLength(2)
  })

  it('ignores non-secret findings mixed in with secret ones', () => {
    const text = 'leak=AKIAIOSFODNN7EXAMPLE'
    const start = text.indexOf('AKIA')
    const dtos: DiagnosticDto[] = [
      secretDto('secret.aws.accessKey', range(0, start, 0, text.length)),
      {
        source: 'jwt',
        code: 'jwt.alg.none',
        message: 'alg=none',
        severity: 'error',
        range: range(0, 0, 0, text.length),
      },
    ]
    const actions = findingsToCodeActionDtos(dtos, text)
    expect(actions).toHaveLength(2) // only the secret produces actions
    expect(actions.every((a) => a.findingId === 'secret.aws.accessKey')).toBe(true)
  })

  it('produces stable kind="quickfix" on every action', () => {
    const text = 'API_KEY=secretvalue'
    const start = text.indexOf('secretvalue')
    const dto = secretDto('secret.generic.label', range(0, start, 0, text.length))
    const actions = findingsToCodeActionDtos([dto], text)
    expect(actions.every((a) => a.kind === 'quickfix')).toBe(true)
  })

  it('preserves diagnostic ordering for findings on different lines', () => {
    const text = ['leak1=AKIAIOSFODNN7EXAMPLE', 'leak2=ghp_abc123def456'].join('\n')
    const s1 = text.indexOf('AKIA')
    const s2 = text.indexOf('ghp_')
    const lineStartOf2 = text.indexOf('\n') + 1
    const dtos: DiagnosticDto[] = [
      secretDto(
        'secret.aws.accessKey',
        range(0, s1, 0, s1 + 'AKIAIOSFODNN7EXAMPLE'.length)
      ),
      secretDto(
        'secret.github.token',
        range(1, s2 - lineStartOf2, 1, s2 - lineStartOf2 + 'ghp_abc123def456'.length)
      ),
    ]
    const actions = findingsToCodeActionDtos(dtos, text)
    expect(actions[0].findingId).toBe('secret.aws.accessKey')
    expect(actions[2].findingId).toBe('secret.github.token')
  })
})

describe('findingsToCodeActionDtos (edge cases)', () => {
  it('threads the uri argument through without affecting output', () => {
    const text = 'API_KEY=secretvalue'
    const start = text.indexOf('secretvalue')
    const dto = secretDto('secret.generic.label', range(0, start, 0, text.length))
    const withUri = findingsToCodeActionDtos([dto], text, 'file:///tmp/a.env')
    const noUri = findingsToCodeActionDtos([dto], text)
    expect(withUri).toEqual(noUri)
  })

  it('does not derive a label that includes surrounding quotes', () => {
    const text = `"API_KEY":"sk_test_123"`
    const start = text.indexOf('sk_test')
    const dto = secretDto(
      'secret.stripe.testKey',
      range(0, start, 0, start + 'sk_test_123'.length)
    )
    const move = findingsToCodeActionDtos([dto], text).find((a) =>
      a.title.startsWith('Move to ')
    )!
    expect(move.sideEffects![0].line).toBe(`API_KEY=${REDACT_PLACEHOLDER}`)
  })

  it('emits a deterministic action shape across calls', () => {
    const text = 'API_KEY=AKIAIOSFODNN7EXAMPLE'
    const start = text.indexOf('AKIA')
    const dto = secretDto('secret.aws.accessKey', range(0, start, 0, text.length))
    const a = findingsToCodeActionDtos([dto], text)
    const b = findingsToCodeActionDtos([dto], text)
    expect(a).toEqual(b)
  })
})
