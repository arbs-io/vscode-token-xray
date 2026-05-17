import { describe, expect, it } from 'vitest'
import { applyDisableComments, FindingWithLocation } from './disableComments'
import { Finding } from './types'

function f(overrides: Partial<Finding> & { id: string; startLine: number }): FindingWithLocation {
  return {
    severity: 'warning',
    message: 'msg',
    ...overrides,
  }
}

describe('applyDisableComments', () => {
  describe('input guards', () => {
    it('returns [] for nullish findings', () => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      expect(applyDisableComments(undefined as any, '')).toEqual([])
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      expect(applyDisableComments(null as any, 'text')).toEqual([])
    })

    it('returns the input copy unchanged when findings is empty', () => {
      expect(applyDisableComments([], 'text')).toEqual([])
    })

    it('returns a copy of findings when text is empty (no directives possible)', () => {
      const findings = [f({ id: 'jwt.alg.none', startLine: 0 })]
      const out = applyDisableComments(findings, '')
      expect(out).toEqual(findings)
      expect(out).not.toBe(findings)
    })

    it('returns a copy of findings when text has no directives', () => {
      const findings = [f({ id: 'jwt.alg.none', startLine: 0 })]
      const out = applyDisableComments(findings, 'just code, no comments\n')
      expect(out).toEqual(findings)
      expect(out).not.toBe(findings)
    })

    it('never mutates the input array', () => {
      const findings = [
        f({ id: 'jwt.alg.none', startLine: 1 }),
        f({ id: 'secret.aws.akid', startLine: 2 }),
      ]
      const snapshot = findings.slice()
      const text = '// tokenxray-disable-next-line jwt.alg.none\ntoken-here\nakid-here\n'
      applyDisableComments(findings, text)
      expect(findings).toEqual(snapshot)
    })
  })

  describe('tokenxray-disable-next-line (// comment style)', () => {
    it('suppresses a single rule on the line directly below', () => {
      const text = '// tokenxray-disable-next-line jwt.alg.none\neyJ.alg.none\n'
      const findings = [f({ id: 'jwt.alg.none', startLine: 1 })]
      expect(applyDisableComments(findings, text)).toEqual([])
    })

    it('suppresses across blank lines between the directive and the next finding', () => {
      const text = '// tokenxray-disable-next-line jwt.alg.none\n\n\neyJ.alg.none\n'
      const findings = [f({ id: 'jwt.alg.none', startLine: 3 })]
      expect(applyDisableComments(findings, text)).toEqual([])
    })

    it('does not suppress findings on later (non-target) lines', () => {
      const text = '// tokenxray-disable-next-line jwt.alg.none\ntoken-here\nother-line\n'
      const onTarget = f({ id: 'jwt.alg.none', startLine: 1 })
      const elsewhere = f({ id: 'jwt.alg.none', startLine: 2 })
      const out = applyDisableComments([onTarget, elsewhere], text)
      expect(out).toEqual([elsewhere])
    })

    it('does not affect findings on the comment line itself', () => {
      const text = '// tokenxray-disable-next-line jwt.alg.none\ntoken-here\n'
      const onComment = f({ id: 'jwt.alg.none', startLine: 0 })
      const out = applyDisableComments([onComment], text)
      expect(out).toEqual([onComment])
    })

    it('does not affect a finding for a different rule on the same target line', () => {
      const text = '// tokenxray-disable-next-line jwt.alg.none\nbadthing\n'
      const out = applyDisableComments(
        [
          f({ id: 'jwt.alg.none', startLine: 1 }),
          f({ id: 'secret.aws.akid', startLine: 1 }),
        ],
        text
      )
      expect(out).toEqual([f({ id: 'secret.aws.akid', startLine: 1 })])
    })

    it('honours leading whitespace before the comment marker', () => {
      const text = '    // tokenxray-disable-next-line jwt.alg.none\nbadthing\n'
      const out = applyDisableComments([f({ id: 'jwt.alg.none', startLine: 1 })], text)
      expect(out).toEqual([])
    })

    it('suppresses multiple rule ids listed on one comment', () => {
      const text =
        '// tokenxray-disable-next-line jwt.alg.none, secret.aws.akid\nrouting key here\n'
      const findings = [
        f({ id: 'jwt.alg.none', startLine: 1 }),
        f({ id: 'secret.aws.akid', startLine: 1 }),
        f({ id: 'saml.signature.missing', startLine: 1 }),
      ]
      const out = applyDisableComments(findings, text)
      expect(out).toEqual([f({ id: 'saml.signature.missing', startLine: 1 })])
    })

    it('ignores trailing `--` remarks after the rule list', () => {
      const text =
        '// tokenxray-disable-next-line jwt.alg.none -- expected for testing\neyJ.alg.none\n'
      expect(
        applyDisableComments([f({ id: 'jwt.alg.none', startLine: 1 })], text)
      ).toEqual([])
    })

    it('skips a directive that lists no rule ids', () => {
      const text = '// tokenxray-disable-next-line\neyJ.alg.none\n'
      const findings = [f({ id: 'jwt.alg.none', startLine: 1 })]
      expect(applyDisableComments(findings, text)).toEqual(findings)
    })

    it('skips a next-line directive with no following non-blank line', () => {
      const text = '// tokenxray-disable-next-line jwt.alg.none\n\n\n'
      // no findings should change because the directive has no target
      const findings = [f({ id: 'jwt.alg.none', startLine: 0 })]
      expect(applyDisableComments(findings, text)).toEqual(findings)
    })
  })

  describe('tokenxray-disable-next-line (# comment style)', () => {
    it('suppresses a single rule on the line directly below', () => {
      const text = '# tokenxray-disable-next-line secret.aws.akid\nAKIA1234567890ABCDEF\n'
      const findings = [f({ id: 'secret.aws.akid', startLine: 1 })]
      expect(applyDisableComments(findings, text)).toEqual([])
    })

    it('suppresses across blank lines', () => {
      const text = '# tokenxray-disable-next-line secret.aws.akid\n\nAKIA1234567890ABCDEF\n'
      const findings = [f({ id: 'secret.aws.akid', startLine: 2 })]
      expect(applyDisableComments(findings, text)).toEqual([])
    })

    it('handles leading whitespace before `#`', () => {
      const text = '\t# tokenxray-disable-next-line secret.aws.akid\nAKIA1234567890ABCDEF\n'
      const findings = [f({ id: 'secret.aws.akid', startLine: 1 })]
      expect(applyDisableComments(findings, text)).toEqual([])
    })

    it('supports multiple rule ids with `#` style', () => {
      const text = '# tokenxray-disable-next-line secret.aws.akid, jwt.alg.none\nbadline\n'
      const findings = [
        f({ id: 'secret.aws.akid', startLine: 1 }),
        f({ id: 'jwt.alg.none', startLine: 1 }),
      ]
      expect(applyDisableComments(findings, text)).toEqual([])
    })
  })

  describe('tokenxray-disable-file', () => {
    it('suppresses matching findings anywhere in the file (// style)', () => {
      const text =
        'line0\n// tokenxray-disable-file secret.aws.akid\nAKIA111\nAKIA222\nAKIA333\n'
      const findings = [
        f({ id: 'secret.aws.akid', startLine: 2 }),
        f({ id: 'secret.aws.akid', startLine: 3 }),
        f({ id: 'secret.aws.akid', startLine: 4 }),
      ]
      expect(applyDisableComments(findings, text)).toEqual([])
    })

    it('suppresses matching findings anywhere in the file (# style)', () => {
      const text =
        '# tokenxray-disable-file secret.aws.akid\nline1\nAKIA111\nline3\nAKIA222\n'
      const findings = [
        f({ id: 'secret.aws.akid', startLine: 2 }),
        f({ id: 'secret.aws.akid', startLine: 4 }),
      ]
      expect(applyDisableComments(findings, text)).toEqual([])
    })

    it('only affects listed rule ids — others pass through', () => {
      const text = '# tokenxray-disable-file secret.aws.akid\nbody\n'
      const findings = [
        f({ id: 'secret.aws.akid', startLine: 1 }),
        f({ id: 'jwt.alg.none', startLine: 1 }),
      ]
      expect(applyDisableComments(findings, text)).toEqual([
        f({ id: 'jwt.alg.none', startLine: 1 }),
      ])
    })

    it('supports multiple rule ids on one file-scope directive', () => {
      const text = '// tokenxray-disable-file secret.aws.akid, jwt.alg.none\nbody\n'
      const findings = [
        f({ id: 'secret.aws.akid', startLine: 1 }),
        f({ id: 'jwt.alg.none', startLine: 1 }),
        f({ id: 'saml.signature.missing', startLine: 1 }),
      ]
      expect(applyDisableComments(findings, text)).toEqual([
        f({ id: 'saml.signature.missing', startLine: 1 }),
      ])
    })
  })

  describe('wildcard `.*` matching', () => {
    it('matches every id under the prefix', () => {
      const text = '// tokenxray-disable-file secret.*\nbody\n'
      const findings = [
        f({ id: 'secret.aws.akid', startLine: 1 }),
        f({ id: 'secret.gcp.serviceAccount', startLine: 2 }),
        f({ id: 'secret.privateKey.pem', startLine: 3 }),
        f({ id: 'jwt.alg.none', startLine: 4 }),
      ]
      expect(applyDisableComments(findings, text)).toEqual([
        f({ id: 'jwt.alg.none', startLine: 4 }),
      ])
    })

    it('matches the bare prefix when used as `prefix.*`', () => {
      const text = '// tokenxray-disable-file secret.*\nbody\n'
      const out = applyDisableComments([f({ id: 'secret', startLine: 1 })], text)
      expect(out).toEqual([])
    })

    it('does not match unrelated ids', () => {
      const text = '// tokenxray-disable-file secret.*\nbody\n'
      const out = applyDisableComments(
        [
          f({ id: 'secretive.foo', startLine: 1 }), // not under secret.*
          f({ id: 'secret.aws.akid', startLine: 1 }),
        ],
        text
      )
      expect(out).toEqual([f({ id: 'secretive.foo', startLine: 1 })])
    })

    it('handles wildcards on next-line directives too', () => {
      const text = '// tokenxray-disable-next-line secret.*\nAKIA1\n'
      expect(
        applyDisableComments([f({ id: 'secret.aws.akid', startLine: 1 })], text)
      ).toEqual([])
    })

    it('does nothing when the wildcard has no prefix (`*` alone is not honoured)', () => {
      const text = '// tokenxray-disable-file .*\nbody\n'
      // `.*` parses as a rule id with empty prefix → matches nothing.
      const findings = [f({ id: 'jwt.alg.none', startLine: 1 })]
      expect(applyDisableComments(findings, text)).toEqual(findings)
    })
  })

  describe('directive recognition edge cases', () => {
    it('ignores comments that do not contain the verb', () => {
      const text = '// totally unrelated comment\nfinding-line\n'
      const findings = [f({ id: 'jwt.alg.none', startLine: 1 })]
      expect(applyDisableComments(findings, text)).toEqual(findings)
    })

    it('does not honour the directive when embedded mid-line', () => {
      // The verb must be the start of the comment after `//` or `#`.
      const text = 'code; // some-other-tag tokenxray-disable-next-line jwt.alg.none\nbad\n'
      const findings = [f({ id: 'jwt.alg.none', startLine: 1 })]
      expect(applyDisableComments(findings, text)).toEqual(findings)
    })

    it('tolerates CRLF line endings', () => {
      const text = '// tokenxray-disable-next-line jwt.alg.none\r\neyJ.alg.none\r\n'
      const findings = [f({ id: 'jwt.alg.none', startLine: 1 })]
      expect(applyDisableComments(findings, text)).toEqual([])
    })

    it('combines file-scope and next-line directives', () => {
      const text =
        '// tokenxray-disable-file secret.aws.akid\n' +
        'AKIA111\n' +
        '// tokenxray-disable-next-line jwt.alg.none\n' +
        'eyJ.alg.none\n'
      const findings = [
        f({ id: 'secret.aws.akid', startLine: 1 }),
        f({ id: 'jwt.alg.none', startLine: 3 }),
        f({ id: 'jwt.alg.none', startLine: 1 }), // not on jwt-target line
      ]
      const out = applyDisableComments(findings, text)
      // only the third remains: secret.aws.akid is file-suppressed,
      // jwt on line 3 is next-line suppressed.
      expect(out).toEqual([f({ id: 'jwt.alg.none', startLine: 1 })])
    })

    it('supports multiple next-line directives stacked in a file', () => {
      const text =
        '// tokenxray-disable-next-line jwt.alg.none\n' +
        'eyJ.alg.none\n' +
        'between\n' +
        '// tokenxray-disable-next-line secret.aws.akid\n' +
        'AKIA111\n'
      const findings = [
        f({ id: 'jwt.alg.none', startLine: 1 }),
        f({ id: 'secret.aws.akid', startLine: 4 }),
      ]
      expect(applyDisableComments(findings, text)).toEqual([])
    })

    it('drops a directive with empty trailing comment (whitespace only)', () => {
      const text = '// tokenxray-disable-next-line    \nbadthing\n'
      const findings = [f({ id: 'jwt.alg.none', startLine: 1 })]
      expect(applyDisableComments(findings, text)).toEqual(findings)
    })

    it('treats `--` immediately after the verb as a no-op directive', () => {
      const text = '// tokenxray-disable-next-line -- nothing\nbadthing\n'
      const findings = [f({ id: 'jwt.alg.none', startLine: 1 })]
      expect(applyDisableComments(findings, text)).toEqual(findings)
    })
  })
})
