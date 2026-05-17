import { describe, expect, it } from 'vitest'
import { matchIgnore, parseIgnoreFile } from './ignoreFile'

describe('parseIgnoreFile', () => {
  it('returns [] for an empty string', () => {
    expect(parseIgnoreFile('')).toEqual([])
  })

  it('skips blank lines and comment lines', () => {
    const text = [
      '# this is a comment',
      '',
      'node_modules/',
      '# another comment',
      '   ',
      '*.log',
    ].join('\n')
    expect(parseIgnoreFile(text)).toEqual(['node_modules/', '*.log'])
  })

  it('preserves order of remaining patterns', () => {
    const text = ['secrets.env', '*.log', '!keep.log', 'dist/', '!dist/important.js'].join('\n')
    expect(parseIgnoreFile(text)).toEqual([
      'secrets.env',
      '*.log',
      '!keep.log',
      'dist/',
      '!dist/important.js',
    ])
  })

  it('trims trailing whitespace from each line', () => {
    const text = ['node_modules/   ', '*.log\t', '!keep.log  '].join('\n')
    expect(parseIgnoreFile(text)).toEqual(['node_modules/', '*.log', '!keep.log'])
  })

  it('tolerates CRLF line endings', () => {
    const text = 'node_modules/\r\n# comment\r\n*.log\r\n'
    expect(parseIgnoreFile(text)).toEqual(['node_modules/', '*.log'])
  })

  it('does not treat `#` characters mid-line as comments', () => {
    // gitignore only treats `#` as a comment marker at the *start* of a line.
    expect(parseIgnoreFile('foo#bar')).toEqual(['foo#bar'])
  })

  it('drops a line whose entire content is whitespace', () => {
    // A whitespace-only line trims down to "" and is skipped.
    expect(parseIgnoreFile('   \n\t\n*.log\n')).toEqual(['*.log'])
  })

  it('keeps negation patterns intact for matchIgnore to consume later', () => {
    expect(parseIgnoreFile('!important.log\n')).toEqual(['!important.log'])
  })

  it('treats a comment with leading whitespace as a real pattern', () => {
    // gitignore comment markers must be at column 0. Leading whitespace
    // disables the comment behaviour. We preserve that quirk so users
    // can still ignore a file literally named `#test` via `\#test`-style
    // workarounds if they ever need to.
    expect(parseIgnoreFile('  # not actually a comment')).toEqual(['  # not actually a comment'])
  })
})

describe('matchIgnore', () => {
  describe('input guards', () => {
    it('returns false for empty path', () => {
      expect(matchIgnore('', ['*.log'])).toBe(false)
    })

    it('returns false for empty patterns', () => {
      expect(matchIgnore('foo.log', [])).toBe(false)
    })

    it('returns false for nullish patterns', () => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      expect(matchIgnore('foo.log', undefined as any)).toBe(false)
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      expect(matchIgnore('foo.log', null as any)).toBe(false)
    })

    it('skips empty pattern strings', () => {
      expect(matchIgnore('foo.log', ['', '*.log'])).toBe(true)
    })

    it('skips bare `!` (negation with no body)', () => {
      // Just `!` is nonsense — ignored entirely.
      expect(matchIgnore('foo.log', ['*.log', '!'])).toBe(true)
    })
  })

  describe('exact paths', () => {
    it('matches a literal filename', () => {
      expect(matchIgnore('secrets.env', ['secrets.env'])).toBe(true)
    })

    it('does not match a different filename', () => {
      expect(matchIgnore('public.env', ['secrets.env'])).toBe(false)
    })

    it('matches nested paths with anchored patterns', () => {
      expect(matchIgnore('src/secrets.env', ['src/secrets.env'])).toBe(true)
      expect(matchIgnore('lib/secrets.env', ['src/secrets.env'])).toBe(false)
    })
  })

  describe('glob patterns', () => {
    it('matches `*.test.ts` against test files at any depth', () => {
      expect(matchIgnore('foo.test.ts', ['*.test.ts'])).toBe(true)
      expect(matchIgnore('src/foo.test.ts', ['*.test.ts'])).toBe(true)
      expect(matchIgnore('src/foo.ts', ['*.test.ts'])).toBe(false)
    })

    it('matches `**/node_modules/**` for nested node_modules', () => {
      expect(matchIgnore('node_modules/foo.js', ['**/node_modules/**'])).toBe(true)
      expect(matchIgnore('a/node_modules/foo.js', ['**/node_modules/**'])).toBe(true)
      expect(matchIgnore('a/b/node_modules/c/d.js', ['**/node_modules/**'])).toBe(true)
      expect(matchIgnore('src/foo.js', ['**/node_modules/**'])).toBe(false)
    })

    it('matches a trailing-slash directory pattern', () => {
      expect(matchIgnore('dist/bundle.js', ['dist/'])).toBe(true)
      expect(matchIgnore('packages/app/dist/bundle.js', ['dist/'])).toBe(true)
      expect(matchIgnore('src/index.js', ['dist/'])).toBe(false)
    })

    it('respects anchored patterns with a leading slash', () => {
      expect(matchIgnore('build/out.js', ['/build/'])).toBe(true)
      expect(matchIgnore('src/build/out.js', ['/build/'])).toBe(false)
    })

    it('matches multiple patterns disjunctively', () => {
      const patterns = ['*.log', 'secrets.env', 'dist/']
      expect(matchIgnore('foo.log', patterns)).toBe(true)
      expect(matchIgnore('secrets.env', patterns)).toBe(true)
      expect(matchIgnore('dist/bundle.js', patterns)).toBe(true)
      expect(matchIgnore('src/index.ts', patterns)).toBe(false)
    })
  })

  describe('negations', () => {
    it('un-ignores a specific file matched by an earlier pattern', () => {
      // `*.log` ignores all logs, `!important.log` re-includes one.
      const patterns = ['*.log', '!important.log']
      expect(matchIgnore('foo.log', patterns)).toBe(true)
      expect(matchIgnore('important.log', patterns)).toBe(false)
    })

    it('does not affect files the negation does not match', () => {
      const patterns = ['*.log', '!keep.log']
      expect(matchIgnore('verbose.log', patterns)).toBe(true)
    })

    it('negation alone (with no prior ignore) is a no-op', () => {
      // matchIgnore starts in the "not ignored" state. A negation
      // pattern flips back to "not ignored" — same as no-op.
      expect(matchIgnore('important.log', ['!important.log'])).toBe(false)
    })

    it('a later ignore pattern re-ignores something a negation un-ignored', () => {
      // Last matching rule wins: *.log → !important.log → important.log
      const patterns = ['*.log', '!important.log', 'important.log']
      expect(matchIgnore('important.log', patterns)).toBe(true)
    })
  })

  describe('multiple-rule precedence', () => {
    it('honours last-matching-rule semantics across many flips', () => {
      // ignore everything, then un-ignore the keep file, then re-ignore.
      const patterns = ['*', '!keep.txt', 'keep.txt', '!keep.txt']
      expect(matchIgnore('keep.txt', patterns)).toBe(false)
      expect(matchIgnore('drop.txt', patterns)).toBe(true)
    })

    it('non-matching rules do not change the verdict', () => {
      // The trailing pattern doesn't match — verdict comes from *.log.
      const patterns = ['*.log', 'something-unrelated.txt']
      expect(matchIgnore('foo.log', patterns)).toBe(true)
    })

    it('handles directory ignore + nested file negation', () => {
      const patterns = ['dist/', '!dist/important.js']
      expect(matchIgnore('dist/bundle.js', patterns)).toBe(true)
      expect(matchIgnore('dist/important.js', patterns)).toBe(false)
    })

    it('works end-to-end with parseIgnoreFile output', () => {
      const text = ['# secrets', '*.env', '!.env.example', '', '# build output', 'dist/'].join('\n')
      const patterns = parseIgnoreFile(text)
      expect(matchIgnore('production.env', patterns)).toBe(true)
      expect(matchIgnore('.env.example', patterns)).toBe(false)
      expect(matchIgnore('dist/bundle.js', patterns)).toBe(true)
      expect(matchIgnore('src/index.ts', patterns)).toBe(false)
    })
  })
})
