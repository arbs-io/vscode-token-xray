import { describe, expect, it } from 'vitest'
import { matchesAnyGlob, matchesGlob } from './globMatch'

describe('matchesGlob', () => {
  it('matches simple basename patterns anywhere in the path', () => {
    expect(matchesGlob('foo.log', '*.log')).toBe(true)
    expect(matchesGlob('a/b/foo.log', '*.log')).toBe(true)
    expect(matchesGlob('a/b/foo.txt', '*.log')).toBe(false)
  })

  it('matches **/* test files anywhere', () => {
    expect(matchesGlob('foo.test.ts', '**/*.test.ts')).toBe(true)
    expect(matchesGlob('a/b/foo.test.ts', '**/*.test.ts')).toBe(true)
    expect(matchesGlob('foo.ts', '**/*.test.ts')).toBe(false)
  })

  it('handles node_modules/** anchored matches', () => {
    expect(matchesGlob('node_modules/foo.js', 'node_modules/**')).toBe(true)
    expect(matchesGlob('node_modules/a/b/c.js', 'node_modules/**')).toBe(true)
    expect(matchesGlob('src/node_modules/foo.js', 'node_modules/**')).toBe(false)
    expect(matchesGlob('src/foo.js', 'node_modules/**')).toBe(false)
  })

  it('handles `**` in the middle of a pattern', () => {
    expect(matchesGlob('src/foo/bar.ts', 'src/**/bar.ts')).toBe(true)
    expect(matchesGlob('src/bar.ts', 'src/**/bar.ts')).toBe(true)
    expect(matchesGlob('src/foo/baz/bar.ts', 'src/**/bar.ts')).toBe(true)
    expect(matchesGlob('lib/bar.ts', 'src/**/bar.ts')).toBe(false)
  })

  it('handles ? for single-character match', () => {
    expect(matchesGlob('a.ts', '?.ts')).toBe(true)
    expect(matchesGlob('ab.ts', '?.ts')).toBe(false)
    expect(matchesGlob('a/b.ts', '?.ts')).toBe(true) // unanchored, matches `b.ts`
  })

  it('handles character classes', () => {
    expect(matchesGlob('foo.ts', 'foo.[jt]s')).toBe(true)
    expect(matchesGlob('foo.js', 'foo.[jt]s')).toBe(true)
    expect(matchesGlob('foo.py', 'foo.[jt]s')).toBe(false)
  })

  it('treats an unclosed [ as literal', () => {
    expect(matchesGlob('foo[bar', 'foo[bar')).toBe(true)
  })

  it('anchors with a leading /', () => {
    expect(matchesGlob('a.log', '/a.log')).toBe(true)
    expect(matchesGlob('dir/a.log', '/a.log')).toBe(false)
  })

  it('treats a trailing / as directory contents', () => {
    expect(matchesGlob('dist/bundle.js', 'dist/')).toBe(true)
    expect(matchesGlob('a/dist/bundle.js', 'dist/')).toBe(true)
    expect(matchesGlob('disty/bundle.js', 'dist/')).toBe(false)
  })

  it('returns false for an empty pattern', () => {
    expect(matchesGlob('foo.ts', '')).toBe(false)
  })

  it('respects nocase option', () => {
    expect(matchesGlob('FOO.LOG', '*.log')).toBe(false)
    expect(matchesGlob('FOO.LOG', '*.log', { nocase: true })).toBe(true)
  })

  it('normalises Windows path separators', () => {
    expect(matchesGlob(String.raw`a\b\c.ts`, '**/*.ts')).toBe(true)
    expect(matchesGlob(String.raw`a\b\c.ts`, 'a/b/*.ts')).toBe(true)
  })

  it('strips a leading ./ from input', () => {
    expect(matchesGlob('./src/foo.ts', 'src/**')).toBe(true)
  })

  it('escapes regex metacharacters in literal segments', () => {
    expect(matchesGlob('a.b+c', 'a.b+c')).toBe(true)
    expect(matchesGlob('aXbYc', 'a.b+c')).toBe(false)
  })

  it('does not let * cross / boundaries', () => {
    expect(matchesGlob('a/b.ts', 'a*.ts')).toBe(false)
    expect(matchesGlob('ab.ts', 'a*.ts')).toBe(true)
  })
})

describe('matchesAnyGlob', () => {
  it('returns true when any pattern matches', () => {
    expect(matchesAnyGlob('foo.test.ts', ['**/*.spec.ts', '**/*.test.ts'])).toBe(true)
  })

  it('returns false when no pattern matches', () => {
    expect(matchesAnyGlob('foo.ts', ['**/*.test.ts', 'node_modules/**'])).toBe(false)
  })

  it('returns false for empty pattern array', () => {
    expect(matchesAnyGlob('foo.ts', [])).toBe(false)
  })

  it('honours nocase across all patterns', () => {
    expect(matchesAnyGlob('FOO.TEST.TS', ['**/*.test.ts'], { nocase: true })).toBe(true)
  })
})
