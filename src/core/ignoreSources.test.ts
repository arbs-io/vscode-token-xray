import { describe, expect, it } from 'vitest'
import { IgnoreSource, isIgnoredByAnySource } from './ignoreSources'

function src(baseDir: string, ...patterns: string[]): IgnoreSource {
  return { baseDir, patterns }
}

describe('isIgnoredByAnySource', () => {
  it('returns false when no sources match', () => {
    expect(isIgnoredByAnySource('/repo/src/x.ts', [src('/repo', '*.log')])).toBe(false)
  })

  it('returns true when a root pattern matches', () => {
    expect(isIgnoredByAnySource('/repo/x.log', [src('/repo', '*.log')])).toBe(true)
  })

  it('ignores a source whose baseDir is not an ancestor of the file', () => {
    expect(
      isIgnoredByAnySource('/elsewhere/x.log', [src('/repo', '*.log')])
    ).toBe(false)
  })

  it('applies nested .gitignore patterns relative to the nested dir', () => {
    // /repo/dist/.gitignore contains `cache/`
    const sources = [src('/repo/dist', 'cache/')]
    expect(isIgnoredByAnySource('/repo/dist/cache/file', sources)).toBe(true)
    expect(isIgnoredByAnySource('/repo/dist/other', sources)).toBe(false)
  })

  it('lets a deeper source override an ancestor verdict (gitignore precedence)', () => {
    // Root ignores *.secret; subfolder un-ignores its keep.secret.
    const sources = [
      src('/repo', '*.secret'),
      src('/repo/sub', '!keep.secret'),
    ]
    expect(isIgnoredByAnySource('/repo/x.secret', sources)).toBe(true)
    expect(isIgnoredByAnySource('/repo/sub/keep.secret', sources)).toBe(false)
    expect(isIgnoredByAnySource('/repo/sub/other.secret', sources)).toBe(true)
  })

  it('honours last-matching-rule-wins within a single source', () => {
    const sources = [src('/repo', '*.tmp', '!important.tmp')]
    expect(isIgnoredByAnySource('/repo/foo.tmp', sources)).toBe(true)
    expect(isIgnoredByAnySource('/repo/important.tmp', sources)).toBe(false)
  })

  it('returns false for the empty inputs', () => {
    expect(isIgnoredByAnySource('', [src('/repo', '*')])).toBe(false)
    expect(isIgnoredByAnySource('/repo/x', [])).toBe(false)
  })

  it('does not consider the source-directory itself as a relative path', () => {
    // The file IS the baseDir → no relative remainder → no match.
    expect(isIgnoredByAnySource('/repo', [src('/repo', '*')])).toBe(false)
  })
})
