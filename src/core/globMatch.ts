// Tiny gitignore-style glob matcher. No dependencies, no vscode imports.
//
// Supported syntax (a subset of .gitignore):
//   *           — matches any run of characters except `/`
//   ?           — matches any single character except `/`
//   **          — matches zero or more path segments (including `/`)
//   [abc]       — character class
//   leading `/` — anchors the pattern to the start of the input path
//   trailing `/` — matches a directory: pattern equivalent to `pattern/**`
//   pattern with no `/` (other than a possible trailing one) — matches anywhere
//     in the path (i.e. behaves like `**/pattern`)
//
// This is intentionally limited: we want predictable behaviour for the
// `tokenXray.secrets.exclude` setting and we don't want to add a dependency.

export interface GlobMatchOptions {
  /** Case-insensitive match (default false). */
  nocase?: boolean
}

/** Returns true when `path` matches the gitignore-style `pattern`. */
export function matchesGlob(path: string, pattern: string, options: GlobMatchOptions = {}): boolean {
  if (!pattern) return false
  const normalised = normalisePath(path)
  const re = compileGlob(pattern, options)
  return re.test(normalised)
}

/** Returns true when any pattern matches the path. Empty array → false. */
export function matchesAnyGlob(
  path: string,
  patterns: readonly string[],
  options: GlobMatchOptions = {}
): boolean {
  if (!patterns || patterns.length === 0) return false
  for (const pattern of patterns) {
    if (matchesGlob(path, pattern, options)) return true
  }
  return false
}

function normalisePath(path: string): string {
  // Normalise Windows separators and strip a leading `./`.
  let out = path.replace(/\\/g, '/')
  if (out.startsWith('./')) out = out.slice(2)
  return out
}

function compileGlob(pattern: string, options: GlobMatchOptions): RegExp {
  let p = pattern.replace(/\\/g, '/')

  // Trailing slash means "match this directory and everything under it".
  // We track it separately so the slash doesn't accidentally anchor the
  // pattern (gitignore semantics: `dist/` matches `dist` at any depth).
  const trailingDir = p.endsWith('/')
  if (trailingDir) p = p.slice(0, -1)

  // Anchor by default if the pattern contains an inner `/`. A leading `/`
  // forces anchoring even for slash-less patterns.
  let anchored = false
  if (p.startsWith('/')) {
    anchored = true
    p = p.slice(1)
  } else if (p.includes('/')) {
    anchored = true
  }

  if (trailingDir) p = p + '/**'

  let re = ''
  let i = 0
  while (i < p.length) {
    const c = p[i]
    if (c === '*') {
      if (p[i + 1] === '*') {
        // `**` — zero or more path segments.
        // `**/` consumes the slash too so it can match zero segments.
        if (p[i + 2] === '/') {
          re += '(?:.*/)?'
          i += 3
        } else {
          re += '.*'
          i += 2
        }
      } else {
        re += '[^/]*'
        i += 1
      }
    } else if (c === '?') {
      re += '[^/]'
      i += 1
    } else if (c === '[') {
      const close = p.indexOf(']', i + 1)
      if (close === -1) {
        re += String.raw`\[`
        i += 1
      } else {
        re += '[' + p.slice(i + 1, close) + ']'
        i = close + 1
      }
    } else if (/[.+^$(){}|]/.test(c)) {
      re += '\\' + c
      i += 1
    } else {
      re += c
      i += 1
    }
  }

  const flags = options.nocase ? 'i' : ''
  if (anchored) {
    return new RegExp('^' + re + '$', flags)
  }
  // Unanchored patterns match anywhere in the path: equivalent to `**/pattern`.
  return new RegExp('(?:^|/)' + re + '$', flags)
}
