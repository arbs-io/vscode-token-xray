import { Analyzer, AnalysisResult, Finding, Match, Section, SectionRow } from '../../core/types'
import { decodeBasic, DecodedBasic } from './decoder'
import { findingsForDecodedBasic, findingsForMalformedBasic, maskPassword } from './findings'

/**
 * Header form: `Authorization: Basic <base64>`.
 * - Case-insensitive header name and scheme (some Java clients send `BASIC`).
 * - The credential portion is captured in group 1 and must consist solely
 *   of base64 alphabet characters (with optional padding).
 * - Length floor of 8 keeps us out of obvious false positives like
 *   `Basic abc`.
 */
const AUTH_HEADER_REGEX = /Authorization\s*[:=]\s*Basic\s+([A-Z0-9+/_=-]{8,})/gi

/**
 * Bare base64 adjacent to a label such as `BASIC_AUTH_CREDS=…`,
 * `Authorization = …`, or `auth: …`. Two separate sub-patterns keep the
 * intent obvious and let us test each shape in isolation:
 *
 *   1. ENV / dotenv style:  `BASIC_AUTH_CREDS=<base64>` (no quotes).
 *      Only `BASIC_AUTH(_CREDS|_CREDENTIALS)?`, `AUTH_BASIC`, and
 *      `AUTHORIZATION` are accepted as env keys — broader patterns
 *      would collide with unrelated labels like `OAUTH_TOKEN`.
 *   2. INI / YAML key form:  the key matches one of `auth`,
 *      `authorization`, `credentials`, `creds`, `basicAuth`,
 *      `basic-auth`, `basic_auth` (case-insensitive), optionally
 *      decorated with snake_case / kebab-case / camelCase context but
 *      not so loose that `oauth_token` slips through.
 *
 * Both require a length floor of 8 for the captured base64 to avoid
 * shouting at every `auth: yes` style key, AND the captured base64
 * must actually decode to a non-empty `user:pass` pair — that check
 * happens in `findInternalHits`.
 */
const BASE64_BODY = '[A-Za-z0-9+/_=-]{8,}'
const ENV_LABELS = '(?:BASIC_AUTH(?:_CREDS?|_CREDENTIALS?)?|AUTH_BASIC|AUTHORIZATION)'
const KV_LABELS = '(basic[_-]?auth|auth(?:orization)?|credentials|creds)'
const LABEL_ENV_REGEX = new RegExp(String.raw`(?<!\w)${ENV_LABELS}\s*=\s*["']?(${BASE64_BODY})["']?`, 'g')
const LABEL_KV_REGEX = new RegExp(String.raw`(?<!\w)${KV_LABELS}(?!\w)\s*[:=]\s*["']?(${BASE64_BODY})["']?`, 'gi')

interface InternalHit {
  /** Full text of the matched span (for downstream highlighting). */
  text: string
  /** Byte range of the matched span. */
  range: { start: number; end: number }
  /** Just the base64 credential portion. */
  credential: string
  /** Source form, useful for the rendered output. */
  form: 'header' | 'env' | 'kv'
}

function findInternalHits(text: string): InternalHit[] {
  if (!text) return []
  const hits: InternalHit[] = []
  const claimed: Array<{ start: number; end: number }> = []

  const claim = (start: number, end: number): boolean => {
    for (const c of claimed) {
      if (start < c.end && c.start < end) return false
    }
    claimed.push({ start, end })
    return true
  }

  // 1. Header form — always reported (we surface a `basic.cred.malformed`
  //    finding if it can't be decoded).
  AUTH_HEADER_REGEX.lastIndex = 0
  let m: RegExpExecArray | null
  while ((m = AUTH_HEADER_REGEX.exec(text)) !== null) {
    const start = m.index
    const end = start + m[0].length
    if (!claim(start, end)) continue
    hits.push({ text: m[0], range: { start, end }, credential: m[1], form: 'header' })
  }

  // 2. & 3. Label forms — only reported when the captured base64 actually
  //    decodes to a non-empty `user:pass`. The spec asks us to be
  //    conservative here because a generic label like `auth:` is easy to
  //    false-positive on.
  LABEL_ENV_REGEX.lastIndex = 0
  while ((m = LABEL_ENV_REGEX.exec(text)) !== null) {
    const start = m.index
    const end = start + m[0].length
    if (!claim(start, end)) continue
    if (!decodeBasic(m[1])) continue
    hits.push({ text: m[0], range: { start, end }, credential: m[1], form: 'env' })
  }

  LABEL_KV_REGEX.lastIndex = 0
  while ((m = LABEL_KV_REGEX.exec(text)) !== null) {
    const start = m.index
    const end = start + m[0].length
    if (!claim(start, end)) continue
    if (!decodeBasic(m[2])) continue
    hits.push({ text: m[0], range: { start, end }, credential: m[2], form: 'kv' })
  }

  hits.sort((a, b) => a.range.start - b.range.start)
  return hits
}

function extractCredential(text: string): string | undefined {
  // Try the header form first (most specific), then the env form, then
  // the generic key-value form. We trim the input so a caller can pass
  // a wider context line.
  const trimmed = text.trim()

  AUTH_HEADER_REGEX.lastIndex = 0
  const h = AUTH_HEADER_REGEX.exec(trimmed)
  if (h) return h[1]

  LABEL_ENV_REGEX.lastIndex = 0
  const e = LABEL_ENV_REGEX.exec(trimmed)
  if (e) return e[1]

  LABEL_KV_REGEX.lastIndex = 0
  const k = LABEL_KV_REGEX.exec(trimmed)
  if (k) return k[2]

  // Caller may have already extracted just the base64 portion.
  if (/^[A-Za-z0-9+/_=-]{8,}$/.test(trimmed)) return trimmed
  return undefined
}

export class BasicAuthAnalyzer implements Analyzer {
  readonly id = 'basicAuth'
  readonly name = 'HTTP Basic credentials'

  detect(text: string): Match[] {
    return findInternalHits(text).map((hit) => ({ text: hit.text, range: hit.range }))
  }

  analyze(match: Match): AnalysisResult {
    const credential = extractCredential(match.text)
    if (credential === undefined) {
      throw new Error('Input does not look like an HTTP Basic credential.')
    }
    const decoded = decodeBasic(credential)
    if (!decoded) {
      return malformedResult(this.id)
    }
    return decodedResult(this.id, decoded)
  }
}

function decodedResult(analyzerId: string, decoded: DecodedBasic): AnalysisResult {
  const rows: SectionRow[] = [
    { key: 'username', value: decoded.user, description: 'Decoded username' },
    {
      key: 'password (masked)',
      value: maskPassword(decoded.password),
      description: 'Password is masked to the last 2 characters — the cleartext value is in the source file.',
    },
  ]
  const sections: Section[] = [{ id: 'credentials', title: 'Credentials', rows }]
  const findings: Finding[] = findingsForDecodedBasic(decoded)
  return {
    analyzerId,
    kind: 'HTTP Basic',
    sections,
    findings,
    raw: { user: decoded.user, passwordMasked: maskPassword(decoded.password) },
  }
}

function malformedResult(analyzerId: string): AnalysisResult {
  const rows: SectionRow[] = [
    {
      key: 'status',
      value: 'malformed',
      description: 'The Authorization: Basic header was present but the credential could not be decoded.',
    },
  ]
  const sections: Section[] = [{ id: 'credentials', title: 'Credentials', rows }]
  const findings: Finding[] = findingsForMalformedBasic()
  return {
    analyzerId,
    kind: 'HTTP Basic (malformed)',
    sections,
    findings,
    raw: undefined,
  }
}
