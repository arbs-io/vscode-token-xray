import { Analyzer, AnalysisResult, Match, Section, SectionRow } from '../../core/types'
import { evaluateCookie } from './findings'
import { extractSetCookieHeaders, parseSetCookie, ParsedCookie } from './parser'

export class CookieAnalyzer implements Analyzer {
  readonly id = 'cookie'
  readonly name = 'HTTP cookie (Set-Cookie)'

  detect(text: string): Match[] {
    if (!text) return []
    return extractSetCookieHeaders(text).map((hit) => ({
      text: hit.raw,
      range: { start: hit.start, end: hit.end },
    }))
  }

  analyze(match: Match): AnalysisResult {
    const [hit] = extractSetCookieHeaders(match.text)
    const value = hit ? hit.value : match.text
    const cookie = parseSetCookie(value)
    const findings = evaluateCookie(cookie)

    const rows: SectionRow[] = [
      { key: 'name', value: cookie.name, description: 'Cookie name' },
      { key: 'value', value: previewValue(cookie.value), description: 'Cookie value' },
    ]
    pushAttr(rows, 'domain', cookie.attributes.domain, 'Domain attribute')
    pushAttr(rows, 'path', cookie.attributes.path, 'Path attribute')
    pushAttr(rows, 'expires', cookie.attributes.expires, 'Expires')
    if (cookie.attributes.maxAge !== undefined) {
      rows.push({ key: 'maxAge', value: cookie.attributes.maxAge, description: 'Max-Age (seconds)' })
    }
    rows.push(
      { key: 'secure', value: String(cookie.attributes.secure), description: 'Secure attribute' },
      { key: 'httpOnly', value: String(cookie.attributes.httpOnly), description: 'HttpOnly attribute' },
    )
    if (cookie.attributes.sameSite) {
      rows.push({ key: 'sameSite', value: cookie.attributes.sameSite, description: 'SameSite policy' })
    }
    if (cookie.attributes.partitioned) {
      rows.push({ key: 'partitioned', value: 'true', description: 'Partitioned (CHIPS)' })
    }

    const sections: Section[] = [{ id: 'cookie', title: `Cookie: ${cookie.name}`, rows }]
    return {
      analyzerId: this.id,
      kind: cookie.name,
      sections,
      findings,
      raw: cookie,
    }
  }
}

function pushAttr(rows: SectionRow[], key: keyof ParsedCookie['attributes'], value: string | undefined, description: string) {
  if (value !== undefined && value !== '') {
    rows.push({ key, value, description })
  }
}

function previewValue(v: string): string {
  if (v.length <= 64) return v
  return `${v.slice(0, 40)}…${v.slice(-12)} (${v.length} chars)`
}
