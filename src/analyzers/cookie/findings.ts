import { Finding } from '../../core/types'
import { ParsedCookie } from './parser'

const SENSITIVE_NAME_PATTERN = /^(?:session|sess|sid|auth|jwt|token|access_token|refresh_token|csrf|xsrf|user|sso)/i
const JWT_VALUE_PATTERN = /^eyJ[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]*$/

export function evaluateCookie(cookie: ParsedCookie): Finding[] {
  const findings: Finding[] = []
  const a = cookie.attributes
  const sensitive = SENSITIVE_NAME_PATTERN.test(cookie.name)

  if (a.sameSite === 'None' && !a.secure) {
    findings.push({
      id: 'cookie.sameSite.noneWithoutSecure',
      severity: 'error',
      message: '"SameSite=None" requires the "Secure" attribute. Modern browsers reject this combination.',
      docUrl: 'https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie/SameSite',
    })
  }

  if (!a.secure && (sensitive || a.sameSite === 'None')) {
    findings.push({
      id: 'cookie.secure.missing',
      severity: 'warning',
      message: `Sensitive cookie "${cookie.name}" is missing the "Secure" attribute — it would be sent over plaintext HTTP.`,
    })
  }

  if (!a.httpOnly && sensitive) {
    findings.push({
      id: 'cookie.httpOnly.missing',
      severity: 'warning',
      message: `Sensitive cookie "${cookie.name}" is missing "HttpOnly" — JavaScript can read it (XSS risk).`,
    })
  }

  if (!a.sameSite && sensitive) {
    findings.push({
      id: 'cookie.sameSite.missing',
      severity: 'info',
      message: `Sensitive cookie "${cookie.name}" has no SameSite — browsers default to Lax, but be explicit.`,
    })
  }

  if (a.expires === undefined && a.maxAge === undefined) {
    findings.push({
      id: 'cookie.expiry.missing',
      severity: 'info',
      message: 'No "Expires" or "Max-Age" — this is a session cookie. Confirm that is intentional.',
    })
  }

  if (a.domain && /^(?:\.)?(?:com|net|org|io|co|app|dev)$/i.test(a.domain)) {
    findings.push({
      id: 'cookie.domain.tooBroad',
      severity: 'warning',
      message: `Domain "${a.domain}" is a public suffix. Most browsers will reject this cookie.`,
    })
  }

  if (a.maxAge !== undefined && a.maxAge < 0) {
    findings.push({
      id: 'cookie.maxAge.deletion',
      severity: 'info',
      message: 'Negative Max-Age — this Set-Cookie is deleting the cookie.',
    })
  }

  if (JWT_VALUE_PATTERN.test(cookie.value)) {
    findings.push({
      id: 'cookie.value.jwt',
      severity: 'info',
      message: 'Cookie value is a JWT. Use the "Inspect JWT" CodeLens on the value for full decoding.',
    })
  }

  return findings
}
