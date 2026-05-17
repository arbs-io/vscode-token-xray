export type SameSite = 'Strict' | 'Lax' | 'None'

export interface CookieAttributes {
  domain?: string
  path?: string
  expires?: string
  maxAge?: number
  secure: boolean
  httpOnly: boolean
  sameSite?: SameSite
  partitioned: boolean
}

export interface ParsedCookie {
  name: string
  value: string
  attributes: CookieAttributes
}

export interface SetCookieMatch {
  raw: string
  value: string
  start: number
  end: number
}

const SET_COOKIE_LINE = /^[ \t]*Set-Cookie[ \t]*:[ \t]*([^\r\n]+)/gim

export function extractSetCookieHeaders(text: string): SetCookieMatch[] {
  if (!text) return []
  const out: SetCookieMatch[] = []
  SET_COOKIE_LINE.lastIndex = 0
  let m: RegExpExecArray | null
  while ((m = SET_COOKIE_LINE.exec(text)) !== null) {
    out.push({
      raw: m[0],
      value: m[1].trim(),
      start: m.index,
      end: m.index + m[0].length,
    })
  }
  return out
}

export function parseSetCookie(headerValue: string): ParsedCookie {
  const trimmed = headerValue.trim()
  if (trimmed.length === 0) throw new Error('Empty Set-Cookie value')

  const parts = splitAttributes(trimmed)
  const [namePair, ...attrs] = parts
  const eq = namePair.indexOf('=')
  if (eq < 0) throw new Error('Set-Cookie missing name=value pair')

  const name = namePair.slice(0, eq).trim()
  const value = stripQuotes(namePair.slice(eq + 1).trim())
  if (name.length === 0) throw new Error('Set-Cookie missing cookie name')

  const attributes: CookieAttributes = { secure: false, httpOnly: false, partitioned: false }
  for (const attr of attrs) {
    applyAttribute(attr.trim(), attributes)
  }
  return { name, value, attributes }
}

function splitAttributes(s: string): string[] {
  return s.split(';').map((p) => p.trim()).filter((p) => p.length > 0)
}

function stripQuotes(v: string): string {
  if (v.length >= 2 && v.startsWith('"') && v.endsWith('"')) return v.slice(1, -1)
  return v
}

function applyAttribute(attr: string, out: CookieAttributes): void {
  const eq = attr.indexOf('=')
  const rawName = (eq < 0 ? attr : attr.slice(0, eq)).trim().toLowerCase()
  const rawValue = eq < 0 ? '' : attr.slice(eq + 1).trim()

  switch (rawName) {
    case 'secure':
      out.secure = true
      return
    case 'httponly':
      out.httpOnly = true
      return
    case 'partitioned':
      out.partitioned = true
      return
    case 'domain':
      out.domain = rawValue.replace(/^\./, '') || rawValue
      return
    case 'path':
      out.path = rawValue
      return
    case 'expires':
      out.expires = rawValue
      return
    case 'max-age': {
      const n = Number(rawValue)
      if (Number.isFinite(n)) out.maxAge = n
      return
    }
    case 'samesite': {
      const v = rawValue.toLowerCase()
      if (v === 'strict') out.sameSite = 'Strict'
      else if (v === 'lax') out.sameSite = 'Lax'
      else if (v === 'none') out.sameSite = 'None'
      return
    }
  }
}
