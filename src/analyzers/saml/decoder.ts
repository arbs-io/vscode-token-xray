import { inflateRawSync } from 'node:zlib'
import { XMLParser } from 'fast-xml-parser'

export interface SamlSubject {
  nameId?: string
  nameIdFormat?: string
}

export interface SamlConditions {
  notBefore?: string
  notOnOrAfter?: string
  audiences: string[]
}

export interface SamlSignatureInfo {
  present: boolean
  algorithm?: string
  digestAlgorithm?: string
}

export type SamlKind = 'Response' | 'Assertion' | 'EncryptedAssertion' | 'unknown'

export interface DecodedSaml {
  kind: SamlKind
  issuer?: string
  subject?: SamlSubject
  conditions?: SamlConditions
  signature: SamlSignatureInfo
  isEncrypted: boolean
  xml: string
}

const SAML_NAMESPACE_ASSERTION = 'urn:oasis:names:tc:SAML:2.0:assertion'
const SAML_NAMESPACE_PROTOCOL = 'urn:oasis:names:tc:SAML:2.0:protocol'

export function looksLikeSamlXml(text: string): boolean {
  const t = text.trim()
  if (!t.startsWith('<')) return false
  return (
    t.includes(SAML_NAMESPACE_ASSERTION) ||
    t.includes(SAML_NAMESPACE_PROTOCOL) ||
    /<(?:saml|samlp|ds)?:?(?:Response|Assertion|EncryptedAssertion)\b/.test(t)
  )
}

export function normaliseSamlInput(input: string): string {
  const trimmed = input.trim()
  if (looksLikeSamlXml(trimmed)) return trimmed

  if (!/^[A-Za-z0-9+/=_\-\s%]+$/.test(trimmed)) {
    throw new Error('Input does not look like SAML XML, base64, or URL-encoded base64')
  }

  const urlDecoded = /%[0-9A-Fa-f]{2}/.test(trimmed) ? decodeURIComponent(trimmed) : trimmed
  const standardised = urlDecoded.replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '')
  const buffer = Buffer.from(standardised, 'base64')
  if (buffer.length === 0) {
    throw new Error('Failed to base64-decode SAML input')
  }
  const asUtf8 = buffer.toString('utf8')
  if (looksLikeSamlXml(asUtf8)) return asUtf8.trim()

  try {
    const inflated = inflateRawSync(buffer).toString('utf8')
    if (looksLikeSamlXml(inflated)) return inflated.trim()
  } catch {
    // fall through
  }

  throw new Error('Decoded SAML input is not recognisable XML')
}

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@',
  removeNSPrefix: true,
  parseAttributeValue: false,
  parseTagValue: false,
  trimValues: true,
})

function pick<T = unknown>(obj: unknown, ...path: string[]): T | undefined {
  let cur: unknown = obj
  for (const key of path) {
    if (!cur || typeof cur !== 'object') return undefined
    cur = (cur as Record<string, unknown>)[key]
  }
  return cur as T | undefined
}

function asString(value: unknown): string | undefined {
  if (typeof value === 'string') return value
  if (value && typeof value === 'object' && '#text' in value) {
    return String((value as { '#text': unknown })['#text'])
  }
  return undefined
}

function detectKind(parsed: Record<string, unknown>): { kind: SamlKind; root: unknown } {
  if ('Response' in parsed) return { kind: 'Response', root: parsed.Response }
  if ('Assertion' in parsed) return { kind: 'Assertion', root: parsed.Assertion }
  if ('EncryptedAssertion' in parsed) return { kind: 'EncryptedAssertion', root: parsed.EncryptedAssertion }
  return { kind: 'unknown', root: undefined }
}

function extractAssertion(response: unknown): unknown {
  return pick(response, 'Assertion') ?? pick(response, 'EncryptedAssertion')
}

function extractAudiences(conditions: unknown): string[] {
  const ar = pick(conditions, 'AudienceRestriction')
  if (!ar) return []
  const audsRaw = pick(ar, 'Audience')
  if (audsRaw === undefined) return []
  const arr = Array.isArray(audsRaw) ? audsRaw : [audsRaw]
  return arr.map(asString).filter((v): v is string => typeof v === 'string')
}

function extractSignature(node: unknown): SamlSignatureInfo {
  const sig = pick(node, 'Signature')
  if (!sig) return { present: false }
  return {
    present: true,
    algorithm: asString(pick(sig, 'SignedInfo', 'SignatureMethod', '@Algorithm')),
    digestAlgorithm: asString(pick(sig, 'SignedInfo', 'Reference', 'DigestMethod', '@Algorithm')),
  }
}

export function decodeSaml(input: string): DecodedSaml {
  const xml = normaliseSamlInput(input)
  const parsed = parser.parse(xml) as Record<string, unknown>
  const { kind, root } = detectKind(parsed)
  if (kind === 'unknown' || !root) {
    return {
      kind,
      signature: { present: false },
      isEncrypted: false,
      xml,
    }
  }

  const assertionNode = kind === 'Response' ? extractAssertion(root) : root
  const isEncrypted = kind === 'EncryptedAssertion' || (kind === 'Response' && !!pick(root, 'EncryptedAssertion'))

  const issuerSource = isEncrypted ? root : assertionNode ?? root
  const issuer = asString(pick(issuerSource, 'Issuer'))

  let subject: SamlSubject | undefined
  let conditions: SamlConditions | undefined
  if (!isEncrypted && assertionNode) {
    const nameId = pick(assertionNode, 'Subject', 'NameID')
    if (nameId !== undefined) {
      subject = {
        nameId: asString(nameId),
        nameIdFormat: asString(pick(assertionNode, 'Subject', 'NameID', '@Format')),
      }
    }
    const cond = pick(assertionNode, 'Conditions')
    if (cond) {
      conditions = {
        notBefore: asString(pick(cond, '@NotBefore')),
        notOnOrAfter: asString(pick(cond, '@NotOnOrAfter')),
        audiences: extractAudiences(cond),
      }
    }
  }

  const signature = extractSignature(root)
  if (!signature.present && assertionNode) {
    Object.assign(signature, extractSignature(assertionNode))
  }

  return { kind, issuer, subject, conditions, signature, isEncrypted, xml }
}
