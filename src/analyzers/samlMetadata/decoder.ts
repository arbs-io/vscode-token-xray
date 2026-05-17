import { X509Certificate } from 'node:crypto'
import { XMLParser } from 'fast-xml-parser'

/**
 * SAML 2.0 metadata decoder (OASIS sstc-saml-metadata-2.0).
 *
 * Distinct from the assertion analyzer in `../saml/`: this module parses the
 * IdP/SP *metadata* documents that describe SAML deployments — typically
 * served at `/FederationMetadata.xml` or `/sso/metadata` URLs. The root
 * element is `EntityDescriptor` (single entity) or `EntitiesDescriptor`
 * (multi-entity wrapper).
 *
 * No XML signature validation is performed — that would require a key store
 * and we do not make network calls at analysis time. We only record
 * *presence* of `<ds:Signature>` at the entity level so we can warn when a
 * metadata document is unsigned.
 */

export type SamlMetadataRoleKind = 'IdP' | 'SP'

export interface SamlMetadataSigningCert {
  notBefore: Date
  notAfter: Date
  subject: string
}

export interface SamlMetadataAssertionConsumerService {
  location: string
  binding: string
}

export interface SamlMetadataRole {
  kind: SamlMetadataRoleKind
  nameIDFormats: string[]
  assertionConsumerServices?: SamlMetadataAssertionConsumerService[]
  signingCerts: SamlMetadataSigningCert[]
}

export interface SamlMetadataEntity {
  entityId: string
  roles: SamlMetadataRole[]
  signed: boolean
}

export interface DecodedSamlMetadata {
  entities: SamlMetadataEntity[]
  rootKind: 'EntityDescriptor' | 'EntitiesDescriptor'
}

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@',
  removeNSPrefix: true,
  parseAttributeValue: false,
  parseTagValue: false,
  trimValues: true,
})

/**
 * Decode a SAML 2.0 metadata XML document. Returns `undefined` when the
 * input is not metadata (wrong root element, malformed XML, missing
 * entityID on a single EntityDescriptor, …). Never throws.
 */
function decodeFromEntitiesDescriptor(parsed: Record<string, unknown>): DecodedSamlMetadata | undefined {
  const root = parsed.EntitiesDescriptor as Record<string, unknown> | undefined
  if (!root) return undefined
  const eds = root.EntityDescriptor
  let list: unknown[]
  if (Array.isArray(eds)) list = eds
  else if (eds === undefined) list = []
  else list = [eds]
  const entities: SamlMetadataEntity[] = []
  for (const e of list) {
    const parsedEntity = parseEntity(e)
    if (parsedEntity) entities.push(parsedEntity)
  }
  if (entities.length === 0) return undefined
  return { entities, rootKind: 'EntitiesDescriptor' }
}

export function decodeSamlMetadata(xml: string): DecodedSamlMetadata | undefined {
  if (typeof xml !== 'string') return undefined
  const trimmed = xml.trim()
  if (!trimmed.startsWith('<')) return undefined

  let parsed: Record<string, unknown>
  try {
    parsed = parser.parse(trimmed) as Record<string, unknown>
  } catch {
    return undefined
  }

  if ('EntityDescriptor' in parsed) {
    const entity = parseEntity(parsed.EntityDescriptor)
    return entity ? { entities: [entity], rootKind: 'EntityDescriptor' } : undefined
  }

  if ('EntitiesDescriptor' in parsed) {
    return decodeFromEntitiesDescriptor(parsed)
  }

  return undefined
}

function parseEntity(node: unknown): SamlMetadataEntity | undefined {
  if (!node || typeof node !== 'object') return undefined
  const obj = node as Record<string, unknown>
  const entityId = asString(obj['@entityID'])
  if (!entityId) return undefined

  const roles: SamlMetadataRole[] = []
  const idp = obj.IDPSSODescriptor
  if (idp) {
    const list = Array.isArray(idp) ? idp : [idp]
    for (const r of list) roles.push(parseRole('IdP', r))
  }
  const sp = obj.SPSSODescriptor
  if (sp) {
    const list = Array.isArray(sp) ? sp : [sp]
    for (const r of list) roles.push(parseRole('SP', r))
  }

  return { entityId, roles, signed: Boolean(obj.Signature) }
}

function parseRole(kind: SamlMetadataRoleKind, node: unknown): SamlMetadataRole {
  const obj = (node && typeof node === 'object' ? (node as Record<string, unknown>) : {})
  const nameIDFormats = collectStrings(obj.NameIDFormat)
  const signingCerts = extractSigningCerts(obj.KeyDescriptor)
  const role: SamlMetadataRole = {
    kind,
    nameIDFormats,
    signingCerts,
  }
  if (kind === 'SP') {
    role.assertionConsumerServices = extractAssertionConsumerServices(obj.AssertionConsumerService)
  }
  return role
}

function extractAssertionConsumerServices(raw: unknown): SamlMetadataAssertionConsumerService[] {
  if (!raw) return []
  const list = Array.isArray(raw) ? raw : [raw]
  const out: SamlMetadataAssertionConsumerService[] = []
  for (const item of list) {
    if (!item || typeof item !== 'object') continue
    const acs = item as Record<string, unknown>
    const location = asString(acs['@Location'])
    const binding = asString(acs['@Binding'])
    if (location) out.push({ location, binding: binding ?? '' })
  }
  return out
}

function extractSigningCerts(raw: unknown): SamlMetadataSigningCert[] {
  if (!raw) return []
  const list = Array.isArray(raw) ? raw : [raw]
  const out: SamlMetadataSigningCert[] = []
  for (const item of list) {
    if (!item || typeof item !== 'object') continue
    const kd = item as Record<string, unknown>
    const use = asString(kd['@use'])
    // KeyDescriptor.use is optional; per spec, absence means the cert can be
    // used for either signing or encryption. Treat missing-use as signing too.
    if (use && use !== 'signing') continue
    const certs = readCertificates(kd.KeyInfo)
    for (const certPem of certs) {
      const decoded = safeDecodeCert(certPem)
      if (decoded) out.push(decoded)
    }
  }
  return out
}

function readCertificates(keyInfo: unknown): string[] {
  if (!keyInfo || typeof keyInfo !== 'object') return []
  const ki = keyInfo as Record<string, unknown>
  const data = ki.X509Data
  if (!data) return []
  const list = Array.isArray(data) ? data : [data]
  const out: string[] = []
  for (const item of list) {
    if (!item || typeof item !== 'object') continue
    const x = item as Record<string, unknown>
    const certs = x.X509Certificate
    if (certs === undefined) continue
    const certList = Array.isArray(certs) ? certs : [certs]
    for (const c of certList) {
      const text = asString(c)
      if (text) out.push(text)
    }
  }
  return out
}

function safeDecodeCert(b64: string): SamlMetadataSigningCert | undefined {
  const pem = wrapPem(b64)
  try {
    const cert = new X509Certificate(pem)
    return {
      notBefore: new Date(cert.validFrom),
      notAfter: new Date(cert.validTo),
      subject: cert.subject,
    }
  } catch {
    return undefined
  }
}

function wrapPem(b64: string): string {
  const compact = b64.replace(/\s+/g, '')
  const lines: string[] = []
  for (let i = 0; i < compact.length; i += 64) lines.push(compact.slice(i, i + 64))
  return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----\n`
}

function collectStrings(raw: unknown): string[] {
  if (raw === undefined || raw === null) return []
  const list = Array.isArray(raw) ? raw : [raw]
  const out: string[] = []
  for (const item of list) {
    const text = asString(item)
    if (text) out.push(text)
  }
  return out
}

function asString(value: unknown): string | undefined {
  if (typeof value === 'string') return value
  if (value && typeof value === 'object' && '#text' in value) {
    return String(value['#text'])
  }
  return undefined
}
