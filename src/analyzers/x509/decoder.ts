import { X509Certificate, KeyObject } from 'node:crypto'
import { detectSignatureAlgorithm } from './sigalg'

export interface DecodedX509 {
  subject: string
  issuer: string
  serialNumber: string
  validFrom: string
  validTo: string
  subjectAltNames: string[]
  keyAlgorithm: string
  keyDetails: string
  signatureAlgorithm: string
  isCA: boolean
  keyUsage: string[]
  selfSigned: boolean
  fingerprint256: string
}

const PEM_REGEX = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g

export function extractCertificateBlocks(text: string): Array<{ pem: string; start: number; end: number }> {
  const out: Array<{ pem: string; start: number; end: number }> = []
  PEM_REGEX.lastIndex = 0
  let m: RegExpExecArray | null
  while ((m = PEM_REGEX.exec(text)) !== null) {
    out.push({ pem: m[0], start: m.index, end: m.index + m[0].length })
  }
  return out
}

export function decodeX509(pem: string): DecodedX509 {
  const cert = new X509Certificate(pem)
  const keyAlgorithm = cert.publicKey.asymmetricKeyType ?? 'unknown'
  const details = (cert.publicKey as KeyObject).asymmetricKeyDetails ?? {}
  const keyDetails = describeKey(keyAlgorithm, details)
  const subjectAltNames = parseSan(cert.subjectAltName)
  const selfSigned = cert.subject === cert.issuer

  return {
    subject: cert.subject,
    issuer: cert.issuer,
    serialNumber: cert.serialNumber,
    validFrom: cert.validFrom,
    validTo: cert.validTo,
    subjectAltNames,
    keyAlgorithm,
    keyDetails,
    signatureAlgorithm: detectSignatureAlgorithm(cert.raw),
    isCA: Boolean(cert.ca),
    keyUsage: cert.keyUsage ?? [],
    selfSigned,
    fingerprint256: cert.fingerprint256,
  }
}

function describeKey(
  alg: string,
  details: { modulusLength?: number; namedCurve?: string; publicExponent?: bigint }
): string {
  if (alg === 'rsa' && details.modulusLength) {
    return `RSA-${details.modulusLength}`
  }
  if (alg === 'ec' && details.namedCurve) {
    return `EC ${details.namedCurve}`
  }
  if (alg === 'ed25519' || alg === 'ed448') {
    return alg
  }
  return alg
}

function parseSan(san: string | undefined): string[] {
  if (!san) return []
  return san
    .split(/,\s*/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
}
