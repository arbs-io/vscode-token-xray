import { Analyzer, AnalysisResult, Match, Section, SectionRow } from '../../core/types'
import { decodeX509, extractCertificateBlocks } from './decoder'
import { evaluateX509, X509FindingOptions } from './findings'

export class X509Analyzer implements Analyzer {
  readonly id = 'x509'
  readonly name = 'X.509 certificate (PEM)'

  constructor(private readonly options: X509FindingOptions = {}) {}

  detect(text: string): Match[] {
    if (!text) return []
    return extractCertificateBlocks(text).map((block) => ({
      text: block.pem,
      range: { start: block.start, end: block.end },
    }))
  }

  analyze(match: Match): AnalysisResult {
    const decoded = decodeX509(match.text)
    const findings = evaluateX509(decoded, this.options)

    const rows: SectionRow[] = [
      { key: 'subject', value: decoded.subject, description: 'Subject DN' },
      { key: 'issuer', value: decoded.issuer, description: 'Issuer DN' },
      { key: 'serialNumber', value: decoded.serialNumber, description: 'Serial number' },
      { key: 'validFrom', value: decoded.validFrom, description: 'Not Before' },
      { key: 'validTo', value: decoded.validTo, description: 'Not After' },
      { key: 'keyAlgorithm', value: decoded.keyAlgorithm, description: 'Public-key algorithm' },
      { key: 'keyDetails', value: decoded.keyDetails, description: 'Key size / curve' },
      { key: 'signatureAlgorithm', value: decoded.signatureAlgorithm, description: 'Signature algorithm' },
      { key: 'fingerprint256', value: decoded.fingerprint256, description: 'SHA-256 fingerprint' },
    ]

    if (decoded.subjectAltNames.length > 0) {
      rows.push({
        key: 'subjectAltNames',
        value: decoded.subjectAltNames.join(', '),
        description: 'Subject Alternative Names',
      })
    }
    if (decoded.keyUsage.length > 0) {
      rows.push({
        key: 'keyUsage',
        value: decoded.keyUsage.join(', '),
        description: 'Key usage extensions',
      })
    }
    if (decoded.isCA) {
      rows.push({ key: 'ca', value: 'true', description: 'CA certificate' })
    }
    if (decoded.selfSigned) {
      rows.push({ key: 'selfSigned', value: 'true', description: 'Subject == Issuer' })
    }

    const sections: Section[] = [{ id: 'certificate', title: 'Certificate', rows }]
    return {
      analyzerId: this.id,
      kind: decoded.isCA ? 'CA' : 'leaf',
      sections,
      findings,
      raw: decoded,
    }
  }
}
