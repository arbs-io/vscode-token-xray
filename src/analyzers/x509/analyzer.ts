import { Analyzer, AnalysisResult, Finding, Match, Section, SectionRow } from '../../core/types'
import { decodeX509, extractCertificateBlocks } from './decoder'
import { tryWrapDerAsPem } from './derWrap'
import { evaluateX509, X509FindingOptions } from './findings'

/**
 * Internal extended match. Carries an optional `encoding` tag so `analyze()`
 * can hint at DER vs PEM in the result without re-running detection.
 *
 * This is a structural superset of `Match` so it still satisfies the
 * `Analyzer.analyze(match: Match)` signature in `../../core/types`.
 */
interface X509Match extends Match {
  encoding?: 'pem' | 'der'
}

export class X509Analyzer implements Analyzer {
  readonly id = 'x509'
  readonly name = 'X.509 certificate (PEM)'

  constructor(private readonly options: X509FindingOptions = {}) {}

  detect(text: string): Match[] {
    if (!text) return []

    const pemBlocks = extractCertificateBlocks(text)
    if (pemBlocks.length > 0) {
      return pemBlocks.map<X509Match>((block) => ({
        text: block.pem,
        range: { start: block.start, end: block.end },
        encoding: 'pem',
      }))
    }

    // No PEM armor found — try base64-DER (common in .cer/.crt/.der exports).
    // `detect()` only receives text, not filename, so we rely on the
    // text-length fallback inside `tryWrapDerAsPem`.
    const wrapped = tryWrapDerAsPem(text)
    if (wrapped) {
      return [
        {
          text: wrapped,
          range: { start: 0, end: text.length },
          encoding: 'der',
        } as X509Match,
      ]
    }

    return []
  }

  analyze(match: Match): AnalysisResult {
    const decoded = decodeX509(match.text)
    const findings = evaluateX509(decoded, this.options)
    const encoding = (match as X509Match).encoding ?? 'pem'

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
      { key: 'encoding', value: encoding === 'der' ? 'DER (base64)' : 'PEM', description: 'Encoding' },
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

    if (encoding === 'der') {
      const derFinding: Finding = {
        id: 'x509.encoding.der',
        severity: 'info',
        message: 'Certificate is base64-DER encoded (no PEM armor). Common in .cer / .crt exports.',
      }
      findings.push(derFinding)
    }

    const kindSuffix = encoding === 'der' ? ' (DER)' : ''
    const sections: Section[] = [{ id: 'certificate', title: 'Certificate', rows }]
    return {
      analyzerId: this.id,
      kind: (decoded.isCA ? 'CA' : 'leaf') + kindSuffix,
      sections,
      findings,
      raw: decoded,
    }
  }
}
