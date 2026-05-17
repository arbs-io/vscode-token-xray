import { Analyzer, AnalysisResult, Finding, Match, Section, SectionRow } from '../../core/types'
import { DecodedCsr, decodeCsr, extractCsrBlocks } from './decoder'
import { evaluateCsr, findingsForParseFailure } from './findings'

/**
 * CSR analyzer — surfaces subject DN, public-key algorithm/size, and
 * requested Subject Alternative Names from PKCS#10 Certificate Signing
 * Request PEM blocks.
 */
export class CsrAnalyzer implements Analyzer {
  readonly id = 'csr'
  readonly name = 'Certificate Signing Request'

  detect(text: string): Match[] {
    if (!text) return []
    return extractCsrBlocks(text).map((block) => ({
      text: block.pem,
      range: { start: block.start, end: block.end },
    }))
  }

  analyze(match: Match): AnalysisResult {
    const decoded = decodeCsr(match.text)
    if (!decoded) {
      return buildParseFailureResult(this.id)
    }
    return buildResult(this.id, decoded)
  }
}

function buildResult(analyzerId: string, decoded: DecodedCsr): AnalysisResult {
  const rows: SectionRow[] = [
    { key: 'subject', value: decoded.subject, description: 'Subject DN requested in the CSR.' },
    { key: 'algorithm', value: formatAlgorithm(decoded), description: 'Public-key algorithm.' },
  ]
  if (decoded.keyAlgorithm === 'rsa' && typeof decoded.keyBits === 'number') {
    rows.push({
      key: 'keySize',
      value: `${decoded.keyBits} bits`,
      description: 'RSA modulus bit length.',
    })
  }
  if (decoded.keyAlgorithm === 'ec' && decoded.curve) {
    rows.push({ key: 'curve', value: decoded.curve, description: 'EC named curve.' })
  }
  rows.push({
    key: 'subjectAltNames',
    value: decoded.subjectAltNames.length > 0 ? decoded.subjectAltNames.join(', ') : '(none requested)',
    description: 'Requested Subject Alternative Names.',
  })

  const sections: Section[] = [{ id: 'subjectKey', title: 'Subject & Key', rows }]
  const findings: Finding[] = evaluateCsr(decoded)
  return {
    analyzerId,
    kind: 'PKCS#10 CSR',
    sections,
    findings,
    raw: decoded,
  }
}

function buildParseFailureResult(analyzerId: string): AnalysisResult {
  const rows: SectionRow[] = [
    {
      key: 'status',
      value: 'parse failed',
      description: 'The PEM block was recognised as a CERTIFICATE REQUEST but the DER could not be parsed.',
    },
  ]
  const sections: Section[] = [{ id: 'subjectKey', title: 'Subject & Key', rows }]
  return {
    analyzerId,
    kind: 'PKCS#10 CSR (malformed)',
    sections,
    findings: findingsForParseFailure(),
    raw: undefined,
  }
}

function formatAlgorithm(decoded: DecodedCsr): string {
  if (decoded.keyAlgorithm === 'rsa') return 'RSA'
  if (decoded.keyAlgorithm === 'ec') return decoded.curve ? `EC (${decoded.curve})` : 'EC'
  if (decoded.keyAlgorithm === 'ed25519') return 'Ed25519'
  if (decoded.keyAlgorithm === 'ed448') return 'Ed448'
  return decoded.keyAlgorithm
}
