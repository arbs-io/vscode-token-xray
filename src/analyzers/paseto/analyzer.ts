import { Analyzer, AnalysisResult, Match, Section, SectionRow } from '../../core/types'
import { decodePaseto, DecodedPaseto } from './decoder'
import { evaluatePaseto } from './findings'

const PASETO_TOKEN_REGEX = /v[1-4]\.(?:local|public)\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?/g

export class PasetoAnalyzer implements Analyzer {
  readonly id = 'paseto'
  readonly name = 'PASETO'

  detect(text: string): Match[] {
    if (!text) return []
    const matches: Match[] = []
    PASETO_TOKEN_REGEX.lastIndex = 0
    let m: RegExpExecArray | null
    while ((m = PASETO_TOKEN_REGEX.exec(text)) !== null) {
      const decoded = decodePaseto(m[0])
      if (!decoded) continue
      matches.push({ text: m[0], range: { start: m.index, end: m.index + m[0].length } })
    }
    return matches
  }

  analyze(match: Match): AnalysisResult {
    const decoded = decodePaseto(match.text)
    if (!decoded) {
      throw new Error('Input does not match the PASETO token shape.')
    }
    const findings = evaluatePaseto(decoded)
    const sections: Section[] = [headerSection(decoded)]
    const payloadSection = buildPayloadSection(decoded)
    if (payloadSection) sections.push(payloadSection)

    return {
      analyzerId: this.id,
      kind: `PASETO ${decoded.version}.${decoded.purpose}`,
      sections,
      findings,
      raw: decoded,
    }
  }
}

function headerSection(decoded: DecodedPaseto): Section {
  const rows: SectionRow[] = [
    { key: 'version', value: decoded.version, description: 'PASETO protocol version' },
    { key: 'purpose', value: decoded.purpose, description: '"local" = symmetric / encrypted, "public" = signed' },
  ]
  if (decoded.footer) {
    rows.push({ key: 'footer', value: decoded.footerDecoded ?? decoded.footer, description: 'Footer (authenticated, not encrypted)' })
  }
  return { id: 'header', title: 'Header', rows }
}

function buildPayloadSection(decoded: DecodedPaseto): Section | undefined {
  if (decoded.purpose === 'local') {
    return {
      id: 'payload',
      title: 'Payload',
      rows: [
        { key: 'payload', value: 'encrypted', description: 'Payload is encrypted; cannot inspect without the symmetric key.' },
      ],
    }
  }
  if (decoded.claims) {
    return {
      id: 'payload',
      title: 'Claims',
      rows: Object.entries(decoded.claims).map(([key, value]) => ({ key, value })),
    }
  }
  if (decoded.payloadInvalid) {
    return {
      id: 'payload',
      title: 'Payload',
      rows: [
        { key: 'payload', value: 'invalid', description: 'Could not decode payload as JSON claims.' },
      ],
    }
  }
  return undefined
}
