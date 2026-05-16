import { Analyzer, AnalysisResult, Match, Section, SectionRow } from '../../core/types'
import {
  DecodedSamlMetadata,
  SamlMetadataEntity,
  decodeSamlMetadata,
} from './decoder'
import { SamlMetadataFindingOptions, evaluateSamlMetadata } from './findings'

/**
 * SAML 2.0 metadata analyzer. Detects documents whose root element is
 * `EntityDescriptor` (single entity) or `EntitiesDescriptor` (multi-entity
 * wrapper) — distinct from the SAML *assertion* analyzer in `../saml/`.
 */

const ROOT_REGEX = /<(?:[a-z]+:)?(EntityDescriptor|EntitiesDescriptor)\b[\s\S]*?<\/(?:[a-z]+:)?\1>/i

export class SamlMetadataAnalyzer implements Analyzer {
  readonly id = 'samlMetadata'
  readonly name = 'SAML 2.0 metadata'

  constructor(private readonly options: SamlMetadataFindingOptions = {}) {}

  detect(text: string): Match[] {
    if (!text) return []
    const candidate = ROOT_REGEX.exec(text)
    if (!candidate) return []
    const start = candidate.index
    const end = start + candidate[0].length
    const slice = candidate[0]
    if (!decodeSamlMetadata(slice)) return []
    return [{ text: slice, range: { start, end } }]
  }

  analyze(match: Match): AnalysisResult {
    const decoded = decodeSamlMetadata(match.text)
    if (!decoded) {
      throw new Error('Input is not a SAML 2.0 metadata document.')
    }
    const findings = evaluateSamlMetadata(decoded, this.options)
    const sections: Section[] = decoded.entities.map((entity, index) =>
      buildEntitySection(entity, index)
    )
    return {
      analyzerId: this.id,
      kind: kindFor(decoded),
      sections,
      findings,
      raw: decoded,
    }
  }
}

function kindFor(decoded: DecodedSamlMetadata): string {
  if (decoded.rootKind === 'EntitiesDescriptor') return 'EntitiesDescriptor'
  const roles = decoded.entities[0]?.roles ?? []
  const kinds = Array.from(new Set(roles.map((r) => r.kind)))
  if (kinds.length === 0) return 'EntityDescriptor'
  return `EntityDescriptor (${kinds.join('+')})`
}

function buildEntitySection(entity: SamlMetadataEntity, index: number): Section {
  const rows: SectionRow[] = [
    { key: 'entityID', value: entity.entityId, description: 'Unique identifier of the entity.' },
  ]

  const roleKinds = entity.roles.map((r) => r.kind)
  rows.push({
    key: 'roles',
    value: roleKinds.length > 0 ? roleKinds.join(', ') : '(none)',
    description: 'Declared SAML roles (IdP / SP).',
  })

  const nameIdFormats = unique(entity.roles.flatMap((r) => r.nameIDFormats))
  if (nameIdFormats.length > 0) {
    rows.push({
      key: 'nameIDFormats',
      value: nameIdFormats.join(', '),
      description: 'NameID formats the entity supports.',
    })
  }

  const acsUrls = entity.roles
    .flatMap((r) => r.assertionConsumerServices ?? [])
    .map((acs) => acs.location)
  if (acsUrls.length > 0) {
    rows.push({
      key: 'assertionConsumerServices',
      value: acsUrls.join(', '),
      description: 'AssertionConsumerService Location URLs (SP).',
    })
  }

  const certs = entity.roles.flatMap((r) => r.signingCerts)
  if (certs.length === 0) {
    rows.push({
      key: 'signingCerts',
      value: '(none)',
      description: 'Signing certificates declared by the entity.',
    })
  } else {
    for (let i = 0; i < certs.length; i++) {
      const c = certs[i]
      rows.push({
        key: certs.length === 1 ? 'signingCert' : `signingCert[${i}]`,
        value: `${c.subject} (notAfter ${c.notAfter.toISOString()})`,
        description: 'Signing certificate subject + expiry.',
      })
    }
  }

  rows.push({
    key: 'signed',
    value: entity.signed ? 'true' : 'false',
    description: 'Whether the metadata itself carries a <ds:Signature>.',
  })

  return {
    id: `entity-${index}`,
    title: `Entity ${index + 1}: ${entity.entityId}`,
    rows,
  }
}

function unique(items: string[]): string[] {
  return Array.from(new Set(items))
}
