import { Finding, Section, Severity } from './types'

/**
 * Zero-based line/column coordinates of a finding within its source file.
 * Mirrors the shape produced by the diagnostics provider so the adapter
 * can pass `vscode.Diagnostic.range` values straight through.
 */
export interface FindingTreeRange {
  startLine: number
  startColumn: number
  endLine: number
  endColumn: number
}

/**
 * One workspace-wide finding entry. The pure builder accepts a flat list
 * of these and groups them into the analyzer → finding tree the provider
 * adapter renders in the Token X-Ray activity-bar view.
 */
export interface WorkspaceFinding {
  filePath: string
  analyzerId: string
  analyzerName: string
  finding: Finding
  range: FindingTreeRange
}

/**
 * One detected token with its full analysis. Used by `buildTokenTree`
 * to produce the richer per-token outline the activity-bar view renders.
 *
 * The fields mirror `AnalysisResult` (sections + findings) plus the
 * file location and analyzer identity needed by the provider adapter.
 */
export interface WorkspaceToken {
  filePath: string
  analyzerId: string
  analyzerName: string
  /** `AnalysisResult.kind` — short kind label like "JWS", "JWE", "cert (DER)". */
  kind: string
  range: FindingTreeRange
  sections: Section[]
  findings: Finding[]
}

/**
 * Discriminator for tree node kinds. The legacy `analyzerRoot` + `finding`
 * pair is kept for back-compat with `buildTree`; the token-rooted builder
 * emits the richer `tokenRoot` / `sectionGroup` / `sectionRow` /
 * `findingsGroup` set.
 */
export type TreeNodeKind =
  | 'analyzerRoot'
  | 'finding'
  | 'tokenRoot'
  | 'sectionGroup'
  | 'sectionRow'
  | 'findingsGroup'

/**
 * Plain-data tree node emitted by the pure builder. The vscode-aware
 * provider adapter converts these into `vscode.TreeItem` instances.
 *
 * Roots carry the analyzer id + name plus the severity breakdown so the
 * adapter can render badges without re-walking the children. Children
 * carry enough provenance (filePath + range + finding id/severity) for
 * the adapter to wire a `vscode.open` reveal command.
 */
export interface TreeNodeDto {
  /** Stable id (`analyzer:<id>` or `analyzer:<id>:<index>`) for the adapter to key on. */
  id: string
  kind: TreeNodeKind
  label: string
  /** Populated only for `analyzerRoot` nodes. */
  analyzerId?: string
  /** Populated only for `analyzerRoot` nodes. */
  analyzerName?: string
  /** Populated only for `analyzerRoot` nodes. */
  errorCount?: number
  /** Populated only for `analyzerRoot` nodes. */
  warningCount?: number
  /** Populated only for `analyzerRoot` nodes. */
  infoCount?: number
  /** Direct children — populated for analyzer roots, empty for findings. */
  children: TreeNodeDto[]
  /** Populated only for `finding` nodes. */
  filePath?: string
  /** Populated only for `finding` nodes. */
  range?: FindingTreeRange
  /** Populated only for `finding` nodes. */
  severity?: Severity
  /** Populated only for `finding` nodes. */
  findingId?: string
  /** Populated only for `finding` nodes. */
  message?: string
  /** Populated only for `sectionRow` nodes. */
  rowKey?: string
  /** Populated only for `sectionRow` nodes. */
  rowValue?: string
  /** Populated only for `sectionRow` nodes — surfaces hover tooltip text. */
  rowDescription?: string
  /** Optional `vscode.TreeItem.description` text — shown next to the label. */
  description?: string
}

/**
 * Severity priority for the per-analyzer sort: lower is more severe.
 * Used both for the analyzer ordering (by total error count desc, then
 * warning, then info) and the optional severity prefix on each finding
 * label.
 */
const SEVERITY_RANK: Record<Severity, number> = {
  error: 0,
  warning: 1,
  info: 2,
}

/**
 * Pure builder: groups workspace-wide findings by analyzer, sorts the
 * analyzer roots by total error count desc (then warning, then info,
 * then label), and sorts the children of each root by file path then
 * line. Returns one root per analyzer.
 *
 * The function never throws and never reads from anything but the
 * provided findings list. No vscode imports.
 */
export function buildTree(findings: readonly WorkspaceFinding[] | undefined | null): TreeNodeDto[] {
  if (!findings || findings.length === 0) return []

  const groups = new Map<string, WorkspaceFinding[]>()
  for (const entry of findings) {
    if (!entry?.finding) continue
    const key = entry.analyzerId
    let bucket = groups.get(key)
    if (!bucket) {
      bucket = []
      groups.set(key, bucket)
    }
    bucket.push(entry)
  }

  const roots: TreeNodeDto[] = []
  for (const [analyzerId, bucket] of groups) {
    if (bucket.length === 0) continue
    const analyzerName = bucket[0].analyzerName

    const sorted = bucket.slice().sort(compareFindings)
    const children: TreeNodeDto[] = sorted.map((entry, index) => buildFindingNode(entry, analyzerId, index))

    let errorCount = 0
    let warningCount = 0
    let infoCount = 0
    for (const entry of bucket) {
      if (entry.finding.severity === 'error') errorCount++
      else if (entry.finding.severity === 'warning') warningCount++
      else infoCount++
    }

    roots.push({
      id: `analyzer:${analyzerId}`,
      kind: 'analyzerRoot',
      label: `${analyzerName} (${bucket.length})`,
      analyzerId,
      analyzerName,
      errorCount,
      warningCount,
      infoCount,
      children,
    })
  }

  roots.sort(compareAnalyzerRoots)
  return roots
}

function buildFindingNode(
  entry: WorkspaceFinding,
  analyzerId: string,
  index: number
): TreeNodeDto {
  const severityPrefix = `[${entry.finding.severity}]`
  const locationSuffix = `${entry.filePath}:${entry.range.startLine + 1}`
  return {
    id: `analyzer:${analyzerId}:${index}`,
    kind: 'finding',
    label: `${severityPrefix} ${entry.finding.message} — ${locationSuffix}`,
    children: [],
    filePath: entry.filePath,
    range: { ...entry.range },
    severity: entry.finding.severity,
    findingId: entry.finding.id,
    message: entry.finding.message,
  }
}

function compareFindings(a: WorkspaceFinding, b: WorkspaceFinding): number {
  const pathDelta = a.filePath.localeCompare(b.filePath)
  if (pathDelta !== 0) return pathDelta
  const lineDelta = a.range.startLine - b.range.startLine
  if (lineDelta !== 0) return lineDelta
  return a.range.startColumn - b.range.startColumn
}

function compareAnalyzerRoots(a: TreeNodeDto, b: TreeNodeDto): number {
  const errorDelta = (b.errorCount ?? 0) - (a.errorCount ?? 0)
  if (errorDelta !== 0) return errorDelta
  const warningDelta = (b.warningCount ?? 0) - (a.warningCount ?? 0)
  if (warningDelta !== 0) return warningDelta
  const infoDelta = (b.infoCount ?? 0) - (a.infoCount ?? 0)
  if (infoDelta !== 0) return infoDelta
  return a.label.localeCompare(b.label)
}

/** Re-export the severity rank table for tests that want to assert on it. */
export const SEVERITY_RANK_TABLE: Readonly<Record<Severity, number>> = SEVERITY_RANK

/**
 * Token-centric tree builder. Emits one root per detected token, with the
 * analyzer's sections + findings as nested children:
 *
 *   tokenRoot — e.g. "JWT (JWS)" + description "sample.jwt:1"
 *     sectionGroup — e.g. "Header"
 *       sectionRow — "alg: HS256"
 *     sectionGroup — "Claims"
 *       sectionRow — "iss: …"
 *     findingsGroup — "Findings (N)" (omitted when there are no findings)
 *       finding — "[error] jwt.alg.none — …"
 *
 * Tokens are sorted by file path then start line. Pure — no vscode refs.
 */
export function buildTokenTree(
  tokens: readonly WorkspaceToken[] | undefined | null
): TreeNodeDto[] {
  if (!tokens || tokens.length === 0) return []
  const sorted = tokens.slice().sort(compareTokenLocation)
  return sorted.map((token, index) => buildTokenRoot(token, index))
}

function buildTokenRoot(token: WorkspaceToken, index: number): TreeNodeDto {
  const id = `token:${index}`
  let errorCount = 0
  let warningCount = 0
  let infoCount = 0
  for (const f of token.findings) {
    if (f.severity === 'error') errorCount++
    else if (f.severity === 'warning') warningCount++
    else infoCount++
  }

  const children: TreeNodeDto[] = []
  token.sections.forEach((section, sIdx) => {
    children.push(buildSectionGroup(section, id, sIdx))
  })
  if (token.findings.length > 0) {
    children.push(buildFindingsGroup(token.findings, id, token.filePath, token.range))
  }

  const kindSuffix = token.kind ? ` (${token.kind})` : ''
  return {
    id,
    kind: 'tokenRoot',
    label: `${token.analyzerName}${kindSuffix}`,
    description: `${token.filePath}:${token.range.startLine + 1}`,
    analyzerId: token.analyzerId,
    analyzerName: token.analyzerName,
    errorCount,
    warningCount,
    infoCount,
    children,
    filePath: token.filePath,
    range: { ...token.range },
  }
}

function buildSectionGroup(section: Section, parentId: string, sIdx: number): TreeNodeDto {
  const id = `${parentId}:section:${sIdx}`
  const rows = section.rows.map((row, rIdx) => buildSectionRow(row, id, rIdx))
  return {
    id,
    kind: 'sectionGroup',
    label: section.title,
    children: rows,
  }
}

function buildSectionRow(
  row: { key: string; value: unknown; description?: string },
  parentId: string,
  rIdx: number
): TreeNodeDto {
  const valueStr = stringifyRowValue(row.value)
  return {
    id: `${parentId}:row:${rIdx}`,
    kind: 'sectionRow',
    label: row.key,
    description: truncate(valueStr, 120),
    rowKey: row.key,
    rowValue: valueStr,
    rowDescription: row.description,
    children: [],
  }
}

function buildFindingsGroup(
  findings: readonly Finding[],
  parentId: string,
  filePath: string,
  range: FindingTreeRange
): TreeNodeDto {
  const id = `${parentId}:findings`
  const children = findings.map((f, fIdx) => ({
    id: `${id}:${fIdx}`,
    kind: 'finding' as const,
    label: `[${f.severity}] ${f.message}`,
    children: [],
    severity: f.severity,
    findingId: f.id,
    message: f.message,
    filePath,
    range: { ...range },
  }))
  return {
    id,
    kind: 'findingsGroup',
    label: `Findings (${findings.length})`,
    children,
  }
}

function compareTokenLocation(a: WorkspaceToken, b: WorkspaceToken): number {
  const pathDelta = a.filePath.localeCompare(b.filePath)
  if (pathDelta !== 0) return pathDelta
  const lineDelta = a.range.startLine - b.range.startLine
  if (lineDelta !== 0) return lineDelta
  return a.range.startColumn - b.range.startColumn
}

function stringifyRowValue(v: unknown): string {
  if (v === null || v === undefined) return ''
  if (typeof v === 'string') return v
  if (typeof v === 'number' || typeof v === 'boolean' || typeof v === 'bigint') return String(v)
  try {
    return JSON.stringify(v)
  } catch {
    return String(v)
  }
}

function truncate(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n - 1)}…` : s
}
