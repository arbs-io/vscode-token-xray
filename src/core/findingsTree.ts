import { Finding, Severity } from './types'

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
 * Discriminator for the two node kinds in the tree. Roots represent an
 * analyzer with one or more findings, children represent the individual
 * findings underneath that analyzer.
 */
export type TreeNodeKind = 'analyzerRoot' | 'finding'

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
    if (!entry || !entry.finding) continue
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
