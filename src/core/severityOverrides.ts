import { Finding, Severity } from './types'

/**
 * Per-rule severity override value. `off` suppresses the finding outright;
 * the other three replace the finding's `severity` field.
 */
export type SeverityOverride = 'error' | 'warning' | 'info' | 'off'

/**
 * Mapping from rule id (or `prefix.*` wildcard) to a severity override.
 *
 *   { 'jwt.alg.none': 'warning',
 *     'secret.*':     'off',
 *     'oauth.github.pat': 'info' }
 *
 * Lookup precedence in `applySeverityOverrides`:
 *   1. exact-id match (case-sensitive),
 *   2. longest-prefix wildcard (`prefix.*`) match.
 *
 * Anything not covered passes through unchanged.
 */
export type SeverityOverrideMap = Record<string, SeverityOverride>

const VALID: ReadonlySet<SeverityOverride> = new Set<SeverityOverride>([
  'error',
  'warning',
  'info',
  'off',
])

/**
 * Pure filter: rewrite or drop findings according to a user-supplied
 * `tokenXray.ruleSeverity` map. The function is the registry-boundary
 * twin of `applyDisableComments` — both run on the pending findings
 * before they escape into vscode-shaped DTOs.
 *
 * Semantics per finding:
 *
 *   - if a matching override resolves to `off` → drop the finding,
 *   - if it resolves to `error` / `warning` / `info` → clone the
 *     finding with the new severity (input is never mutated),
 *   - otherwise → pass the finding through unchanged.
 *
 * Wildcard support: keys ending in `.*` apply to any finding id starting
 * with the literal prefix (the prefix is everything before `.*`).  An
 * exact id match always wins over a wildcard, and when multiple
 * wildcards could match, the longest prefix wins (so `secret.aws.*` beats
 * `secret.*`).
 *
 * The function is pure: no vscode imports, no I/O, never throws, never
 * mutates its inputs.
 */
interface SplitOverrides {
  exact: Map<string, SeverityOverride>
  wildcards: Array<{ prefix: string; value: SeverityOverride }>
}

function splitOverrides(overrides: SeverityOverrideMap): SplitOverrides {
  // Pre-split overrides into exact and wildcard buckets so we can pick
  // the most specific match per finding in O(wildcards) instead of
  // re-scanning the whole map.
  const exact = new Map<string, SeverityOverride>()
  const wildcards: Array<{ prefix: string; value: SeverityOverride }> = []
  for (const key of Object.keys(overrides)) {
    const value = overrides[key]
    if (!isValidOverride(value)) continue
    if (key.endsWith('.*')) {
      const prefix = key.slice(0, -2)
      if (prefix) wildcards.push({ prefix, value })
    } else if (key) {
      exact.set(key, value)
    }
  }
  // Longest prefix first so the first hit during iteration wins.
  wildcards.sort((a, b) => b.prefix.length - a.prefix.length)
  return { exact, wildcards }
}

function applyOverride(finding: Finding, override: SeverityOverride | undefined): Finding | undefined {
  if (override === undefined) return finding
  if (override === 'off') return undefined
  // Same severity — preserve reference identity so the no-op path is observably cheap.
  if (override === finding.severity) return finding
  return { ...finding, severity: override }
}

export function applySeverityOverrides(
  findings: Finding[],
  overrides: SeverityOverrideMap
): Finding[] {
  if (!findings || findings.length === 0) return findings ?? []
  if (!overrides || typeof overrides !== 'object') return findings.slice()

  const { exact, wildcards } = splitOverrides(overrides)

  const out: Finding[] = []
  for (const finding of findings) {
    const result = applyOverride(finding, resolveOverride(finding.id, exact, wildcards))
    if (result) out.push(result)
  }
  return out
}

function resolveOverride(
  findingId: string,
  exact: Map<string, SeverityOverride>,
  wildcards: Array<{ prefix: string; value: SeverityOverride }>
): SeverityOverride | undefined {
  const direct = exact.get(findingId)
  if (direct !== undefined) return direct

  for (const { prefix, value } of wildcards) {
    if (findingId === prefix) return value
    if (findingId.startsWith(prefix + '.')) return value
  }
  return undefined
}

function isValidOverride(value: unknown): value is SeverityOverride {
  return typeof value === 'string' && VALID.has(value as SeverityOverride)
}
