export type Severity = 'info' | 'warning' | 'error'

export interface SourceRange {
  start: number
  end: number
}

export interface Finding {
  id: string
  severity: Severity
  message: string
  range?: SourceRange
  docUrl?: string
}

export interface SectionRow {
  key: string
  value: unknown
  description?: string
  iconKey?: string
}

export interface Section {
  id: string
  title: string
  rows: SectionRow[]
}

export interface AnalysisResult {
  analyzerId: string
  kind: string
  sections: Section[]
  findings: Finding[]
  raw?: unknown
}

export interface Match {
  text: string
  range?: SourceRange
}

export interface Analyzer {
  readonly id: string
  readonly name: string
  detect(text: string): Match[]
  analyze(match: Match): AnalysisResult | Promise<AnalysisResult>
}
