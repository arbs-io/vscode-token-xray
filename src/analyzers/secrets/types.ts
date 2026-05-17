import { Severity } from '../../core/types'

export interface SecretRuleContext {
  filename?: string
}

export interface SensitiveSpan {
  start: number
  end: number
}

export interface SecretRule {
  id: string
  vendor: string
  name: string
  pattern: RegExp
  severity: Severity
  description: string
  docUrl?: string
  validate?: (raw: string, ctx: SecretRuleContext) => boolean
  sensitiveSpan?: (raw: string) => SensitiveSpan
}

export interface SecretHit {
  rule: SecretRule
  text: string
  start: number
  end: number
  sensitiveStart: number
  sensitiveEnd: number
}
