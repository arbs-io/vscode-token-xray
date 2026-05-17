import { describe, expect, it } from 'vitest'
import { BUILT_IN_SECRET_RULES, createRuleSet } from './rules'
import { SecretRule } from './types'

describe('BUILT_IN_SECRET_RULES', () => {
  it('has unique rule ids', () => {
    const ids = BUILT_IN_SECRET_RULES.map((r) => r.id)
    expect(new Set(ids).size).toBe(ids.length)
  })

  it('every rule uses the global flag', () => {
    for (const r of BUILT_IN_SECRET_RULES) {
      expect(r.pattern.flags).toContain('g')
    }
  })
})

describe('createRuleSet', () => {
  const FAKE: SecretRule = {
    id: 'demo.x',
    vendor: 'demo',
    name: 'Demo rule',
    pattern: /demo/g,
    severity: 'info',
    description: 'demo',
  }

  it('includes built-in rules plus extras', () => {
    const set = createRuleSet([FAKE])
    expect(set).toContain(FAKE)
    expect(set.length).toBe(BUILT_IN_SECRET_RULES.length + 1)
  })

  it('rejects duplicate ids', () => {
    expect(() => createRuleSet([BUILT_IN_SECRET_RULES[0]])).toThrow(/Duplicate/)
  })

  it('returns built-ins when called with no args', () => {
    expect(createRuleSet()).toEqual(BUILT_IN_SECRET_RULES)
  })
})
