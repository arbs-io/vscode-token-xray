import { describe, expect, it } from 'vitest'
import { scanForSecrets } from '../scanner'
import { AI_SECRET_RULES } from './ai'

const opts = { rules: AI_SECRET_RULES }

// Reusable filler strings sized for each provider's minimum length.
const ALNUM_48 = 'A'.repeat(24) + 'a'.repeat(12) + '0123456789' + 'KL' // 48
const ALNUM_60 = 'A'.repeat(30) + 'a'.repeat(20) + '0123456789' // 60
const ALNUM_93 = 'A'.repeat(40) + 'a'.repeat(40) + '0123456789' + 'xyz' // 93
const ALNUM_34 = 'A'.repeat(17) + 'a'.repeat(7) + '0123456789' // 34
const ALNUM_40 = ALNUM_34 + 'abcdef' // 40

describe('AI_SECRET_RULES — OpenAI classic secret key', () => {
  it('matches sk-<48 alnum>', () => {
    const text = `sk-${ALNUM_48}`
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'ai.openai.secretKey')
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(`sk-${ALNUM_48}`)
  })

  it('rejects short sk- strings (less than 48 chars after prefix)', () => {
    const short = 'sk-' + 'a'.repeat(20)
    expect(scanForSecrets(short, opts).some((h) => h.rule.id === 'ai.openai.secretKey')).toBe(false)
  })

  it('rejects CSS class name `.sk-loader { … }`', () => {
    expect(
      scanForSecrets('.sk-loader { color: red; }', opts).some(
        (h) => h.rule.id === 'ai.openai.secretKey'
      )
    ).toBe(false)
  })

  it('rejects JS identifier `sk-active` (also short)', () => {
    expect(
      scanForSecrets('const sk-active = true;', opts).some(
        (h) => h.rule.id === 'ai.openai.secretKey'
      )
    ).toBe(false)
  })

  it('rejects sk- with too many trailing alnum chars (49+) — boundary breaks', () => {
    // 49 alnum -> {48} would match but trailing alnum fails the lookahead.
    const text = `sk-${ALNUM_48}Z`
    expect(scanForSecrets(text, opts).some((h) => h.rule.id === 'ai.openai.secretKey')).toBe(false)
  })

  it('rejects `sk-` when preceded by a letter / underscore / dash (identifier context)', () => {
    expect(
      scanForSecrets(`x_sk-${ALNUM_48}`, opts).some((h) => h.rule.id === 'ai.openai.secretKey')
    ).toBe(false)
  })
})

describe('AI_SECRET_RULES — OpenAI project key', () => {
  it('matches sk-proj-<60+ chars>', () => {
    const text = `sk-proj-${ALNUM_60}`
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'ai.openai.projectKey')
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
  })

  it('matches sk-proj- with underscores / dashes in body', () => {
    const body = 'A'.repeat(30) + '_-' + 'a'.repeat(28) // 60 incl. _-
    const text = `sk-proj-${body}`
    expect(
      scanForSecrets(text, opts).some((h) => h.rule.id === 'ai.openai.projectKey')
    ).toBe(true)
  })

  it('rejects sk-proj- with too-short body (< 60 chars)', () => {
    const text = 'sk-proj-' + 'a'.repeat(30)
    expect(
      scanForSecrets(text, opts).some((h) => h.rule.id === 'ai.openai.projectKey')
    ).toBe(false)
  })
})

describe('AI_SECRET_RULES — OPENAI_API_KEY labelled', () => {
  it('matches OPENAI_API_KEY=<value> with sensitiveSpan over the value', () => {
    const value = `sk-${ALNUM_48}`
    const text = `OPENAI_API_KEY=${value}`
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'ai.openai.labelled')
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(value)
  })

  it('matches quoted JSON OPENAI_API_KEY style', () => {
    const value = 'a'.repeat(40)
    const text = `{"OPENAI_API_KEY": "${value}"}`
    expect(scanForSecrets(text, opts).some((h) => h.rule.id === 'ai.openai.labelled')).toBe(true)
  })

  it('rejects empty value `OPENAI_API_KEY=`', () => {
    expect(scanForSecrets('OPENAI_API_KEY=', opts).some((h) => h.rule.id === 'ai.openai.labelled')).toBe(false)
  })
})

describe('AI_SECRET_RULES — Anthropic API key', () => {
  it('matches sk-ant-api03-<93+ chars>', () => {
    const text = `sk-ant-api03-${ALNUM_93}`
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'ai.anthropic.apiKey')
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
  })

  it('matches sk-ant-admin01-<93+ chars>', () => {
    const text = `sk-ant-admin01-${ALNUM_93}`
    expect(scanForSecrets(text, opts).some((h) => h.rule.id === 'ai.anthropic.apiKey')).toBe(true)
  })

  it('rejects unknown sub-prefix `sk-ant-foo-…`', () => {
    const text = `sk-ant-foo-${ALNUM_93}`
    expect(scanForSecrets(text, opts).some((h) => h.rule.id === 'ai.anthropic.apiKey')).toBe(false)
  })

  it('rejects sk-ant-api03- with too-short body', () => {
    const text = `sk-ant-api03-${'a'.repeat(50)}`
    expect(scanForSecrets(text, opts).some((h) => h.rule.id === 'ai.anthropic.apiKey')).toBe(false)
  })
})

describe('AI_SECRET_RULES — ANTHROPIC_API_KEY labelled', () => {
  it('matches ANTHROPIC_API_KEY=<value>', () => {
    const value = `sk-ant-api03-${ALNUM_93}`
    const text = `ANTHROPIC_API_KEY=${value}`
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'ai.anthropic.labelled')
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(value)
  })

  it('rejects empty value `ANTHROPIC_API_KEY=`', () => {
    expect(
      scanForSecrets('ANTHROPIC_API_KEY=', opts).some((h) => h.rule.id === 'ai.anthropic.labelled')
    ).toBe(false)
  })
})

describe('AI_SECRET_RULES — Hugging Face token', () => {
  it('matches hf_<34+ alnum>', () => {
    const text = `hf_${ALNUM_34}`
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'ai.huggingface.token')
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
  })

  it('rejects `hf_short` (< 34 chars)', () => {
    expect(
      scanForSecrets('hf_short', opts).some((h) => h.rule.id === 'ai.huggingface.token')
    ).toBe(false)
  })

  it('rejects 33-char hf_ body', () => {
    expect(
      scanForSecrets('hf_' + 'a'.repeat(33), opts).some(
        (h) => h.rule.id === 'ai.huggingface.token'
      )
    ).toBe(false)
  })
})

describe('AI_SECRET_RULES — HF labelled envs', () => {
  it('matches HF_TOKEN=<value>', () => {
    const value = 'a'.repeat(40)
    const text = `HF_TOKEN=${value}`
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'ai.huggingface.labelled')
    expect(hit).toBeDefined()
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(value)
  })

  it('matches HUGGINGFACE_API_KEY=<value>', () => {
    const value = 'a'.repeat(40)
    const text = `HUGGINGFACE_API_KEY=${value}`
    expect(
      scanForSecrets(text, opts).some((h) => h.rule.id === 'ai.huggingface.labelled')
    ).toBe(true)
  })

  it('rejects empty value `HF_TOKEN=`', () => {
    expect(
      scanForSecrets('HF_TOKEN=', opts).some((h) => h.rule.id === 'ai.huggingface.labelled')
    ).toBe(false)
  })
})

describe('AI_SECRET_RULES — Replicate token', () => {
  it('matches r8_<40+ alnum>', () => {
    const text = `r8_${ALNUM_40}`
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'ai.replicate.token')
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
  })

  it('rejects r8_ with body too short (< 40 chars)', () => {
    expect(
      scanForSecrets('r8_' + 'a'.repeat(39), opts).some(
        (h) => h.rule.id === 'ai.replicate.token'
      )
    ).toBe(false)
  })
})

describe('AI_SECRET_RULES — REPLICATE_API_TOKEN labelled', () => {
  it('matches REPLICATE_API_TOKEN=<value>', () => {
    const value = 'r8_' + ALNUM_40
    const text = `REPLICATE_API_TOKEN=${value}`
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'ai.replicate.labelled')
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(value)
  })

  it('rejects empty value `REPLICATE_API_TOKEN=`', () => {
    expect(
      scanForSecrets('REPLICATE_API_TOKEN=', opts).some(
        (h) => h.rule.id === 'ai.replicate.labelled'
      )
    ).toBe(false)
  })
})

describe('AI_SECRET_RULES — coverage', () => {
  it('all rules use the global flag', () => {
    for (const r of AI_SECRET_RULES) {
      expect(r.pattern.flags).toContain('g')
    }
  })

  it('all rules are namespaced under ai.<service>.', () => {
    for (const r of AI_SECRET_RULES) {
      expect(r.id.startsWith('ai.')).toBe(true)
      // shape: ai.<service>.<reason>
      expect(r.id.split('.').length).toBeGreaterThanOrEqual(3)
    }
  })

  it('all rules carry error severity', () => {
    for (const r of AI_SECRET_RULES) {
      expect(r.severity).toBe('error')
    }
  })
})
