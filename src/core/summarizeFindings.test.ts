import { describe, expect, it } from 'vitest'
import { summarizeFindings } from './summarizeFindings'
import { Finding } from './types'

function err(id = 'x.err'): Finding {
  return { id, severity: 'error', message: id }
}

function warn(id = 'x.warn'): Finding {
  return { id, severity: 'warning', message: id }
}

function info(id = 'x.info'): Finding {
  return { id, severity: 'info', message: id }
}

describe('summarizeFindings', () => {
  describe('empty / no findings', () => {
    it('returns hidden + empty label for an empty findings list', () => {
      const result = summarizeFindings([])
      expect(result.errors).toBe(0)
      expect(result.warnings).toBe(0)
      expect(result.infos).toBe(0)
      expect(result.label).toBe('')
      expect(result.hidden).toBe(true)
    })

    it('returns hidden + empty label for an undefined findings list', () => {
      const result = summarizeFindings(undefined)
      expect(result).toEqual({ errors: 0, warnings: 0, infos: 0, label: '', hidden: true })
    })

    it('returns hidden + empty label for a null findings list', () => {
      const result = summarizeFindings(null)
      expect(result).toEqual({ errors: 0, warnings: 0, infos: 0, label: '', hidden: true })
    })

    it('ignores nullish entries without throwing', () => {
      const result = summarizeFindings([
        undefined as unknown as Finding,
        null as unknown as Finding,
        err(),
      ])
      expect(result.errors).toBe(1)
      expect(result.hidden).toBe(false)
      expect(result.label).toBe('$(shield) 1 error')
    })
  })

  describe('only errors', () => {
    it('pluralises a single error as "1 error"', () => {
      const result = summarizeFindings([err()])
      expect(result.errors).toBe(1)
      expect(result.warnings).toBe(0)
      expect(result.infos).toBe(0)
      expect(result.label).toBe('$(shield) 1 error')
      expect(result.hidden).toBe(false)
    })

    it('pluralises multiple errors as "N errors"', () => {
      const result = summarizeFindings([err('a'), err('b'), err('c')])
      expect(result.errors).toBe(3)
      expect(result.label).toBe('$(shield) 3 errors')
      expect(result.hidden).toBe(false)
    })
  })

  describe('only warnings', () => {
    it('pluralises a single warning as "1 warning"', () => {
      const result = summarizeFindings([warn()])
      expect(result.errors).toBe(0)
      expect(result.warnings).toBe(1)
      expect(result.infos).toBe(0)
      expect(result.label).toBe('$(shield) 1 warning')
      expect(result.hidden).toBe(false)
    })

    it('pluralises multiple warnings as "N warnings"', () => {
      const result = summarizeFindings([warn('a'), warn('b')])
      expect(result.warnings).toBe(2)
      expect(result.label).toBe('$(shield) 2 warnings')
    })
  })

  describe('only infos', () => {
    it('shows "1 info" when info is the only category', () => {
      const result = summarizeFindings([info()])
      expect(result.errors).toBe(0)
      expect(result.warnings).toBe(0)
      expect(result.infos).toBe(1)
      expect(result.label).toBe('$(shield) 1 info')
      expect(result.hidden).toBe(false)
    })

    it('pluralises infos as "N infos" when info is the only category', () => {
      const result = summarizeFindings([info('a'), info('b'), info('c'), info('d')])
      expect(result.infos).toBe(4)
      expect(result.label).toBe('$(shield) 4 infos')
    })
  })

  describe('mixed severities', () => {
    it('formats "2 errors, 1 warning" for the spec example', () => {
      const result = summarizeFindings([err('a'), err('b'), warn()])
      expect(result.errors).toBe(2)
      expect(result.warnings).toBe(1)
      expect(result.infos).toBe(0)
      expect(result.label).toBe('$(shield) 2 errors, 1 warning')
    })

    it('drops info from the label when errors are present', () => {
      const result = summarizeFindings([err(), info('a'), info('b')])
      expect(result.errors).toBe(1)
      expect(result.infos).toBe(2)
      expect(result.label).toBe('$(shield) 1 error')
    })

    it('drops info from the label when warnings are present', () => {
      const result = summarizeFindings([warn(), info('a'), info('b'), info('c')])
      expect(result.warnings).toBe(1)
      expect(result.infos).toBe(3)
      expect(result.label).toBe('$(shield) 1 warning')
    })

    it('drops info from the label when both errors and warnings are present', () => {
      const result = summarizeFindings([err(), err('b'), warn(), info('a'), info('b'), info('c')])
      expect(result.errors).toBe(2)
      expect(result.warnings).toBe(1)
      expect(result.infos).toBe(3)
      expect(result.label).toBe('$(shield) 2 errors, 1 warning')
    })

    it('orders errors before warnings in the label', () => {
      // Severity order is fixed: errors first, then warnings, regardless of
      // insertion order in the findings array.
      const result = summarizeFindings([warn('w1'), err('e1'), warn('w2'), err('e2')])
      expect(result.label).toBe('$(shield) 2 errors, 2 warnings')
    })

    it('keeps category counts even when label hides info', () => {
      const result = summarizeFindings([err(), warn(), info()])
      // Counts are always populated; the label is the only thing that
      // suppresses the info category.
      expect(result.errors).toBe(1)
      expect(result.warnings).toBe(1)
      expect(result.infos).toBe(1)
      expect(result.label).toBe('$(shield) 1 error, 1 warning')
      expect(result.hidden).toBe(false)
    })
  })

  describe('label prefix', () => {
    it('always prefixes the label with the shield codicon', () => {
      expect(summarizeFindings([err()]).label.startsWith('$(shield) ')).toBe(true)
      expect(summarizeFindings([warn()]).label.startsWith('$(shield) ')).toBe(true)
      expect(summarizeFindings([info()]).label.startsWith('$(shield) ')).toBe(true)
    })

    it('returns an empty label (no shield) when there is nothing to show', () => {
      expect(summarizeFindings([]).label).toBe('')
    })
  })

  describe('unrecognised severity', () => {
    it('ignores findings whose severity is outside the known set', () => {
      const weird: Finding = {
        id: 'x',
        severity: 'fatal' as unknown as Finding['severity'],
        message: 'unknown',
      }
      const result = summarizeFindings([weird, err()])
      expect(result.errors).toBe(1)
      expect(result.warnings).toBe(0)
      expect(result.infos).toBe(0)
      expect(result.label).toBe('$(shield) 1 error')
    })
  })
})
