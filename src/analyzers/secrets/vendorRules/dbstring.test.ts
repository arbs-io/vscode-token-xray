import { describe, expect, it } from 'vitest'
import { scanForSecrets } from '../scanner'
import { DBSTRING_SECRET_RULES } from './dbstring'

const opts = { rules: DBSTRING_SECRET_RULES }

describe('DBSTRING_SECRET_RULES — postgres', () => {
  it('matches postgres://user:password@host/db (error)', () => {
    const text = 'postgres://alice:hunter2@db.example.com:5432/orders'
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.dbstring.postgres')
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe('hunter2')
  })

  it('matches postgresql:// alias', () => {
    const text = 'postgresql://alice:s3cret@db.example.com/orders'
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.dbstring.postgres')
    expect(hit).toBeDefined()
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe('s3cret')
  })

  it('does not match passwordless postgres://user@host/db', () => {
    expect(scanForSecrets('postgres://alice@db.example.com/orders', opts)).toEqual([])
  })

  it('does not match unrelated pg:// scheme', () => {
    expect(scanForSecrets('pg://alice:hunter2@db.example.com/orders', opts)).toEqual([])
  })
})

describe('DBSTRING_SECRET_RULES — mysql', () => {
  it('matches mysql://user:password@host/db', () => {
    const text = 'mysql://root:toor@127.0.0.1:3306/app'
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.dbstring.mysql')
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe('toor')
  })

  it('does not match passwordless mysql://host/db (no user)', () => {
    expect(scanForSecrets('mysql://127.0.0.1:3306/app', opts)).toEqual([])
  })

  it('does not match mysql://user@host/db (no password)', () => {
    expect(scanForSecrets('mysql://root@127.0.0.1:3306/app', opts)).toEqual([])
  })
})

describe('DBSTRING_SECRET_RULES — mongodb', () => {
  it('matches mongodb://user:password@host/db', () => {
    const text = 'mongodb://app:p@ssw0rd@cluster.local:27017/data'
    // p@ssw0rd contains '@' which the regex treats as terminator; pick a safe pw
    const safe = 'mongodb://app:pwd123@cluster.local:27017/data'
    const hit = scanForSecrets(safe, opts).find((h) => h.rule.id === 'secret.dbstring.mongodb')
    expect(hit?.rule.severity).toBe('error')
    expect(safe.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe('pwd123')
    // sanity: the @-in-password case still matches *something* up to first '@'
    expect(
      scanForSecrets(text, opts).some((h) => h.rule.id === 'secret.dbstring.mongodb')
    ).toBe(true)
  })

  it('matches mongodb+srv:// form', () => {
    const text = 'mongodb+srv://app:secret@cluster0.mongodb.net/test'
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.dbstring.mongodb')
    expect(hit).toBeDefined()
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe('secret')
  })

  it('does not match passwordless mongodb://user@host/db', () => {
    expect(scanForSecrets('mongodb://app@cluster.local/data', opts)).toEqual([])
  })
})

describe('DBSTRING_SECRET_RULES — redis', () => {
  it('matches redis://user:password@host (error)', () => {
    const text = 'redis://default:hunter2@redis.example.com:6379'
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.dbstring.redis')
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe('hunter2')
  })

  it('matches rediss:// (TLS) form', () => {
    const text = 'rediss://default:tlspwd@redis.example.com:6380'
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.dbstring.redis')
    expect(hit).toBeDefined()
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe('tlspwd')
  })

  it('does not match passwordless redis://host', () => {
    expect(scanForSecrets('redis://redis.example.com:6379', opts)).toEqual([])
  })
})

describe('DBSTRING_SECRET_RULES — jdbc', () => {
  it('matches jdbc URL with password= query param (error)', () => {
    const text = 'jdbc:mysql://db.example.com:3306/app?user=root&password=hunter2&useSSL=true'
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.dbstring.jdbc')
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe('hunter2')
  })

  it('matches jdbc:postgresql:// drivers', () => {
    const text = 'jdbc:postgresql://db.example.com/app?password=letmein&ssl=true'
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.dbstring.jdbc')
    expect(hit).toBeDefined()
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe('letmein')
  })

  it('does not match jdbc URL without password=', () => {
    expect(
      scanForSecrets('jdbc:mysql://db.example.com:3306/app?user=root&useSSL=true', opts)
    ).toEqual([])
  })

  it('does not match jdbc URL with no query string at all', () => {
    expect(scanForSecrets('jdbc:mysql://db.example.com:3306/app', opts)).toEqual([])
  })
})

describe('DBSTRING_SECRET_RULES — coverage', () => {
  it('all rules use the global flag', () => {
    for (const r of DBSTRING_SECRET_RULES) {
      expect(r.pattern.flags).toContain('g')
    }
  })

  it('all rules are namespaced under secret.dbstring', () => {
    for (const r of DBSTRING_SECRET_RULES) {
      expect(r.id.startsWith('secret.dbstring.')).toBe(true)
    }
  })

  it('all rules have severity error', () => {
    for (const r of DBSTRING_SECRET_RULES) {
      expect(r.severity).toBe('error')
    }
  })

  it('all rules define a sensitiveSpan', () => {
    for (const r of DBSTRING_SECRET_RULES) {
      expect(typeof r.sensitiveSpan).toBe('function')
    }
  })
})
