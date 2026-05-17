import { SecretRule } from '../types'

// URI-form helper: for `scheme://user:password@host…` the password sits between
// the first `:` after the userinfo and the trailing `@`. We locate the
// userinfo+`@` block using a small RE and return the offsets of the password
// substring inside the matched raw string.
const sensitiveUriPassword = (raw: string) => {
  const m = /:\/\/[^:@\s]+:([^@\s]+)@/.exec(raw)
  if (!m) return { start: 0, end: raw.length }
  // m[1] is the password capture. Its absolute offset is the index where the
  // `://user:` prefix ends inside the overall match.
  const prefixEnd = m.index + m[0].length - 1 - m[1].length // -1 to drop the trailing '@'
  return { start: prefixEnd, end: prefixEnd + m[1].length }
}

// JDBC form: `jdbc:<driver>://…?…password=<secret>…`. The password value is
// everything between `password=` and the next `&` / whitespace.
const sensitiveJdbcPassword = (raw: string) => {
  const m = /password=([^&\s]+)/.exec(raw)
  if (!m) return { start: 0, end: raw.length }
  const start = m.index + m[0].length - m[1].length
  return { start, end: start + m[1].length }
}

const POSTGRES: SecretRule = {
  id: 'secret.dbstring.postgres',
  vendor: 'dbstring',
  name: 'PostgreSQL connection string with embedded password',
  pattern: /(?:postgres|postgresql):\/\/[^:@\s]+:[^@\s]+@[^\s]+/g,
  severity: 'error',
  description:
    'PostgreSQL connection URI carrying an inline username/password. Move credentials into env vars or a secret manager instead of source.',
  docUrl: 'https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-CONNSTRING',
  sensitiveSpan: sensitiveUriPassword,
}

const MYSQL: SecretRule = {
  id: 'secret.dbstring.mysql',
  vendor: 'dbstring',
  name: 'MySQL connection string with embedded password',
  pattern: /mysql:\/\/[^:@\s]+:[^@\s]+@[^\s]+/g,
  severity: 'error',
  description:
    'MySQL connection URI carrying an inline username/password. Move credentials into env vars or a secret manager instead of source.',
  docUrl: 'https://dev.mysql.com/doc/refman/8.0/en/connecting-using-uri-or-key-value-pairs.html',
  sensitiveSpan: sensitiveUriPassword,
}

const MONGODB: SecretRule = {
  id: 'secret.dbstring.mongodb',
  vendor: 'dbstring',
  name: 'MongoDB connection string with embedded password',
  pattern: /mongodb(?:\+srv)?:\/\/[^:@\s]+:[^@\s]+@[^\s]+/g,
  severity: 'error',
  description:
    'MongoDB connection URI (including SRV form) carrying an inline username/password. Move credentials into env vars or a secret manager instead of source.',
  docUrl: 'https://www.mongodb.com/docs/manual/reference/connection-string/',
  sensitiveSpan: sensitiveUriPassword,
}

const REDIS: SecretRule = {
  id: 'secret.dbstring.redis',
  vendor: 'dbstring',
  name: 'Redis connection string with embedded password',
  pattern: /rediss?:\/\/[^:@\s]+:[^@\s]+@[^\s]+/g,
  severity: 'error',
  description:
    'Redis connection URI (incl. TLS rediss://) carrying an inline username/password. Move credentials into env vars or a secret manager instead of source.',
  docUrl: 'https://www.iana.org/assignments/uri-schemes/prov/redis',
  sensitiveSpan: sensitiveUriPassword,
}

const JDBC: SecretRule = {
  id: 'secret.dbstring.jdbc',
  vendor: 'dbstring',
  name: 'JDBC connection string with password query parameter',
  pattern: /jdbc:[a-z]+:\/\/[^?\s]+\?(?:[^\s]*&)?password=[^&\s]+[^\s]*/g,
  severity: 'error',
  description:
    'JDBC URL carrying a `password=` query parameter. Move credentials into env vars or a JDBC properties file outside source control.',
  docUrl: 'https://docs.oracle.com/javase/tutorial/jdbc/basics/connecting.html',
  sensitiveSpan: sensitiveJdbcPassword,
}

export const DBSTRING_SECRET_RULES: SecretRule[] = [
  POSTGRES,
  MYSQL,
  MONGODB,
  REDIS,
  JDBC,
]
