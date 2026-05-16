import { SecretRule } from '../types'

// Communications-API vendor token formats: Twilio, SendGrid, Mailgun,
// Telegram (bot tokens), Discord (bot tokens). Each pattern is anchored
// against the surrounding character class so a longer identifier or a
// phone-number-like prefix cannot accidentally extract a token out of an
// unrelated word.

const sensitiveAfterDelimiter = (raw: string, valueRe: RegExp) => {
  const m = valueRe.exec(raw)
  if (!m) return { start: 0, end: raw.length }
  const start = raw.lastIndexOf(m[1])
  return { start, end: start + m[1].length }
}

// Twilio account SID — `AC` + 32 lowercase hex. Not a secret on its own
// (it identifies the account) but knowing it pinpoints which Twilio
// account a leaked auth-token belongs to, so we surface it as info.
const TWILIO_ACCOUNT_SID: SecretRule = {
  id: 'secret.twilio.accountSid',
  vendor: 'twilio',
  name: 'Twilio Account SID (AC…)',
  pattern: /(?<![A-Za-z0-9])AC[a-f0-9]{32}(?![A-Za-z0-9])/g,
  severity: 'info',
  description:
    'Twilio Account SID. Identifies the Twilio account; not a secret on its own but pairs with an auth token to authenticate against the REST API.',
  docUrl: 'https://www.twilio.com/docs/iam/api/account',
}

// Twilio API key SID — `SK` + 32 lowercase hex. Confidential half is the
// associated secret, but the SID identifies the key. Treated as an error
// because the SID + paired secret grants full REST API access.
const TWILIO_API_KEY_SID: SecretRule = {
  id: 'secret.twilio.apiKeySid',
  vendor: 'twilio',
  name: 'Twilio API Key SID (SK…)',
  pattern: /(?<![A-Za-z0-9])SK[a-f0-9]{32}(?![A-Za-z0-9])/g,
  severity: 'error',
  description:
    'Twilio API key SID. When paired with its secret grants full REST API access for the parent account — revoke immediately if leaked.',
  docUrl: 'https://www.twilio.com/docs/iam/keys/api-key',
}

// Twilio auth token (32 hex) labelled as `TWILIO_AUTH_TOKEN=…`. The raw
// token is the same 32-hex shape as the account SID body without the
// `AC` prefix, so without a label it would be indistinguishable from
// many other hex strings — we only surface the labelled form.
const TWILIO_AUTH_TOKEN_LABELLED: SecretRule = {
  id: 'secret.twilio.authTokenLabelled',
  vendor: 'twilio',
  name: 'Twilio auth token (env-labelled TWILIO_AUTH_TOKEN=)',
  pattern: /(?:TWILIO_AUTH_TOKEN|twilio_auth_token|twilioAuthToken)["']?\s*[:=]\s*["']?[a-f0-9]{32}["']?/g,
  severity: 'error',
  description:
    'Twilio auth token referenced via env var. Combined with the account SID, grants full REST API access — rotate immediately if leaked.',
  docUrl: 'https://www.twilio.com/docs/iam/access-tokens',
  sensitiveSpan: (raw) => sensitiveAfterDelimiter(raw, /[:=]\s*["']?([a-f0-9]{32})/),
}

// SendGrid API key — `SG.` + 22 base64url + `.` + 43 base64url. The
// SendGrid key envelope is fixed-length so the body sizes are exact.
const SENDGRID_API_KEY: SecretRule = {
  id: 'secret.sendgrid.apiKey',
  vendor: 'sendgrid',
  name: 'SendGrid API key (SG.…)',
  pattern: /(?<![A-Za-z0-9_-])SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])/g,
  severity: 'error',
  description:
    'SendGrid API key. Grants Mail Send / API access scoped to the issuing key — revoke immediately if leaked.',
  docUrl: 'https://docs.sendgrid.com/api-reference/api-keys',
}

// Mailgun API key — legacy `key-` prefix + 32 lowercase hex chars.
const MAILGUN_API_KEY: SecretRule = {
  id: 'secret.mailgun.apiKey',
  vendor: 'mailgun',
  name: 'Mailgun API key (key-…)',
  pattern: /(?<![A-Za-z0-9_-])key-[a-f0-9]{32}(?![A-Za-z0-9_-])/g,
  severity: 'error',
  description:
    'Mailgun API key. Authenticates against the Mailgun REST API for the issuing domain — revoke immediately if leaked.',
  docUrl: 'https://documentation.mailgun.com/en/latest/api-intro.html#authentication',
}

// Telegram bot token — `<bot-id>:<auth-hash>`. The bot ID is 8-10 digits.
// The auth hash is base64url and exactly 35 chars in published tokens.
// We anchor against an alnum lookbehind so a phone number followed by
// `:<35 chars>` cannot match — a phone like `12345678901234:value` has
// 14 digits ahead of the colon and the negative lookbehind on `\d` would
// not help (each digit is a valid `\d`), so we use a leading
// `(?<![A-Za-z0-9])` to require either start-of-string or a non-alnum
// boundary. Strict 8-10 digit bound matches Telegram's published bot ID
// range and rejects shorter phone-fragment-like prefixes (e.g. a 7-digit
// area code).
const TELEGRAM_BOT_TOKEN: SecretRule = {
  id: 'secret.telegram.botToken',
  vendor: 'telegram',
  name: 'Telegram bot token (<bot-id>:<hash>)',
  pattern: /(?<![A-Za-z0-9])\d{8,10}:[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])/g,
  severity: 'error',
  description:
    'Telegram bot token. Grants full control of the bot account (send messages, read updates, manage webhooks) — revoke via @BotFather immediately if leaked.',
  docUrl: 'https://core.telegram.org/bots/api#authorizing-your-bot',
}

// Discord bot token — three base64url segments joined by `.`. First
// segment encodes the user ID (24 chars beginning `M` or `N`), second is
// a 6-char timestamp, third is a 27-char HMAC. The total length is
// always 59 chars + 2 separators = 61 chars (`M…23.6.27`). We anchor
// against the base64url charset so a token embedded in a longer
// identifier (e.g. `prefix_Mxxxxx…`) is rejected.
const DISCORD_BOT_TOKEN: SecretRule = {
  id: 'secret.discord.botToken',
  vendor: 'discord',
  name: 'Discord bot token',
  pattern: /(?<![A-Za-z0-9_-])[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}(?![A-Za-z0-9_-])/g,
  severity: 'error',
  description:
    'Discord bot token. Grants full bot-account access (send / read messages, manage guilds) — reset via the Discord developer portal immediately if leaked.',
  docUrl: 'https://discord.com/developers/docs/reference#authentication',
}

export const COMMS_SECRET_RULES: SecretRule[] = [
  TWILIO_ACCOUNT_SID,
  TWILIO_API_KEY_SID,
  TWILIO_AUTH_TOKEN_LABELLED,
  SENDGRID_API_KEY,
  MAILGUN_API_KEY,
  TELEGRAM_BOT_TOKEN,
  DISCORD_BOT_TOKEN,
]
