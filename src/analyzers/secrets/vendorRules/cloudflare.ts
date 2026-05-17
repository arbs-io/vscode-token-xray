import { SecretRule } from '../types'

const sensitiveAfterDelimiter = (raw: string, valueRe: RegExp) => {
  const m = valueRe.exec(raw)
  if (!m) return { start: 0, end: raw.length }
  const start = raw.lastIndexOf(m[1])
  return { start, end: start + m[1].length }
}

const GLOBAL_API_KEY: SecretRule = {
  id: 'secret.cloudflare.globalApiKey',
  vendor: 'cloudflare',
  name: 'Cloudflare global API key',
  pattern: /X-Auth-Key\s*:\s*[0-9a-f]{37}\b/gi,
  severity: 'error',
  description:
    'Cloudflare global API key. Grants full account access — Cloudflare recommends migrating to scoped API tokens.',
  docUrl: 'https://developers.cloudflare.com/fundamentals/api/get-started/keys/',
  sensitiveSpan: (raw) => sensitiveAfterDelimiter(raw, /([0-9a-f]{37})\b/),
}

const API_TOKEN_LABELLED: SecretRule = {
  id: 'secret.cloudflare.apiToken',
  vendor: 'cloudflare',
  name: 'Cloudflare scoped API token (labelled)',
  pattern: /(?:CLOUDFLARE_API_TOKEN|CF_API_TOKEN)["']?\s*[:=]\s*["']?[A-Za-z0-9_-]{40}["']?/g,
  severity: 'error',
  description: 'Cloudflare scoped API token. Rotate immediately if leaked.',
  docUrl: 'https://developers.cloudflare.com/fundamentals/api/get-started/create-token/',
  sensitiveSpan: (raw) => sensitiveAfterDelimiter(raw, /[:=]\s*["']?([A-Za-z0-9_-]{40})/),
}

const ACCESS_CLIENT_ID: SecretRule = {
  id: 'secret.cloudflare.accessClientId',
  vendor: 'cloudflare',
  name: 'Cloudflare Access service-token client_id',
  pattern: /(?:CF_ACCESS_CLIENT_ID|CLOUDFLARE_ACCESS_CLIENT_ID)["']?\s*[:=]\s*["']?[a-f0-9]{32}\.access\.[a-zA-Z0-9.-]+["']?/g,
  severity: 'info',
  description:
    'Cloudflare Access service-token client_id. Identifies the tenant; not secret on its own but pair-with-secret unlocks Access-protected apps.',
  sensitiveSpan: (raw) => sensitiveAfterDelimiter(raw, /[:=]\s*["']?([a-f0-9]{32}\.access\.[a-zA-Z0-9.-]+)/),
}

const ACCESS_CLIENT_SECRET: SecretRule = {
  id: 'secret.cloudflare.accessClientSecret',
  vendor: 'cloudflare',
  name: 'Cloudflare Access service-token client_secret',
  pattern: /(?:CF_ACCESS_CLIENT_SECRET|CLOUDFLARE_ACCESS_CLIENT_SECRET)["']?\s*[:=]\s*["']?[a-f0-9]{64,}["']?/g,
  severity: 'error',
  description: 'Cloudflare Access service-token client_secret. Grants automated access to Cloudflare Access-protected applications.',
  sensitiveSpan: (raw) => sensitiveAfterDelimiter(raw, /[:=]\s*["']?([a-f0-9]{64,})/),
}

const TUNNEL_TOKEN: SecretRule = {
  id: 'secret.cloudflare.tunnelToken',
  vendor: 'cloudflare',
  name: 'Cloudflare Tunnel token',
  pattern: /(?:CF_TUNNEL_TOKEN|CLOUDFLARE_TUNNEL_TOKEN|TUNNEL_TOKEN)["']?\s*[:=]\s*["']?[A-Za-z0-9+/=_-]{100,}["']?/g,
  severity: 'error',
  description: 'Cloudflare Tunnel (cloudflared) connection token. Anyone with this can run a tunnel as your account.',
  sensitiveSpan: (raw) => sensitiveAfterDelimiter(raw, /[:=]\s*["']?([A-Za-z0-9+/=_-]{100,})/),
}

export const CLOUDFLARE_SECRET_RULES: SecretRule[] = [
  GLOBAL_API_KEY,
  API_TOKEN_LABELLED,
  ACCESS_CLIENT_ID,
  ACCESS_CLIENT_SECRET,
  TUNNEL_TOKEN,
]
