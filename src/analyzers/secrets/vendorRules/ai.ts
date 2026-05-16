import { SecretRule } from '../types'

const sensitiveAfterDelimiter = (raw: string, valueRe: RegExp) => {
  const m = valueRe.exec(raw)
  if (!m) return { start: 0, end: raw.length }
  const start = raw.lastIndexOf(m[1])
  return { start, end: start + m[1].length }
}

// OpenAI classic secret key: `sk-` + 48 base62 chars. The negative lookbehind
// `(?<![A-Za-z_-])` rejects identifiers like `sk-active` / CSS classes that
// happen to start with `sk-` and would otherwise look like a longer name. The
// {48} length floor pushes past plausible CSS / JS identifier lengths and the
// trailing `(?![A-Za-z0-9])` blocks longer alnum runs that aren't keys.
const OPENAI_SECRET_KEY: SecretRule = {
  id: 'ai.openai.secretKey',
  vendor: 'openai',
  name: 'OpenAI API secret key (sk-…)',
  pattern: /(?<![A-Za-z_-])sk-[A-Za-z0-9]{48}(?![A-Za-z0-9])/g,
  severity: 'error',
  description:
    'OpenAI API secret key. Grants full account access to OpenAI APIs and is billable — rotate immediately if leaked.',
  docUrl: 'https://platform.openai.com/docs/api-reference/authentication',
}

// OpenAI project-scoped key: `sk-proj-` + 60+ chars from base64url-ish set.
// Anchored similarly so we don't pick up `sk-projector` etc.
const OPENAI_PROJECT_KEY: SecretRule = {
  id: 'ai.openai.projectKey',
  vendor: 'openai',
  name: 'OpenAI project-scoped API key (sk-proj-…)',
  pattern: /(?<![A-Za-z_-])sk-proj-[A-Za-z0-9_-]{60,}(?![A-Za-z0-9_-])/g,
  severity: 'error',
  description:
    'OpenAI project-scoped API key. Bound to a single project but still grants billable API access — rotate immediately if leaked.',
  docUrl: 'https://platform.openai.com/docs/api-reference/authentication',
}

const OPENAI_LABELLED: SecretRule = {
  id: 'ai.openai.labelled',
  vendor: 'openai',
  name: 'OpenAI API key (env-labelled OPENAI_API_KEY=)',
  pattern: /(?:OPENAI_API_KEY|openai_api_key|openaiApiKey)["']?\s*[:=]\s*["']?[A-Za-z0-9_-]{20,}["']?/g,
  severity: 'error',
  description:
    'OpenAI API key referenced via env var. Anyone with the value can run billable API calls — rotate immediately if leaked.',
  docUrl: 'https://platform.openai.com/docs/api-reference/authentication',
  sensitiveSpan: (raw) => sensitiveAfterDelimiter(raw, /[:=]\s*["']?([A-Za-z0-9_-]{20,})/),
}

// Anthropic API key: `sk-ant-` + `api03` (user) or `admin01` (admin) + 93+ chars.
const ANTHROPIC_API_KEY: SecretRule = {
  id: 'ai.anthropic.apiKey',
  vendor: 'anthropic',
  name: 'Anthropic API key (sk-ant-…)',
  pattern: /(?<![A-Za-z_-])sk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{93,}(?![A-Za-z0-9_-])/g,
  severity: 'error',
  description:
    'Anthropic API key. Grants account access to Claude APIs and is billable — rotate immediately if leaked.',
  docUrl: 'https://docs.anthropic.com/en/api/getting-started',
}

const ANTHROPIC_LABELLED: SecretRule = {
  id: 'ai.anthropic.labelled',
  vendor: 'anthropic',
  name: 'Anthropic API key (env-labelled ANTHROPIC_API_KEY=)',
  pattern: /(?:ANTHROPIC_API_KEY|anthropic_api_key|anthropicApiKey)["']?\s*[:=]\s*["']?[A-Za-z0-9_-]{20,}["']?/g,
  severity: 'error',
  description:
    'Anthropic API key referenced via env var. Anyone with the value can run billable API calls — rotate immediately if leaked.',
  docUrl: 'https://docs.anthropic.com/en/api/getting-started',
  sensitiveSpan: (raw) => sensitiveAfterDelimiter(raw, /[:=]\s*["']?([A-Za-z0-9_-]{20,})/),
}

// Hugging Face access token: `hf_` + 34+ alphanumeric chars.
const HUGGINGFACE_TOKEN: SecretRule = {
  id: 'ai.huggingface.token',
  vendor: 'huggingface',
  name: 'Hugging Face access token (hf_…)',
  pattern: /(?<![A-Za-z_-])hf_[A-Za-z0-9]{34,}(?![A-Za-z0-9])/g,
  severity: 'error',
  description:
    'Hugging Face user access token. Grants Hub read/write access scoped to the issuing account — rotate immediately if leaked.',
  docUrl: 'https://huggingface.co/docs/hub/security-tokens',
}

const HUGGINGFACE_LABELLED: SecretRule = {
  id: 'ai.huggingface.labelled',
  vendor: 'huggingface',
  name: 'Hugging Face access token (env-labelled HF_TOKEN=/HUGGINGFACE_API_KEY=)',
  pattern: /(?:HF_TOKEN|HUGGINGFACE_API_KEY|HUGGING_FACE_HUB_TOKEN|hf_token|huggingface_api_key|huggingFaceToken)["']?\s*[:=]\s*["']?[A-Za-z0-9_-]{20,}["']?/g,
  severity: 'error',
  description:
    'Hugging Face access token referenced via env var. Anyone with the value can read/write the issuing account — rotate immediately if leaked.',
  docUrl: 'https://huggingface.co/docs/hub/security-tokens',
  sensitiveSpan: (raw) => sensitiveAfterDelimiter(raw, /[:=]\s*["']?([A-Za-z0-9_-]{20,})/),
}

// Replicate API token: `r8_` + 40+ alphanumeric chars.
const REPLICATE_TOKEN: SecretRule = {
  id: 'ai.replicate.token',
  vendor: 'replicate',
  name: 'Replicate API token (r8_…)',
  pattern: /(?<![A-Za-z_-])r8_[A-Za-z0-9]{40,}(?![A-Za-z0-9])/g,
  severity: 'error',
  description:
    'Replicate API token. Grants billable access to run/host models on the issuing account — rotate immediately if leaked.',
  docUrl: 'https://replicate.com/docs/reference/http#authentication',
}

const REPLICATE_LABELLED: SecretRule = {
  id: 'ai.replicate.labelled',
  vendor: 'replicate',
  name: 'Replicate API token (env-labelled REPLICATE_API_TOKEN=)',
  pattern: /(?:REPLICATE_API_TOKEN|replicate_api_token|replicateApiToken)["']?\s*[:=]\s*["']?[A-Za-z0-9_-]{20,}["']?/g,
  severity: 'error',
  description:
    'Replicate API token referenced via env var. Anyone with the value can run billable models on the issuing account — rotate immediately if leaked.',
  docUrl: 'https://replicate.com/docs/reference/http#authentication',
  sensitiveSpan: (raw) => sensitiveAfterDelimiter(raw, /[:=]\s*["']?([A-Za-z0-9_-]{20,})/),
}

export const AI_SECRET_RULES: SecretRule[] = [
  OPENAI_SECRET_KEY,
  OPENAI_PROJECT_KEY,
  OPENAI_LABELLED,
  ANTHROPIC_API_KEY,
  ANTHROPIC_LABELLED,
  HUGGINGFACE_TOKEN,
  HUGGINGFACE_LABELLED,
  REPLICATE_TOKEN,
  REPLICATE_LABELLED,
]
