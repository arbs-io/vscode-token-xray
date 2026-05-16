import { Finding } from '../../core/types'
import { CavageSig, Rfc9421Sig } from './parser'

const CAVAGE_DOC_URL =
  'https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12'
const RFC9421_DOC_URL = 'https://www.rfc-editor.org/rfc/rfc9421.html'

const WEAK_ALGORITHMS = new Set(['hmac-sha1', 'rsa-sha1'])

/**
 * Allowable clock skew when judging whether `created` is "in the
 * future" — 5 minutes, matching the conventional NTP fudge factor and
 * the threshold this analyzer's spec calls out.
 */
const FUTURE_CREATED_SKEW_SECONDS = 5 * 60

/**
 * Map a parsed Cavage signature to findings.
 *
 * Emitted ids:
 *   - `httpSignature.algorithm.weak`     (warning) — algorithm is
 *     `hmac-sha1` or `rsa-sha1` (case-insensitive).
 *   - `httpSignature.algorithm.missing`  (info)    — the Cavage header
 *     has no `algorithm` parameter at all. (RFC 9421 doesn't carry the
 *     algorithm inline; this finding is suppressed for that variant.)
 *   - `httpSignature.created.future`     (warning) — `created` is more
 *     than 5 minutes ahead of `now`.
 */
export function findingsForCavage(sig: CavageSig, now: number = Date.now()): Finding[] {
  const findings: Finding[] = []

  if (sig.algorithm) {
    if (WEAK_ALGORITHMS.has(sig.algorithm.toLowerCase())) {
      findings.push({
        id: 'httpSignature.algorithm.weak',
        severity: 'warning',
        message: `HTTP Signature algorithm "${sig.algorithm}" is cryptographically weak — SHA-1 is broken and should not be used for new signatures.`,
        docUrl: CAVAGE_DOC_URL,
      })
    }
  } else {
    findings.push({
      id: 'httpSignature.algorithm.missing',
      severity: 'info',
      message: 'Cavage Signature header does not declare an algorithm — verifiers must derive it from the key, which is fragile and ambiguous.',
      docUrl: CAVAGE_DOC_URL,
    })
  }

  if (sig.created !== undefined) {
    const nowSeconds = Math.floor(now / 1000)
    if (sig.created > nowSeconds + FUTURE_CREATED_SKEW_SECONDS) {
      findings.push({
        id: 'httpSignature.created.future',
        severity: 'warning',
        message: `HTTP Signature "created" timestamp (${sig.created}) is more than 5 minutes in the future relative to now (${nowSeconds}). Clock skew or replay manipulation?`,
        docUrl: CAVAGE_DOC_URL,
      })
    }
  }

  return findings
}

/**
 * Map a parsed RFC 9421 signature to findings. The `algorithm.missing`
 * finding is suppressed for this variant because the standard says
 * verifiers must derive the algorithm from the key reference; not
 * carrying it inline is the expected behaviour.
 */
export function findingsForRfc9421(sig: Rfc9421Sig, now: number = Date.now()): Finding[] {
  const findings: Finding[] = []

  if (sig.algorithm && WEAK_ALGORITHMS.has(sig.algorithm.toLowerCase())) {
    findings.push({
      id: 'httpSignature.algorithm.weak',
      severity: 'warning',
      message: `HTTP Signature algorithm "${sig.algorithm}" is cryptographically weak — SHA-1 is broken and should not be used for new signatures.`,
      docUrl: RFC9421_DOC_URL,
    })
  }

  if (sig.created !== undefined) {
    const nowSeconds = Math.floor(now / 1000)
    if (sig.created > nowSeconds + FUTURE_CREATED_SKEW_SECONDS) {
      findings.push({
        id: 'httpSignature.created.future',
        severity: 'warning',
        message: `HTTP Signature "created" timestamp (${sig.created}) is more than 5 minutes in the future relative to now (${nowSeconds}). Clock skew or replay manipulation?`,
        docUrl: RFC9421_DOC_URL,
      })
    }
  }

  return findings
}
