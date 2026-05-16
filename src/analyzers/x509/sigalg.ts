// Minimal lookup: DER-encoded OID byte pattern → signature algorithm name.
// The signatureAlgorithm AlgorithmIdentifier inside an X.509 certificate is
// always present twice (once in TBSCertificate, once outside). We just need
// to find any occurrence of one of these byte sequences in the cert DER.

interface AlgEntry {
  name: string
  oidBytes: number[]
}

export const SIG_ALG_TABLE: AlgEntry[] = [
  { name: 'md5WithRSAEncryption', oidBytes: [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04] },
  { name: 'sha1WithRSAEncryption', oidBytes: [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05] },
  { name: 'sha256WithRSAEncryption', oidBytes: [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b] },
  { name: 'sha384WithRSAEncryption', oidBytes: [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c] },
  { name: 'sha512WithRSAEncryption', oidBytes: [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d] },
  { name: 'rsassaPss', oidBytes: [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a] },
  { name: 'ecdsa-with-SHA1', oidBytes: [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01] },
  { name: 'ecdsa-with-SHA256', oidBytes: [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02] },
  { name: 'ecdsa-with-SHA384', oidBytes: [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03] },
  { name: 'ecdsa-with-SHA512', oidBytes: [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04] },
  { name: 'ed25519', oidBytes: [0x2b, 0x65, 0x70] },
  { name: 'ed448', oidBytes: [0x2b, 0x65, 0x71] },
]

const WEAK_NAMES = new Set(['md5WithRSAEncryption', 'sha1WithRSAEncryption', 'ecdsa-with-SHA1'])

export function detectSignatureAlgorithm(der: Buffer): string {
  for (const entry of SIG_ALG_TABLE) {
    if (indexOfSubsequence(der, entry.oidBytes) >= 0) {
      return entry.name
    }
  }
  return 'unknown'
}

export function isWeakSignatureAlgorithm(name: string): boolean {
  return WEAK_NAMES.has(name)
}

function indexOfSubsequence(haystack: Buffer, needle: number[]): number {
  if (needle.length === 0 || haystack.length < needle.length) return -1
  outer: for (let i = 0; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer
    }
    return i
  }
  return -1
}
