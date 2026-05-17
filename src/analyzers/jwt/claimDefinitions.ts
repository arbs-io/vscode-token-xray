export interface ClaimDefinition {
  key: string
  description: string
  iconKey?: string
  isTimestamp?: boolean
  category?: 'standard' | 'oidc' | 'azure-ad' | 'aws-cognito' | 'custom'
}

export const STANDARD_CLAIMS: ClaimDefinition[] = [
  { key: 'iss', description: 'Issuer — principal that issued the JWT.', category: 'standard', iconKey: 'firewall' },
  { key: 'sub', description: 'Subject — principal the JWT is about.', category: 'standard', iconKey: 'subject' },
  { key: 'aud', description: 'Audience — recipients the JWT is intended for.', category: 'standard', iconKey: 'audience' },
  { key: 'exp', description: 'Expiration Time (NumericDate).', category: 'standard', isTimestamp: true, iconKey: 'timestamp' },
  { key: 'nbf', description: 'Not Before (NumericDate).', category: 'standard', isTimestamp: true, iconKey: 'timestamp' },
  { key: 'iat', description: 'Issued At (NumericDate).', category: 'standard', isTimestamp: true, iconKey: 'timestamp' },
  { key: 'jti', description: 'JWT ID — unique identifier.', category: 'standard', iconKey: 'key' },

  { key: 'nonce', description: 'OIDC: random value to mitigate replay attacks.', category: 'oidc' },
  { key: 'azp', description: 'OIDC: authorized party / client_id.', category: 'oidc' },
  { key: 'at_hash', description: 'OIDC: access token hash.', category: 'oidc' },
  { key: 'c_hash', description: 'OIDC: authorization code hash.', category: 'oidc' },
  { key: 'auth_time', description: 'OIDC: time of end-user authentication.', category: 'oidc', isTimestamp: true },
  { key: 'acr', description: 'OIDC: authentication context class reference.', category: 'oidc' },
  { key: 'amr', description: 'OIDC: authentication methods reference.', category: 'oidc' },

  { key: 'tid', description: 'Azure AD: tenant ID.', category: 'azure-ad' },
  { key: 'oid', description: 'Azure AD: object ID of the principal.', category: 'azure-ad' },
  { key: 'appid', description: 'Azure AD v1: application ID.', category: 'azure-ad' },
  { key: 'roles', description: 'Azure AD: application roles.', category: 'azure-ad' },
  { key: 'scp', description: 'Azure AD: delegated scopes.', category: 'azure-ad' },
  { key: 'upn', description: 'Azure AD: user principal name.', category: 'azure-ad' },

  { key: 'cognito:username', description: 'AWS Cognito: username.', category: 'aws-cognito' },
  { key: 'cognito:groups', description: 'AWS Cognito: group memberships.', category: 'aws-cognito' },
  { key: 'token_use', description: 'AWS Cognito: token type (access | id).', category: 'aws-cognito' },
]

const BY_KEY = new Map(STANDARD_CLAIMS.map((c) => [c.key, c]))

export function getClaimDefinition(key: string): ClaimDefinition | undefined {
  return BY_KEY.get(key)
}
