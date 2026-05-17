export interface IdpPattern {
  id: string
  name: string
  pattern: RegExp
  tenantGroup?: number
  extraGroups?: Record<string, number>
  docUrl?: string
  guidance?: string
}

export interface RecognizedIssuer {
  pattern: IdpPattern
  tenant?: string
  extras: Record<string, string>
}

export const IDP_PATTERNS: IdpPattern[] = [
  {
    id: 'entraV1',
    name: 'Microsoft Entra ID (v1.0)',
    pattern: /^https:\/\/sts\.windows\.net\/([0-9a-fA-F-]{36})\/?$/,
    tenantGroup: 1,
    docUrl: 'https://learn.microsoft.com/azure/active-directory/develop/access-tokens',
    guidance: 'v1.0 endpoint is legacy. Microsoft recommends migrating to v2.0.',
  },
  {
    id: 'entraV2',
    name: 'Microsoft Entra ID (v2.0)',
    pattern: /^https:\/\/login\.microsoftonline\.(?:com|us|cn|de)\/([0-9a-fA-F-]{36}|common|organizations|consumers)\/v2\.0\/?$/,
    tenantGroup: 1,
    docUrl: 'https://learn.microsoft.com/azure/active-directory/develop/access-tokens',
  },
  {
    id: 'okta',
    name: 'Okta',
    pattern: /^https:\/\/([a-z0-9-]+)\.(okta|okta-emea|oktapreview)\.com\/oauth2(?:\/[a-zA-Z0-9_-]+)?\/?$/,
    tenantGroup: 1,
    extraGroups: { environment: 2 },
    docUrl: 'https://developer.okta.com/docs/concepts/auth-servers/',
  },
  {
    id: 'auth0',
    name: 'Auth0',
    pattern: /^https:\/\/([a-z0-9-]+(?:\.[a-z]{2,3})?)\.auth0\.com\/?$/,
    tenantGroup: 1,
    docUrl: 'https://auth0.com/docs/secure/tokens/access-tokens',
  },
  {
    id: 'cognito',
    name: 'AWS Cognito',
    pattern: /^https:\/\/cognito-idp\.([a-z0-9-]+)\.amazonaws\.com\/([a-zA-Z0-9_-]+)\/?$/,
    tenantGroup: 2,
    extraGroups: { region: 1 },
    docUrl: 'https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html',
  },
  {
    id: 'cloudflareAccess',
    name: 'Cloudflare Access',
    pattern: /^https:\/\/([a-z0-9-]+)\.cloudflareaccess\.com\/?$/,
    tenantGroup: 1,
    docUrl: 'https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/validating-json/',
  },
  {
    id: 'sailpoint',
    name: 'SailPoint Identity Security Cloud',
    pattern: /^https:\/\/([a-z0-9-]+)\.(?:api\.)?identitynow\.com(?:\/oauth)?\/?$/,
    tenantGroup: 1,
    docUrl: 'https://developer.sailpoint.com/docs/api/authentication',
  },
  {
    id: 'googleAccounts',
    name: 'Google Accounts',
    pattern: /^https:\/\/accounts\.google\.com\/?$/,
    docUrl: 'https://developers.google.com/identity/openid-connect/openid-connect',
  },
  {
    id: 'firebase',
    name: 'Firebase Authentication',
    pattern: /^https:\/\/securetoken\.google\.com\/([a-z0-9-]+)\/?$/,
    tenantGroup: 1,
    extraGroups: {},
    docUrl: 'https://firebase.google.com/docs/auth/admin/verify-id-tokens',
  },
  {
    id: 'githubActions',
    name: 'GitHub Actions OIDC',
    pattern: /^https:\/\/token\.actions\.githubusercontent\.com\/?$/,
    docUrl: 'https://docs.github.com/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect',
  },
  {
    id: 'gitlabOidc',
    name: 'GitLab OIDC',
    pattern: /^https:\/\/gitlab\.com\/?$/,
    docUrl: 'https://docs.gitlab.com/ci/cloud_services/',
  },
  {
    id: 'pingOne',
    name: 'Ping Identity (PingOne)',
    pattern: /^https:\/\/([a-z0-9-]+)\.pingone\.com\/([0-9a-fA-F-]{36})\/?$/,
    tenantGroup: 1,
    extraGroups: { envId: 2 },
    docUrl: 'https://apidocs.pingidentity.com/pingone/platform/v1/api/',
  },
  {
    id: 'pingIdentity',
    name: 'Ping Identity Cloud',
    pattern: /^https:\/\/([a-z0-9-]+)\.pingidentity\.cloud(?:\/[^?]*)?\/?$/,
    tenantGroup: 1,
    docUrl: 'https://docs.pingidentity.com/',
  },
  {
    id: 'forgerock',
    name: 'ForgeRock Identity Cloud',
    pattern: /^https:\/\/([a-z0-9-]+)\.(?:forgerock\.io|identitycloud\.com)(?:\/am)?\/oauth2(?:\/[a-zA-Z0-9_-]+)?\/?$/,
    tenantGroup: 1,
    docUrl: 'https://backstage.forgerock.com/docs/idcloud/latest/',
  },
  {
    id: 'oneLogin',
    name: 'OneLogin',
    pattern: /^https:\/\/([a-z0-9-]+)\.onelogin\.com\/oidc\/2\/?$/,
    tenantGroup: 1,
    docUrl: 'https://developers.onelogin.com/openid-connect',
  },
  {
    id: 'keycloak',
    name: 'Keycloak',
    pattern: /^https?:\/\/[^/]+\/auth\/realms\/([a-zA-Z0-9_-]+)\/?$/,
    tenantGroup: 1,
    docUrl: 'https://www.keycloak.org/docs/latest/securing_apps/',
  },
  {
    id: 'salesforce',
    name: 'Salesforce',
    pattern: /^https:\/\/(?:login\.salesforce\.com|([a-z0-9-]+)\.my\.salesforce\.com)\/?$/,
    tenantGroup: 1,
    docUrl: 'https://help.salesforce.com/s/articleView?id=sf.remoteaccess_oauth_endpoints.htm',
  },
  {
    id: 'appleId',
    name: 'Sign in with Apple',
    pattern: /^https:\/\/appleid\.apple\.com\/?$/,
    docUrl: 'https://developer.apple.com/documentation/sign_in_with_apple',
  },
  {
    id: 'microsoftB2C',
    name: 'Microsoft Entra External ID (B2C)',
    pattern: /^https:\/\/([a-z0-9-]+)\.b2clogin\.com\/([0-9a-fA-F-]{36})\/(?:v2\.0\/?)?$/,
    tenantGroup: 2,
    extraGroups: { account: 1 },
    docUrl: 'https://learn.microsoft.com/azure/active-directory-b2c/tokens-overview',
  },
  {
    id: 'clerk',
    name: 'Clerk',
    pattern: /^https:\/\/([a-z0-9-]+)\.clerk\.accounts\.dev\/?$/,
    tenantGroup: 1,
    docUrl: 'https://clerk.com/docs/backend-requests/handling/manual-jwt',
  },
  {
    id: 'workOs',
    name: 'WorkOS',
    pattern: /^https:\/\/api\.workos\.com\/?$/,
    docUrl: 'https://workos.com/docs/reference',
  },
  {
    id: 'frontegg',
    name: 'Frontegg',
    pattern: /^https:\/\/([a-z0-9-]+)\.frontegg\.com\/?$/,
    tenantGroup: 1,
    docUrl: 'https://docs.frontegg.com/docs/welcome-to-frontegg',
  },
  {
    id: 'descope',
    name: 'Descope',
    pattern: /^https:\/\/api\.descope\.com\/(?:v1\/)?([a-zA-Z0-9]+)\/?$/,
    tenantGroup: 1,
    docUrl: 'https://docs.descope.com/',
  },
  {
    id: 'twitch',
    name: 'Twitch OIDC',
    pattern: /^https:\/\/id\.twitch\.tv\/oauth2\/?$/,
    docUrl: 'https://dev.twitch.tv/docs/authentication/',
  },
  {
    id: 'linkedin',
    name: 'LinkedIn',
    pattern: /^https:\/\/www\.linkedin\.com\/?$/,
    docUrl: 'https://learn.microsoft.com/linkedin/shared/authentication/authentication',
  },
  {
    id: 'discord',
    name: 'Discord OIDC',
    pattern: /^https:\/\/discord\.com\/?$/,
    docUrl: 'https://discord.com/developers/docs/topics/oauth2',
  },
]

export function recognizeIssuer(iss: string): RecognizedIssuer | undefined {
  if (!iss || typeof iss !== 'string') return undefined
  const trimmed = iss.trim()
  for (const pattern of IDP_PATTERNS) {
    const m = pattern.pattern.exec(trimmed)
    if (!m) continue
    const tenant = pattern.tenantGroup ? m[pattern.tenantGroup] : undefined
    const extras: Record<string, string> = {}
    if (pattern.extraGroups) {
      for (const [key, group] of Object.entries(pattern.extraGroups)) {
        if (m[group]) extras[key] = m[group]
      }
    }
    return { pattern, tenant, extras }
  }
  return undefined
}
