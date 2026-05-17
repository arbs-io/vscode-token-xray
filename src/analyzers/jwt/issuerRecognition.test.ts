import { describe, expect, it } from 'vitest'
import { IDP_PATTERNS, recognizeIssuer } from './issuerRecognition'

describe('IDP_PATTERNS', () => {
  it('has unique ids', () => {
    const ids = IDP_PATTERNS.map((p) => p.id)
    expect(new Set(ids).size).toBe(ids.length)
  })

  it('all patterns anchor start and end', () => {
    for (const p of IDP_PATTERNS) {
      expect(p.pattern.source.startsWith('^')).toBe(true)
      expect(p.pattern.source.endsWith('$')).toBe(true)
    }
  })
})

describe('recognizeIssuer — Entra ID', () => {
  it('matches Entra v1 (sts.windows.net)', () => {
    const r = recognizeIssuer('https://sts.windows.net/00000000-0000-0000-0000-000000000001/')
    expect(r?.pattern.id).toBe('entraV1')
    expect(r?.tenant).toBe('00000000-0000-0000-0000-000000000001')
  })

  it('matches Entra v2 (login.microsoftonline.com /<tid>/v2.0)', () => {
    const r = recognizeIssuer('https://login.microsoftonline.com/00000000-0000-0000-0000-000000000001/v2.0')
    expect(r?.pattern.id).toBe('entraV2')
    expect(r?.tenant).toBe('00000000-0000-0000-0000-000000000001')
  })

  it('matches Entra v2 common / organizations tenants', () => {
    expect(recognizeIssuer('https://login.microsoftonline.com/common/v2.0')?.tenant).toBe('common')
    expect(recognizeIssuer('https://login.microsoftonline.com/organizations/v2.0')?.tenant).toBe(
      'organizations'
    )
  })

  it('matches Entra v2 sovereign clouds (.us, .cn, .de)', () => {
    expect(
      recognizeIssuer('https://login.microsoftonline.us/00000000-0000-0000-0000-000000000001/v2.0')?.pattern.id
    ).toBe('entraV2')
  })

  it('Entra v1 carries guidance about v2.0 migration', () => {
    const r = recognizeIssuer('https://sts.windows.net/00000000-0000-0000-0000-000000000001/')
    expect(r?.pattern.guidance).toMatch(/v2\.0/)
  })
})

describe('recognizeIssuer — Okta', () => {
  it('matches okta.com domain', () => {
    const r = recognizeIssuer('https://my-tenant.okta.com/oauth2/default')
    expect(r?.pattern.id).toBe('okta')
    expect(r?.tenant).toBe('my-tenant')
    expect(r?.extras.environment).toBe('okta')
  })

  it('matches okta-emea variant', () => {
    expect(recognizeIssuer('https://eu.okta-emea.com/oauth2/default')?.pattern.id).toBe('okta')
  })

  it('matches oktapreview', () => {
    expect(recognizeIssuer('https://demo.oktapreview.com/oauth2')?.pattern.id).toBe('okta')
  })
})

describe('recognizeIssuer — Auth0', () => {
  it('matches plain tenant', () => {
    const r = recognizeIssuer('https://example.auth0.com/')
    expect(r?.pattern.id).toBe('auth0')
    expect(r?.tenant).toBe('example')
  })

  it('matches region-qualified tenant', () => {
    expect(recognizeIssuer('https://example.eu.auth0.com/')?.pattern.id).toBe('auth0')
  })
})

describe('recognizeIssuer — Cognito', () => {
  it('matches cognito user-pool issuer', () => {
    const r = recognizeIssuer('https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc12345')
    expect(r?.pattern.id).toBe('cognito')
    expect(r?.tenant).toBe('us-east-1_abc12345')
    expect(r?.extras.region).toBe('us-east-1')
  })
})

describe('recognizeIssuer — Cloudflare Access', () => {
  it('matches cloudflareaccess.com domain', () => {
    const r = recognizeIssuer('https://example.cloudflareaccess.com/')
    expect(r?.pattern.id).toBe('cloudflareAccess')
    expect(r?.tenant).toBe('example')
  })
})

describe('recognizeIssuer — SailPoint', () => {
  it('matches identitynow.com', () => {
    expect(recognizeIssuer('https://acme.identitynow.com/oauth')?.pattern.id).toBe('sailpoint')
  })

  it('matches api.identitynow.com variant', () => {
    const r = recognizeIssuer('https://acme.api.identitynow.com')
    expect(r?.pattern.id).toBe('sailpoint')
    expect(r?.tenant).toBe('acme')
  })
})

describe('recognizeIssuer — Google / Firebase / CI OIDC', () => {
  it('matches Google accounts', () => {
    expect(recognizeIssuer('https://accounts.google.com')?.pattern.id).toBe('googleAccounts')
  })

  it('matches Firebase securetoken', () => {
    expect(recognizeIssuer('https://securetoken.google.com/my-project')?.tenant).toBe('my-project')
  })

  it('matches GitHub Actions OIDC', () => {
    expect(recognizeIssuer('https://token.actions.githubusercontent.com')?.pattern.id).toBe(
      'githubActions'
    )
  })

  it('matches GitLab OIDC', () => {
    expect(recognizeIssuer('https://gitlab.com')?.pattern.id).toBe('gitlabOidc')
  })
})

describe('recognizeIssuer — Ping Identity', () => {
  it('matches PingOne with env id', () => {
    const r = recognizeIssuer('https://auth.pingone.com/00000000-0000-0000-0000-000000000001/')
    expect(r?.pattern.id).toBe('pingOne')
    expect(r?.tenant).toBe('auth')
    expect(r?.extras.envId).toBe('00000000-0000-0000-0000-000000000001')
  })

  it('matches PingIdentity cloud', () => {
    const r = recognizeIssuer('https://acme.pingidentity.cloud/')
    expect(r?.pattern.id).toBe('pingIdentity')
    expect(r?.tenant).toBe('acme')
  })

  it('matches PingIdentity cloud with path suffix', () => {
    const r = recognizeIssuer('https://acme.pingidentity.cloud/as')
    expect(r?.pattern.id).toBe('pingIdentity')
    expect(r?.tenant).toBe('acme')
  })
})

describe('recognizeIssuer — ForgeRock', () => {
  it('matches forgerock.io with /am/oauth2', () => {
    const r = recognizeIssuer('https://openam-acme.forgerock.io/am/oauth2')
    expect(r?.pattern.id).toBe('forgerock')
    expect(r?.tenant).toBe('openam-acme')
  })

  it('matches identitycloud.com with realm segment', () => {
    const r = recognizeIssuer('https://acme.identitycloud.com/oauth2/alpha')
    expect(r?.pattern.id).toBe('forgerock')
    expect(r?.tenant).toBe('acme')
  })
})

describe('recognizeIssuer — OneLogin', () => {
  it('matches onelogin OIDC v2 endpoint', () => {
    const r = recognizeIssuer('https://acme.onelogin.com/oidc/2')
    expect(r?.pattern.id).toBe('oneLogin')
    expect(r?.tenant).toBe('acme')
  })
})

describe('recognizeIssuer — Keycloak', () => {
  it('matches keycloak /auth/realms/<realm>', () => {
    const r = recognizeIssuer('https://keycloak.example.com/auth/realms/myrealm')
    expect(r?.pattern.id).toBe('keycloak')
    expect(r?.tenant).toBe('myrealm')
  })

  it('accepts http for self-hosted dev instances', () => {
    const r = recognizeIssuer('http://localhost:8080/auth/realms/dev')
    expect(r?.pattern.id).toBe('keycloak')
    expect(r?.tenant).toBe('dev')
  })
})

describe('recognizeIssuer — Salesforce', () => {
  it('matches login.salesforce.com (no tenant)', () => {
    const r = recognizeIssuer('https://login.salesforce.com/')
    expect(r?.pattern.id).toBe('salesforce')
    expect(r?.tenant).toBeUndefined()
  })

  it('matches my.salesforce.com tenant subdomain', () => {
    const r = recognizeIssuer('https://acme.my.salesforce.com/')
    expect(r?.pattern.id).toBe('salesforce')
    expect(r?.tenant).toBe('acme')
  })
})

describe('recognizeIssuer — Apple', () => {
  it('matches appleid.apple.com', () => {
    const r = recognizeIssuer('https://appleid.apple.com')
    expect(r?.pattern.id).toBe('appleId')
    expect(r?.tenant).toBeUndefined()
  })
})

describe('recognizeIssuer — Microsoft B2C', () => {
  it('matches b2clogin with tenant id and v2.0 suffix', () => {
    const r = recognizeIssuer(
      'https://contoso.b2clogin.com/00000000-0000-0000-0000-000000000001/v2.0/'
    )
    expect(r?.pattern.id).toBe('microsoftB2C')
    expect(r?.tenant).toBe('00000000-0000-0000-0000-000000000001')
    expect(r?.extras.account).toBe('contoso')
  })
})

describe('recognizeIssuer — Clerk', () => {
  it('matches clerk.accounts.dev', () => {
    const r = recognizeIssuer('https://crisp-yak-42.clerk.accounts.dev')
    expect(r?.pattern.id).toBe('clerk')
    expect(r?.tenant).toBe('crisp-yak-42')
  })
})

describe('recognizeIssuer — WorkOS', () => {
  it('matches api.workos.com', () => {
    const r = recognizeIssuer('https://api.workos.com')
    expect(r?.pattern.id).toBe('workOs')
    expect(r?.tenant).toBeUndefined()
  })
})

describe('recognizeIssuer — Frontegg', () => {
  it('matches frontegg subdomain', () => {
    const r = recognizeIssuer('https://acme.frontegg.com/')
    expect(r?.pattern.id).toBe('frontegg')
    expect(r?.tenant).toBe('acme')
  })
})

describe('recognizeIssuer — Descope', () => {
  it('matches descope project id (v1 prefix)', () => {
    const r = recognizeIssuer('https://api.descope.com/v1/P2abc123XYZ')
    expect(r?.pattern.id).toBe('descope')
    expect(r?.tenant).toBe('P2abc123XYZ')
  })

  it('matches descope project id without v1 prefix', () => {
    const r = recognizeIssuer('https://api.descope.com/P2abc123XYZ')
    expect(r?.pattern.id).toBe('descope')
    expect(r?.tenant).toBe('P2abc123XYZ')
  })
})

describe('recognizeIssuer — Twitch / LinkedIn / Discord', () => {
  it('matches Twitch OIDC', () => {
    const r = recognizeIssuer('https://id.twitch.tv/oauth2')
    expect(r?.pattern.id).toBe('twitch')
  })

  it('matches LinkedIn', () => {
    const r = recognizeIssuer('https://www.linkedin.com')
    expect(r?.pattern.id).toBe('linkedin')
  })

  it('matches Discord', () => {
    const r = recognizeIssuer('https://discord.com')
    expect(r?.pattern.id).toBe('discord')
  })
})

describe('recognizeIssuer — negatives', () => {
  it('returns undefined for empty / non-string', () => {
    expect(recognizeIssuer('')).toBeUndefined()
    expect(recognizeIssuer(undefined as unknown as string)).toBeUndefined()
  })

  it('returns undefined for unrelated URLs', () => {
    expect(recognizeIssuer('https://example.com')).toBeUndefined()
  })

  it('returns undefined for unrelated oauth2 URL', () => {
    expect(recognizeIssuer('https://random.example.com/oauth2')).toBeUndefined()
  })

  it('does not match Entra v2 without /v2.0 suffix', () => {
    expect(
      recognizeIssuer('https://login.microsoftonline.com/00000000-0000-0000-0000-000000000001/')
    ).toBeUndefined()
  })
})
