import { BasicAuthAnalyzer } from '../analyzers/basicAuth/analyzer'
import { CookieAnalyzer } from '../analyzers/cookie/analyzer'
import { JwkAnalyzer } from '../analyzers/jwk/analyzer'
import { JwtAnalyzer } from '../analyzers/jwt/analyzer'
import { OAuthTokenAnalyzer } from '../analyzers/oauth/analyzer'
import { PasetoAnalyzer } from '../analyzers/paseto/analyzer'
import { SamlAnalyzer } from '../analyzers/saml/analyzer'
import { SecretAnalyzer } from '../analyzers/secrets/analyzer'
import { X509Analyzer } from '../analyzers/x509/analyzer'
import { AnalyzerRegistry } from './registry'

export function createDefaultRegistry(): AnalyzerRegistry {
  const registry = new AnalyzerRegistry()
  registry.register(new JwtAnalyzer())
  registry.register(new SamlAnalyzer())
  registry.register(new X509Analyzer())
  registry.register(new JwkAnalyzer())
  registry.register(new OAuthTokenAnalyzer())
  registry.register(new CookieAnalyzer())
  registry.register(new PasetoAnalyzer())
  registry.register(new BasicAuthAnalyzer())
  registry.register(new SecretAnalyzer())
  return registry
}
