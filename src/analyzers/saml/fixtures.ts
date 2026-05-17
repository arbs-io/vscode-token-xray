export interface SamlFixtureOptions {
  signed?: boolean
  signatureAlg?: string
  digestAlg?: string
  notBefore?: string
  notOnOrAfter?: string
  audience?: string | null
  issuer?: string | null
  nameId?: string
  encrypted?: boolean
}

const SIGNATURE_BLOCK = (alg: string, dig: string) => `
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo>
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="${alg}"/>
        <ds:Reference URI="#a1">
          <ds:Transforms>
            <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          </ds:Transforms>
          <ds:DigestMethod Algorithm="${dig}"/>
          <ds:DigestValue>xxx</ds:DigestValue>
        </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue>xxx</ds:SignatureValue>
    </ds:Signature>`

function renderConditions(options: SamlFixtureOptions): string {
  if (!options.notBefore && !options.notOnOrAfter && options.audience === null) return ''
  const notBeforeAttr = options.notBefore ? ` NotBefore="${options.notBefore}"` : ''
  const notOnOrAfterAttr = options.notOnOrAfter ? ` NotOnOrAfter="${options.notOnOrAfter}"` : ''
  const audienceBody =
    options.audience === null
      ? ''
      : `<saml:AudienceRestriction><saml:Audience>${options.audience ?? 'https://sp.example.test/'}</saml:Audience></saml:AudienceRestriction>`
  return `<saml:Conditions${notBeforeAttr}${notOnOrAfterAttr}>${audienceBody}</saml:Conditions>`
}

export function samlResponseFixture(options: SamlFixtureOptions = {}): string {
  const issuer = options.issuer === null ? '' : `<saml:Issuer>${options.issuer ?? 'https://idp.example.test/'}</saml:Issuer>`
  const conditions =
    options.notBefore || options.notOnOrAfter || options.audience !== null ? renderConditions(options) : ''
  const signature = options.signed
    ? SIGNATURE_BLOCK(
        options.signatureAlg ?? 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
        options.digestAlg ?? 'http://www.w3.org/2001/04/xmlenc#sha256'
      )
    : ''

  const assertion = options.encrypted
    ? `<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element"/></saml:EncryptedAssertion>`
    : `<saml:Assertion ID="a1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
        ${issuer}
        <saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${options.nameId ?? 'alice@example.test'}</saml:NameID></saml:Subject>
        ${conditions}
        ${signature}
      </saml:Assertion>`

  return `<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="r1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
  ${issuer}
  ${assertion}
</samlp:Response>`
}

export function toBase64(text: string): string {
  return Buffer.from(text, 'utf8').toString('base64')
}

export function toRedirectEncoded(text: string): string {
  // HTTP-Redirect binding: DEFLATE then base64 then URL-encode.
  // Using zlib.deflateRawSync to produce raw deflate (no zlib header).
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { deflateRawSync } = require('node:zlib')
  const deflated = deflateRawSync(Buffer.from(text, 'utf8'))
  return encodeURIComponent(deflated.toString('base64'))
}
