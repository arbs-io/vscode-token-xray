import { decodeJwt } from '../analyzers/jwt/decoder'

export class JwtDecoder {
  public joseHeader: object
  public claimset: object

  constructor(token: string) {
    if (typeof token !== 'string') {
      throw new Error('Invalid token specified')
    }
    try {
      const decoded = decodeJwt(token)
      this.joseHeader = decoded.header
      this.claimset = decoded.payload ?? {}
    } catch (e) {
      throw new Error(`Invalid token specified: ${(e as Error).message}`)
    }
  }
}
