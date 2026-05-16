export function base64UrlDecode(input: string): string {
  let output = input.replace(/-/g, '+').replace(/_/g, '/')
  switch (output.length % 4) {
    case 0:
      break
    case 2:
      output += '=='
      break
    case 3:
      output += '='
      break
    default:
      throw new Error('invalid base64url string')
  }

  const binary = atob(output)
  try {
    return decodeURIComponent(
      binary.replace(/(.)/g, (_m, p: string) => {
        const code = p.charCodeAt(0).toString(16).toUpperCase()
        return '%' + (code.length < 2 ? '0' + code : code)
      })
    )
  } catch {
    return binary
  }
}

export function base64UrlDecodeBytes(input: string): Uint8Array {
  let output = input.replace(/-/g, '+').replace(/_/g, '/')
  switch (output.length % 4) {
    case 0:
      break
    case 2:
      output += '=='
      break
    case 3:
      output += '='
      break
    default:
      throw new Error('invalid base64url string')
  }
  const binary = atob(output)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}
