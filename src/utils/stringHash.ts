export function stringHash(str: string): number {
  let hash = 5381
  ;[...str].forEach((c) => (hash = (hash * 33) ^ (c.codePointAt(0) ?? 0)))
  return hash >>> 0
}
