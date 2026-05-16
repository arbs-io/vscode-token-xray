import { ExtensionContext, Hover, languages, MarkdownString } from 'vscode'
import { LocalStorageService } from '../services/storageService'
import { stringHash } from '../utils/stringHash'

export function registerHoverProvider(context: ExtensionContext) {
  context.subscriptions.push(
    languages.registerHoverProvider('jwt', {
      provideHover(document, position) {
        const docHash = stringHash(document.uri.toString())
        const storage = new LocalStorageService(context.workspaceState)
        const kind = storage.getValue<string>(`jwtKind_${docHash}`)

        const range = document.getWordRangeAtPosition(position)
        const storageKey =
          range?.start.character === 0 ? `joseHeader_${docHash}` : `claimsSet_${docHash}`
        const value = storage.getValue<object>(storageKey)

        if (kind === 'JWE' && storageKey === `claimsSet_${docHash}`) {
          const md = new MarkdownString(
            '**JWE** — payload is encrypted. Provide a decryption key to inspect contents.'
          )
          return new Hover(md)
        }

        if (!value) return undefined

        return new Hover({
          language: 'json',
          value: JSON.stringify(value, undefined, 4),
        })
      },
    })
  )
}
