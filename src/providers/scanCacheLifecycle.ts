import { ExtensionContext, window, workspace } from 'vscode'
import { ScanCache } from '../core/scanCache'
import { effectiveTabUri, openTabUriStrings } from '../utils/openTabs'

/**
 * Owns the vscode wiring that keeps a `ScanCache` clean. When a doc
 * closes or its tab disappears (`onDidCloseTextDocument` is not
 * guaranteed to fire for tab closes — see the existing providers), the
 * cache's entry is dropped so a re-open of the same URI does not serve
 * tokens from the prior session.
 *
 * Kept separate from the providers because the cache is shared state:
 * its lifecycle is owned by `extension.ts`, not by any one consumer.
 */
export function registerScanCacheLifecycle(
  context: ExtensionContext,
  cache: ScanCache
): void {
  context.subscriptions.push(
    workspace.onDidCloseTextDocument((doc) => cache.invalidate(doc.uri.toString())),
    window.tabGroups.onDidChangeTabs((event) => {
      if (event.closed.length === 0) return
      const openTabs = openTabUriStrings()
      // Any document that no longer has a tab — including ghost docs
      // VS Code kept alive past their tab — loses its cache entry, so
      // a fresh scan runs the next time the file is opened.
      for (const doc of workspace.textDocuments) {
        if (!openTabs.has(effectiveTabUri(doc.uri).toString())) {
          cache.invalidate(doc.uri.toString())
        }
      }
    })
  )
}
