import {
  TabInputNotebook,
  TabInputNotebookDiff,
  TabInputText,
  TabInputTextDiff,
  Uri,
  window,
} from 'vscode'

/**
 * Returns the set of URI strings that are currently bound to an editor tab.
 *
 * Token X-Ray uses this as the source-of-truth for "documents the user can
 * actually see". `workspace.onDidCloseTextDocument` is not guaranteed to
 * fire when a tab is closed — VS Code can keep the underlying
 * `TextDocument` alive in `workspace.textDocuments` long after the tab
 * disappears — so refreshing on `window.tabGroups.onDidChangeTabs` and
 * filtering by this set is what keeps the findings tree view and the
 * Problems panel from showing stale results.
 *
 * Diff tabs contribute both sides. Webview / terminal / custom tabs are
 * ignored because they have no backing text document.
 */
export function openTabUriStrings(): Set<string> {
  const set = new Set<string>()
  for (const group of window.tabGroups.all) {
    for (const tab of group.tabs) {
      const input = tab.input
      if (input instanceof TabInputText || input instanceof TabInputNotebook) {
        set.add(input.uri.toString())
      } else if (input instanceof TabInputTextDiff || input instanceof TabInputNotebookDiff) {
        set.add(input.original.toString())
        set.add(input.modified.toString())
      }
    }
  }
  return set
}

/**
 * Maps a `vscode-notebook-cell:` URI to its parent `.ipynb` file URI so a
 * cell can be matched against the notebook tab that hosts it. For other
 * URIs the input is returned unchanged.
 */
export function effectiveTabUri(uri: Uri): Uri {
  if (uri.scheme !== 'vscode-notebook-cell' || !uri.path) return uri
  return uri.with({ scheme: 'file', fragment: '' })
}
