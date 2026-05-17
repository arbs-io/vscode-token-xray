import { TextDocument, Uri, workspace, WorkspaceFolder } from 'vscode'

/**
 * Utilities for translating a `vscode.TextDocument`'s URI into the
 * shapes the analyzers + filters care about. Extracted from
 * `findingsTreeViewProvider` and `securityDiagnosticsProvider` because
 * both providers needed identical notebook → fsPath → workspace-relative
 * conversion logic.
 *
 * No analyzer logic lives here; only path arithmetic. The functions
 * tolerate untitled / unrooted / non-file URIs (each returns a sensible
 * fallback) so callers never need to special-case them.
 */

const NOTEBOOK_CELL_SCHEME = 'vscode-notebook-cell'

/**
 * For a `vscode-notebook-cell` URI, return a synthesised `file:` URI
 * pointing at the parent `.ipynb`. Returns `undefined` for any other
 * scheme (caller should use the original URI in that case).
 *
 * VS Code encodes cells as `vscode-notebook-cell:///path/to/file.ipynb#cellId`,
 * so `uri.path` already holds the on-disk path; we strip the fragment
 * and rebrand the scheme so the rest of the pipeline can treat the cell
 * as a regular file for ignore-glob and workspace-folder lookups.
 */
export function notebookFileUri(uri: Uri): Uri | undefined {
  if (uri.scheme !== NOTEBOOK_CELL_SCHEME) return undefined
  if (!uri.path) return undefined
  return uri.with({ scheme: 'file', fragment: '' })
}

/**
 * Resolve the document's "effective" on-disk URI: the notebook parent
 * for cells, the document URI for everything else.
 */
export function effectiveUri(doc: TextDocument): Uri {
  return notebookFileUri(doc.uri) ?? doc.uri
}

/**
 * Strip the leading workspace-folder prefix + any leading separators
 * from `fsPath`. Returns `undefined` when `fsPath` is not inside
 * `folder`. The returned string uses the host path separator (callers
 * who need forward-slashes should normalise).
 */
function stripWorkspacePrefix(fsPath: string, folder: WorkspaceFolder): string | undefined {
  const folderPath = folder.uri.fsPath
  if (!fsPath.startsWith(folderPath)) return undefined
  return fsPath.slice(folderPath.length).replace(/^[\\/]+/, '')
}

/**
 * Workspace-relative display path for the document (suitable for
 * tooltips, tree-view descriptions, and `secrets.exclude` glob
 * matching). Falls back to the absolute fsPath when the document is
 * outside every workspace folder, and to `undefined` for untitled
 * buffers / non-file schemes (which have no on-disk filename to match
 * a glob against).
 */
export function workspaceRelativeFilename(doc: TextDocument): string | undefined {
  const sourceUri = effectiveUri(doc)
  if (sourceUri.scheme !== 'file') return undefined
  const folder = workspace.getWorkspaceFolder(sourceUri)
  if (folder) {
    const stripped = stripWorkspacePrefix(sourceUri.fsPath, folder)
    if (stripped !== undefined) return stripped
  }
  return sourceUri.fsPath
}

/**
 * Same as {@link workspaceRelativeFilename} but always normalised to
 * forward-slash separators — required by glob and `.gitignore`-style
 * matchers, which assume POSIX paths. Returns `undefined` for
 * documents that aren't inside any workspace folder (an unrooted
 * file can't match a workspace-scoped ignore rule).
 */
export function workspaceRelativePathForIgnore(
  doc: TextDocument,
  folder: WorkspaceFolder
): string | undefined {
  const sourceUri = effectiveUri(doc)
  if (sourceUri.scheme !== 'file') return undefined
  const stripped = stripWorkspacePrefix(sourceUri.fsPath, folder)
  if (stripped === undefined) return undefined
  return stripped.replace(/\\/g, '/')
}

/**
 * The label the providers show in tree descriptions / debug logs when
 * `workspaceRelativeFilename` returns `undefined` (e.g. untitled
 * buffers). Picks the URI's basename so logs don't show the full
 * `untitled:Untitled-1` blob.
 */
export function fallbackDisplayLabel(uri: Uri): string {
  const basename = uri.path.split('/').pop()
  return basename ? basename : uri.toString()
}
