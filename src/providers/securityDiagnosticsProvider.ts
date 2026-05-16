import {
  Diagnostic,
  DiagnosticSeverity,
  ExtensionContext,
  languages,
  Range,
  TextDocument,
  Uri,
  workspace,
} from 'vscode'
import { createDefaultRegistry } from '../core/defaultRegistry'
import { DiagnosticDto } from '../core/diagnostics'
import {
  DEFAULT_SECRETS_MAX_FILE_SIZE_BYTES,
  ScanTextSettings,
  scanText,
} from '../core/scanText'

const SEVERITY_MAP: Record<DiagnosticDto['severity'], DiagnosticSeverity> = {
  error: DiagnosticSeverity.Error,
  warning: DiagnosticSeverity.Warning,
  information: DiagnosticSeverity.Information,
  hint: DiagnosticSeverity.Hint,
}

const SUPPORTED_SCHEMES = new Set(['file', 'untitled'])

function dtoToDiagnostic(dto: DiagnosticDto): Diagnostic {
  const diag = new Diagnostic(
    new Range(dto.range.startLine, dto.range.startColumn, dto.range.endLine, dto.range.endColumn),
    dto.message,
    SEVERITY_MAP[dto.severity]
  )
  diag.source = dto.source
  diag.code = dto.code
  return diag
}

function readSecretsSettings(uri: Uri): ScanTextSettings {
  const config = workspace.getConfiguration('tokenXray', uri)
  return {
    secrets: {
      enabled: config.get<boolean>('secrets.enabled', true),
      exclude: config.get<string[]>('secrets.exclude', []),
      maxFileSizeBytes: config.get<number>(
        'secrets.maxFileSizeBytes',
        DEFAULT_SECRETS_MAX_FILE_SIZE_BYTES
      ),
    },
  }
}

function filenameFor(doc: TextDocument): string | undefined {
  if (doc.uri.scheme === 'file') {
    const folder = workspace.getWorkspaceFolder(doc.uri)
    if (folder) {
      const folderPath = folder.uri.fsPath
      const filePath = doc.uri.fsPath
      if (filePath.startsWith(folderPath)) {
        // Strip the workspace prefix + leading separator so exclude globs are
        // matched against a workspace-relative path.
        return filePath.slice(folderPath.length).replace(/^[\\/]+/, '')
      }
    }
    return doc.uri.fsPath
  }
  // untitled buffers — no on-disk filename
  return undefined
}

export function registerSecurityDiagnosticsProvider(context: ExtensionContext) {
  const registry = createDefaultRegistry()
  const collection = languages.createDiagnosticCollection('tokenXray')
  context.subscriptions.push(collection)

  const refresh = async (doc: TextDocument) => {
    if (!SUPPORTED_SCHEMES.has(doc.uri.scheme)) {
      collection.delete(doc.uri)
      return
    }
    try {
      const settings = readSecretsSettings(doc.uri)
      const filename = filenameFor(doc)
      const dtos = await scanText(doc.getText(), filename, registry, settings)
      collection.set(doc.uri, dtos.map(dtoToDiagnostic))
    } catch {
      collection.delete(doc.uri)
    }
  }

  for (const doc of workspace.textDocuments) {
    void refresh(doc)
  }

  context.subscriptions.push(
    workspace.onDidOpenTextDocument((doc) => void refresh(doc)),
    workspace.onDidChangeTextDocument((e) => void refresh(e.document)),
    workspace.onDidCloseTextDocument((doc) => collection.delete(doc.uri)),
    workspace.onDidChangeConfiguration((e) => {
      if (!e.affectsConfiguration('tokenXray.secrets')) return
      for (const doc of workspace.textDocuments) {
        void refresh(doc)
      }
    })
  )
}
