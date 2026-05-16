import * as fs from 'fs'
import * as path from 'path'
import {
  CancellationToken,
  CodeAction,
  CodeActionContext,
  CodeActionKind,
  CodeActionProvider,
  Diagnostic,
  ExtensionContext,
  languages,
  Position,
  Range,
  TextDocument,
  Uri,
  WorkspaceEdit,
  workspace,
} from 'vscode'
import {
  CodeActionDto,
  CodeActionSideEffectDto,
  findingsToCodeActionDtos,
  isSecretDiagnostic,
} from '../core/secretCodeActions'
import { DiagnosticDto, DiagnosticSeverityDto } from '../core/diagnostics'

const SUPPORTED_SCHEMES = new Set(['file', 'untitled'])

const SEVERITY_DTO: Record<number, DiagnosticSeverityDto> = {
  0: 'error', // DiagnosticSeverity.Error
  1: 'warning', // DiagnosticSeverity.Warning
  2: 'information', // DiagnosticSeverity.Information
  3: 'hint', // DiagnosticSeverity.Hint
}

export class SecretCodeActionsProvider implements CodeActionProvider {
  static readonly providedCodeActionKinds = [CodeActionKind.QuickFix]

  provideCodeActions(
    document: TextDocument,
    _range: Range,
    context: CodeActionContext,
    _token: CancellationToken
  ): CodeAction[] {
    if (!SUPPORTED_SCHEMES.has(document.uri.scheme)) return []
    const secretDtos: DiagnosticDto[] = context.diagnostics
      .map((d) => diagnosticToDto(d))
      .filter((d): d is DiagnosticDto => !!d && isSecretDiagnostic(d))
    if (secretDtos.length === 0) return []

    const text = document.getText()
    const dtos = findingsToCodeActionDtos(secretDtos, text, document.uri.toString())
    return dtos.map((dto) => dtoToCodeAction(dto, document, context.diagnostics))
  }
}

function diagnosticToDto(d: Diagnostic): DiagnosticDto | undefined {
  if (!d.code || !d.source) return undefined
  const code = typeof d.code === 'object' ? d.code.value : d.code
  const severity = SEVERITY_DTO[d.severity] ?? 'warning'
  return {
    source: d.source,
    code: String(code),
    message: d.message,
    severity,
    range: {
      startLine: d.range.start.line,
      startColumn: d.range.start.character,
      endLine: d.range.end.line,
      endColumn: d.range.end.character,
    },
  }
}

function dtoToCodeAction(
  dto: CodeActionDto,
  document: TextDocument,
  contextDiagnostics: readonly Diagnostic[]
): CodeAction {
  const action = new CodeAction(dto.title, CodeActionKind.QuickFix)
  const edit = new WorkspaceEdit()
  for (const e of dto.edits) {
    const range = new Range(
      new Position(e.range.startLine, e.range.startColumn),
      new Position(e.range.endLine, e.range.endColumn)
    )
    edit.replace(document.uri, range, e.newText)
  }
  if (dto.sideEffects && dto.sideEffects.length > 0) {
    applySideEffects(edit, dto.sideEffects, document)
  }
  action.edit = edit
  // Link the action back to the diagnostic it fixes — vscode uses this to put
  // the lightbulb on that diagnostic.
  const linked = contextDiagnostics.find((d) => {
    const code = typeof d.code === 'object' ? d.code?.value : d.code
    return String(code) === dto.findingId
  })
  if (linked) {
    action.diagnostics = [linked]
  }
  return action
}

/**
 * Apply each side-effect to the supplied WorkspaceEdit. We resolve target file
 * URIs relative to the source document's workspace folder (or its parent
 * directory if no workspace is open).
 */
function applySideEffects(
  edit: WorkspaceEdit,
  sideEffects: readonly CodeActionSideEffectDto[],
  document: TextDocument
): void {
  for (const fx of sideEffects) {
    if (fx.kind !== 'appendToFile') continue
    const targetUri = resolveTargetUri(document, fx.file)
    if (!targetUri) continue
    const exists = targetUri.scheme === 'file' && safeStat(targetUri.fsPath)
    if (!exists) {
      edit.createFile(targetUri, { ignoreIfExists: true })
    }
    const prefix = exists ? '\n' : ''
    edit.insert(targetUri, endOfFilePosition(targetUri), `${prefix}${fx.line}\n`)
  }
}

function resolveTargetUri(document: TextDocument, relative: string): Uri | undefined {
  const folder = workspace.getWorkspaceFolder(document.uri)
  if (folder) {
    return Uri.joinPath(folder.uri, relative)
  }
  if (document.uri.scheme === 'file') {
    return Uri.file(path.join(path.dirname(document.uri.fsPath), relative))
  }
  return undefined
}

function endOfFilePosition(uri: Uri): Position {
  if (uri.scheme !== 'file') return new Position(0, 0)
  try {
    const text = fs.readFileSync(uri.fsPath, 'utf8')
    const lineCount = text.split('\n').length
    return new Position(Math.max(0, lineCount - 1), 0)
  } catch {
    return new Position(0, 0)
  }
}

function safeStat(p: string): boolean {
  try {
    return fs.statSync(p).isFile()
  } catch {
    return false
  }
}

export function registerSecretCodeActionsProvider(context: ExtensionContext) {
  const enabled = workspace
    .getConfiguration('tokenXray')
    .get<boolean>('secrets.codeActions.enabled', true)
  if (!enabled) return

  const provider = new SecretCodeActionsProvider()
  context.subscriptions.push(
    languages.registerCodeActionsProvider(
      [
        { scheme: 'file', pattern: '**/*' },
        { scheme: 'untitled', pattern: '**/*' },
      ],
      provider,
      {
        providedCodeActionKinds: SecretCodeActionsProvider.providedCodeActionKinds,
      }
    )
  )
}
