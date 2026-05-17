/**
 * Hand-rolled vscode test double. The real `vscode` module is only
 * available inside an Extension Development Host, so the provider tests
 * stub it out via `vi.mock('vscode', () => ...)`. The state lives at
 * module scope so tests can mutate it via the helpers below; call
 * `resetVscodeMock()` in `beforeEach` to start each test from a clean
 * slate.
 *
 * Only the surface that `findingsTreeViewProvider`, `securityDiagnosticsProvider`,
 * and `utils/openTabs` actually touch is implemented. Adding more is
 * fine — keep it minimal and predictable, since over-faithful mocks
 * just rot in step with the real API.
 */

type Listener<T> = (value: T) => void
type Disposable = { dispose: () => void }

class FakeEventEmitter<T> {
  private listeners: Array<Listener<T>> = []
  readonly event = (listener: Listener<T>): Disposable => {
    this.listeners.push(listener)
    return {
      dispose: () => {
        this.listeners = this.listeners.filter((l) => l !== listener)
      },
    }
  }
  fire(value: T): void {
    for (const l of [...this.listeners]) l(value)
  }
  dispose(): void {
    this.listeners = []
  }
}

class FakeUri {
  readonly scheme: string
  readonly authority: string
  readonly path: string
  readonly query: string
  readonly fragment: string

  constructor(parts: {
    scheme: string
    authority?: string
    path?: string
    query?: string
    fragment?: string
  }) {
    this.scheme = parts.scheme
    this.authority = parts.authority ?? ''
    this.path = parts.path ?? ''
    this.query = parts.query ?? ''
    this.fragment = parts.fragment ?? ''
  }

  get fsPath(): string {
    return this.path
  }

  with(change: {
    scheme?: string
    authority?: string
    path?: string
    query?: string
    fragment?: string
  }): FakeUri {
    return new FakeUri({
      scheme: change.scheme ?? this.scheme,
      authority: change.authority ?? this.authority,
      path: change.path ?? this.path,
      query: change.query ?? this.query,
      fragment: change.fragment ?? this.fragment,
    })
  }

  toString(): string {
    const auth = this.authority ? `//${this.authority}` : ''
    const q = this.query ? `?${this.query}` : ''
    const f = this.fragment ? `#${this.fragment}` : ''
    return `${this.scheme}:${auth}${this.path}${q}${f}`
  }

  static parse(value: string): FakeUri {
    // Minimal `scheme:authority/path?query#fragment` parser; sufficient
    // for round-tripping URIs produced by `toString()` above.
    const schemeMatch = /^([a-zA-Z][a-zA-Z0-9+\-.]*):/.exec(value)
    if (!schemeMatch) throw new Error(`FakeUri.parse: missing scheme in ${value}`)
    const scheme = schemeMatch[1]
    let rest = value.slice(schemeMatch[0].length)
    let authority = ''
    if (rest.startsWith('//')) {
      rest = rest.slice(2)
      const slash = rest.indexOf('/')
      if (slash === -1) {
        authority = rest
        rest = ''
      } else {
        authority = rest.slice(0, slash)
        rest = rest.slice(slash)
      }
    }
    let fragment = ''
    const hash = rest.indexOf('#')
    if (hash !== -1) {
      fragment = rest.slice(hash + 1)
      rest = rest.slice(0, hash)
    }
    let query = ''
    const qIdx = rest.indexOf('?')
    if (qIdx !== -1) {
      query = rest.slice(qIdx + 1)
      rest = rest.slice(0, qIdx)
    }
    return new FakeUri({ scheme, authority, path: rest, query, fragment })
  }

  static file(p: string): FakeUri {
    return new FakeUri({ scheme: 'file', path: p })
  }

  static joinPath(base: FakeUri, ...segments: string[]): FakeUri {
    const joined = [base.path, ...segments].filter(Boolean).join('/').replace(/\/+/g, '/')
    return base.with({ path: joined })
  }
}

class FakeRange {
  constructor(
    readonly startLine: number,
    readonly startColumn: number,
    readonly endLine: number,
    readonly endColumn: number
  ) {}
  get start() {
    return { line: this.startLine, character: this.startColumn }
  }
  get end() {
    return { line: this.endLine, character: this.endColumn }
  }
}

const DiagnosticSeverity = {
  Error: 0,
  Warning: 1,
  Information: 2,
  Hint: 3,
} as const

class FakeDiagnostic {
  source?: string
  code?: string | number
  constructor(
    readonly range: FakeRange,
    readonly message: string,
    readonly severity: number
  ) {}
}

class FakeDiagnosticCollection {
  private map = new Map<string, FakeDiagnostic[]>()
  constructor(readonly name: string) {}
  set(uri: FakeUri, diagnostics: FakeDiagnostic[]): void {
    this.map.set(uri.toString(), diagnostics)
  }
  delete(uri: FakeUri): void {
    this.map.delete(uri.toString())
  }
  get(uri: FakeUri): FakeDiagnostic[] | undefined {
    return this.map.get(uri.toString())
  }
  has(uri: FakeUri): boolean {
    return this.map.has(uri.toString())
  }
  forEach(
    cb: (uri: FakeUri, diagnostics: FakeDiagnostic[], coll: FakeDiagnosticCollection) => void
  ): void {
    for (const [key, value] of Array.from(this.map.entries())) {
      cb(FakeUri.parse(key), value, this)
    }
  }
  clear(): void {
    this.map.clear()
  }
  dispose(): void {
    this.map.clear()
  }
}

// Tab input classes — `openTabUriStrings` uses `instanceof` against
// these, so tests must construct tab inputs via the same classes
// imported through `vi.mock('vscode')`.
class FakeTabInputText {
  constructor(readonly uri: FakeUri) {}
}
class FakeTabInputTextDiff {
  constructor(readonly original: FakeUri, readonly modified: FakeUri) {}
}
class FakeTabInputNotebook {
  constructor(readonly uri: FakeUri, readonly notebookType: string = 'jupyter') {}
}
class FakeTabInputNotebookDiff {
  constructor(
    readonly original: FakeUri,
    readonly modified: FakeUri,
    readonly notebookType: string = 'jupyter'
  ) {}
}

interface FakeTab {
  readonly label: string
  readonly input: unknown
  readonly isActive?: boolean
}
interface FakeTabGroup {
  readonly tabs: FakeTab[]
  readonly isActive?: boolean
}

interface FakeTabChangeEvent {
  readonly opened: readonly FakeTab[]
  readonly closed: readonly FakeTab[]
  readonly changed: readonly FakeTab[]
}

class FakeThemeIcon {
  constructor(readonly id: string) {}
}

const TreeItemCollapsibleState = {
  None: 0,
  Collapsed: 1,
  Expanded: 2,
} as const

class FakeTreeItem {
  description?: string
  iconPath?: FakeThemeIcon
  tooltip?: string
  command?: unknown
  contextValue?: string
  id?: string
  constructor(
    readonly label: string,
    readonly collapsibleState: number = TreeItemCollapsibleState.None
  ) {}
}

class FakeFileSystemError extends Error {}

interface FakeTextDocument {
  uri: FakeUri
  getText(): string
  fileName?: string
  isDirty?: boolean
  isClosed?: boolean
  version?: number
}

interface FakeWorkspaceFolder {
  uri: FakeUri
  name: string
  index: number
}

interface FakeConfigSlice {
  get<T>(section: string, defaultValue: T): T
}

// Module-scoped mutable state. Reset between tests with `resetVscodeMock`.
interface VscodeMockState {
  textDocuments: FakeTextDocument[]
  tabGroups: FakeTabGroup[]
  workspaceFolders: FakeWorkspaceFolder[]
  configSlices: Map<string, Record<string, unknown>>
  fsReader: ((uri: FakeUri) => Uint8Array | Promise<Uint8Array>) | undefined

  openTextDocEmitter: FakeEventEmitter<FakeTextDocument>
  closeTextDocEmitter: FakeEventEmitter<FakeTextDocument>
  changeTextDocEmitter: FakeEventEmitter<{ document: FakeTextDocument }>
  saveTextDocEmitter: FakeEventEmitter<FakeTextDocument>
  changeTabsEmitter: FakeEventEmitter<FakeTabChangeEvent>
  changeDiagnosticsEmitter: FakeEventEmitter<{ uris: readonly FakeUri[] }>
  changeConfigEmitter: FakeEventEmitter<{ affectsConfiguration: (section: string) => boolean }>
  createFilesEmitter: FakeEventEmitter<unknown>
  deleteFilesEmitter: FakeEventEmitter<unknown>
  changeFoldersEmitter: FakeEventEmitter<unknown>
  diagnosticCollections: FakeDiagnosticCollection[]
  lastTreeViewOptions: unknown
}

export const vscodeMockState: VscodeMockState = {
  textDocuments: [],
  tabGroups: [],
  workspaceFolders: [],
  configSlices: new Map(),
  fsReader: undefined,
  openTextDocEmitter: new FakeEventEmitter(),
  closeTextDocEmitter: new FakeEventEmitter(),
  changeTextDocEmitter: new FakeEventEmitter(),
  saveTextDocEmitter: new FakeEventEmitter(),
  changeTabsEmitter: new FakeEventEmitter(),
  changeDiagnosticsEmitter: new FakeEventEmitter(),
  changeConfigEmitter: new FakeEventEmitter(),
  createFilesEmitter: new FakeEventEmitter(),
  deleteFilesEmitter: new FakeEventEmitter(),
  changeFoldersEmitter: new FakeEventEmitter(),
  diagnosticCollections: [],
  lastTreeViewOptions: undefined,
}

// Reset clears values + listener subscriptions in place. Emitter
// *instances* are preserved across resets so the `vscodeMockModule`
// getters and any registered handler from a previous test setup still
// point at the same objects — but `.dispose()` drops the listeners,
// so each test starts with no live subscribers.
export function resetVscodeMock(): void {
  vscodeMockState.textDocuments.length = 0
  vscodeMockState.tabGroups.length = 0
  vscodeMockState.workspaceFolders.length = 0
  vscodeMockState.configSlices.clear()
  vscodeMockState.fsReader = undefined
  for (const c of vscodeMockState.diagnosticCollections) c.dispose()
  vscodeMockState.diagnosticCollections.length = 0
  vscodeMockState.openTextDocEmitter.dispose()
  vscodeMockState.closeTextDocEmitter.dispose()
  vscodeMockState.changeTextDocEmitter.dispose()
  vscodeMockState.saveTextDocEmitter.dispose()
  vscodeMockState.changeTabsEmitter.dispose()
  vscodeMockState.changeDiagnosticsEmitter.dispose()
  vscodeMockState.changeConfigEmitter.dispose()
  vscodeMockState.createFilesEmitter.dispose()
  vscodeMockState.deleteFilesEmitter.dispose()
  vscodeMockState.changeFoldersEmitter.dispose()
  vscodeMockState.lastTreeViewOptions = undefined
}

// Build the object that `vi.mock('vscode', () => vscodeMockModule)` returns.
// Note: properties are getters where the underlying state can be replaced
// by `resetVscodeMock`, so tests always see the current emitters.
export const vscodeMockModule = {
  Uri: FakeUri,
  Range: FakeRange,
  Diagnostic: FakeDiagnostic,
  DiagnosticSeverity,
  ThemeIcon: FakeThemeIcon,
  TreeItem: FakeTreeItem,
  TreeItemCollapsibleState,
  TabInputText: FakeTabInputText,
  TabInputTextDiff: FakeTabInputTextDiff,
  TabInputNotebook: FakeTabInputNotebook,
  TabInputNotebookDiff: FakeTabInputNotebookDiff,
  EventEmitter: FakeEventEmitter,
  FileSystemError: FakeFileSystemError,

  workspace: {
    get textDocuments() {
      return vscodeMockState.textDocuments
    },
    get workspaceFolders() {
      return vscodeMockState.workspaceFolders.length > 0
        ? vscodeMockState.workspaceFolders
        : undefined
    },
    onDidOpenTextDocument: ((listener: Listener<FakeTextDocument>) =>
      vscodeMockState.openTextDocEmitter.event(listener)),
    onDidCloseTextDocument: ((listener: Listener<FakeTextDocument>) =>
      vscodeMockState.closeTextDocEmitter.event(listener)),
    onDidChangeTextDocument: ((listener: Listener<{ document: FakeTextDocument }>) =>
      vscodeMockState.changeTextDocEmitter.event(listener)),
    onDidSaveTextDocument: ((listener: Listener<FakeTextDocument>) =>
      vscodeMockState.saveTextDocEmitter.event(listener)),
    onDidChangeConfiguration: ((
      listener: Listener<{ affectsConfiguration: (section: string) => boolean }>
    ) => vscodeMockState.changeConfigEmitter.event(listener)),
    onDidCreateFiles: ((listener: Listener<unknown>) =>
      vscodeMockState.createFilesEmitter.event(listener)),
    onDidDeleteFiles: ((listener: Listener<unknown>) =>
      vscodeMockState.deleteFilesEmitter.event(listener)),
    onDidChangeWorkspaceFolders: ((listener: Listener<unknown>) =>
      vscodeMockState.changeFoldersEmitter.event(listener)),
    getConfiguration: (section: string, _resource?: FakeUri): FakeConfigSlice => {
      const slice = vscodeMockState.configSlices.get(section) ?? {}
      return {
        get<T>(key: string, defaultValue: T): T {
          return (key in slice ? (slice[key] as T) : defaultValue)
        },
      }
    },
    getWorkspaceFolder: (uri: FakeUri): FakeWorkspaceFolder | undefined => {
      for (const folder of vscodeMockState.workspaceFolders) {
        if (uri.fsPath.startsWith(folder.uri.fsPath)) return folder
      }
      return undefined
    },
    fs: {
      readFile: async (uri: FakeUri): Promise<Uint8Array> => {
        if (!vscodeMockState.fsReader) {
          throw new FakeFileSystemError(`No fs reader registered for ${uri.toString()}`)
        }
        return vscodeMockState.fsReader(uri)
      },
    },
  },

  window: {
    tabGroups: {
      get all(): FakeTabGroup[] {
        return vscodeMockState.tabGroups
      },
      onDidChangeTabs: ((listener: Listener<FakeTabChangeEvent>) =>
        vscodeMockState.changeTabsEmitter.event(listener)),
    },
    createTreeView: (_viewId: string, options: unknown) => {
      vscodeMockState.lastTreeViewOptions = options
      return {
        dispose: () => undefined,
        visible: true,
        onDidChangeSelection: new FakeEventEmitter<unknown>().event,
        onDidChangeVisibility: new FakeEventEmitter<unknown>().event,
        onDidCollapseElement: new FakeEventEmitter<unknown>().event,
        onDidExpandElement: new FakeEventEmitter<unknown>().event,
      }
    },
  },

  languages: {
    createDiagnosticCollection: (name: string): FakeDiagnosticCollection => {
      const c = new FakeDiagnosticCollection(name)
      vscodeMockState.diagnosticCollections.push(c)
      return c
    },
    onDidChangeDiagnostics: ((listener: Listener<{ uris: readonly FakeUri[] }>) =>
      vscodeMockState.changeDiagnosticsEmitter.event(listener)),
  },
}

// Test-side helpers ---------------------------------------------------------

export function makeDoc(uri: FakeUri, text: string): FakeTextDocument {
  return {
    uri,
    getText: () => text,
    fileName: uri.fsPath,
    isDirty: false,
    isClosed: false,
    version: 1,
  }
}

export function addOpenTab(input: unknown, opts: { active?: boolean } = {}): void {
  const tab: FakeTab = { label: 'tab', input, isActive: opts.active ?? false }
  if (vscodeMockState.tabGroups.length === 0) {
    vscodeMockState.tabGroups.push({ tabs: [tab], isActive: true })
  } else {
    ;(vscodeMockState.tabGroups[0].tabs as FakeTab[]).push(tab)
  }
}

export function clearTabs(): void {
  vscodeMockState.tabGroups = []
}

export function fireTabsChanged(event: Partial<FakeTabChangeEvent>): void {
  vscodeMockState.changeTabsEmitter.fire({
    opened: event.opened ?? [],
    closed: event.closed ?? [],
    changed: event.changed ?? [],
  })
}

export function createFakeContext(): {
  subscriptions: Array<{ dispose: () => void }>
} {
  return { subscriptions: [] }
}

export type { FakeTab, FakeTabChangeEvent, FakeTextDocument, FakeWorkspaceFolder }
export {
  FakeDiagnostic,
  FakeDiagnosticCollection,
  FakeEventEmitter,
  FakeRange,
  FakeTabInputNotebook,
  FakeTabInputNotebookDiff,
  FakeTabInputText,
  FakeTabInputTextDiff,
  FakeUri,
}
