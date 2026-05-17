import { ExtensionContext, OutputChannel, window, workspace } from 'vscode'

/**
 * Debug output channel for Token X-Ray. Gated by the `tokenXray.debug`
 * boolean setting (default false). When the setting is off the logger
 * returned from `getDebugLogger` is a no-op; when on it appends a
 * timestamped line to a single shared `OutputChannel` named
 * "Token X-Ray".
 *
 * The channel is created lazily on the first call to
 * `registerDebugOutputChannel` and registered as a disposable on the
 * extension context so vscode tears it down when the extension is
 * deactivated. Subsequent calls within the same activation reuse the
 * same channel.
 *
 * Pure pass-through wiring — no analyzer logic, no scan triggering.
 */

const CHANNEL_NAME = 'Token X-Ray'

let channel: OutputChannel | undefined

/**
 * Lazily create the shared output channel and register it as a
 * disposable on the extension context. Idempotent within a single
 * activation — subsequent calls return the cached channel.
 */
function getChannel(context: ExtensionContext): OutputChannel {
  if (channel) return channel
  channel = window.createOutputChannel(CHANNEL_NAME)
  context.subscriptions.push(channel)
  return channel
}

/**
 * Returns a closure that, when invoked, checks the current
 * `tokenXray.debug` setting and writes a timestamped line to the
 * "Token X-Ray" output channel when enabled. When the setting is false
 * the closure is a no-op so callers can sprinkle log calls freely
 * without runtime cost in the common case.
 *
 * The configuration is re-read on every invocation so flipping the
 * setting in the user's settings.json takes effect immediately without
 * an extension reload.
 */
export function getDebugLogger(context: ExtensionContext): (msg: string) => void {
  const log = getChannel(context)
  return (msg: string): void => {
    const config = workspace.getConfiguration('tokenXray')
    if (!config.get<boolean>('debug', false)) return
    const stamp = new Date().toISOString()
    log.appendLine(`[${stamp}] ${msg}`)
  }
}

/**
 * Convenience wrapper for the activate() flow. Registers the channel
 * eagerly and returns the logger closure in one call. The channel is
 * cheap to create (vscode reuses the underlying buffer until the user
 * opens the Output view) so creating it up-front avoids races with
 * any provider's first log call.
 */
export function registerDebugOutputChannel(
  context: ExtensionContext
): (msg: string) => void {
  return getDebugLogger(context)
}

/**
 * Test-only hook so unit tests that instantiate a fresh extension
 * context don't carry the module-level channel reference across test
 * cases. Not exported from the package's public surface; only the
 * Vitest setup calls it.
 *
 * @internal
 */
export function __resetDebugOutputChannelForTesting(): void {
  channel = undefined
}
