#!/usr/bin/env node
// Fail when package.json's version and the top entry of CHANGELOG.md
// are out of sync. Caught us once when 1.1.0 shipped under a CHANGELOG
// heading of [2.0.0]. Wired into CI before `vsce publish` and into
// `vscode:prepublish` so a local `npm run deploy` catches it too.
//
// Pure Node, no deps — runs in the same install footprint as `clean.js`.

const fs = require('node:fs')
const path = require('node:path')

const repoRoot = path.resolve(__dirname, '..', '..')
const pkgPath = path.join(repoRoot, 'package.json')
const changelogPath = path.join(repoRoot, 'CHANGELOG.md')

function fail(message) {
  process.stderr.write(`check-version: ${message}\n`)
  process.exit(1)
}

const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'))
const pkgVersion = pkg.version
if (!pkgVersion) fail('package.json is missing a "version" field')

const changelog = fs.readFileSync(changelogPath, 'utf8')
// First `## [x.y.z]` heading wins. Trailing "— date" or "- date" is
// allowed; the date is informational, not asserted.
const match = changelog.match(/^##\s+\[([^\]]+)\]/m)
if (!match) {
  fail('CHANGELOG.md has no `## [x.y.z]` heading')
}

const changelogVersion = match[1]
if (changelogVersion !== pkgVersion) {
  fail(
    `version mismatch — package.json is "${pkgVersion}" but top CHANGELOG ` +
    `heading is "[${changelogVersion}]". Update one or the other.`
  )
}

process.stdout.write(
  `check-version: package.json and CHANGELOG.md both at ${pkgVersion}\n`
)
