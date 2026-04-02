/**
 * Package diff viewer — shows exactly what changed in a dependency
 * update, with a git-diff-style output. Compares:
 *   - Install scripts (postinstall, preinstall, etc.)
 *   - Dependency list changes
 *   - File additions/removals
 *   - Binary/native module changes
 */

import fs from 'fs'
import path from 'path'
import os from 'os'

const CACHE_DIR = path.join(os.homedir(), '.safenpm', 'pkg-snapshots')

export interface PackageDiff {
  name: string
  previousVersion: string | null
  currentVersion: string
  isNew: boolean
  scriptDiff: ScriptDiff | null
  depsDiff: DepsDiff | null
  fileDiff: FileDiff | null
  summary: string
}

export interface ScriptDiff {
  hook: string
  previous: string | null
  current: string | null
  added: boolean
  removed: boolean
  changed: boolean
  diffLines: DiffLine[]
}

export interface DepsDiff {
  added: string[]
  removed: string[]
  changed: { name: string; from: string; to: string }[]
}

export interface FileDiff {
  added: string[]
  removed: string[]
  totalFilesPrev: number
  totalFilesCurr: number
}

export interface DiffLine {
  type: 'add' | 'remove' | 'context'
  content: string
}

/**
 * Take a snapshot of a package for future diffing.
 */
export function snapshotPackage(pkgDir: string, name: string, version: string): void {
  try {
    if (!fs.existsSync(CACHE_DIR)) {
      fs.mkdirSync(CACHE_DIR, { recursive: true })
    }

    const pkgJsonPath = path.join(pkgDir, 'package.json')
    if (!fs.existsSync(pkgJsonPath)) return

    const pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'))
    const scripts = pkgJson.scripts || {}
    const deps = pkgJson.dependencies || {}
    const files = listFiles(pkgDir, 3) // max depth 3

    const snapshot = {
      name,
      version,
      scripts,
      dependencies: deps,
      files,
      timestamp: Date.now(),
    }

    const file = path.join(CACHE_DIR, safeName(name) + '.json')
    fs.writeFileSync(file, JSON.stringify(snapshot), 'utf8')
  } catch { /* best effort */ }
}

/**
 * Load a previous snapshot of a package.
 */
function loadSnapshot(name: string): any | null {
  try {
    const file = path.join(CACHE_DIR, safeName(name) + '.json')
    if (!fs.existsSync(file)) return null
    return JSON.parse(fs.readFileSync(file, 'utf8'))
  } catch {
    return null
  }
}

/**
 * Diff a package against its previously cached snapshot.
 */
export function diffPackage(pkgDir: string, name: string, version: string): PackageDiff {
  const prev = loadSnapshot(name)
  const pkgJsonPath = path.join(pkgDir, 'package.json')

  let currentPkg: any = {}
  try {
    currentPkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'))
  } catch { /* skip */ }

  const currentScripts = currentPkg.scripts || {}
  const currentDeps = currentPkg.dependencies || {}
  const currentFiles = listFiles(pkgDir, 3)

  if (!prev) {
    return {
      name,
      previousVersion: null,
      currentVersion: version,
      isNew: true,
      scriptDiff: null,
      depsDiff: null,
      fileDiff: null,
      summary: `New package: ${name}@${version}`,
    }
  }

  const prevScripts = prev.scripts || {}
  const prevDeps = prev.dependencies || {}
  const prevFiles = prev.files || []

  // ── Script diffs ──
  const scriptDiffs: ScriptDiff[] = []
  const allHooks = new Set([...Object.keys(prevScripts), ...Object.keys(currentScripts)])

  for (const hook of ['preinstall', 'install', 'postinstall', 'prepare']) {
    if (!allHooks.has(hook)) continue

    const prevScript = prevScripts[hook] || null
    const currScript = currentScripts[hook] || null

    if (prevScript === currScript) continue

    scriptDiffs.push({
      hook,
      previous: prevScript,
      current: currScript,
      added: !prevScript && !!currScript,
      removed: !!prevScript && !currScript,
      changed: !!prevScript && !!currScript && prevScript !== currScript,
      diffLines: computeLineDiff(prevScript || '', currScript || ''),
    })
  }

  // ── Dependency diffs ──
  const addedDeps: string[] = []
  const removedDeps: string[] = []
  const changedDeps: { name: string; from: string; to: string }[] = []

  for (const [dep, ver] of Object.entries<string>(currentDeps)) {
    if (!prevDeps[dep]) {
      addedDeps.push(`${dep}@${ver}`)
    } else if (prevDeps[dep] !== ver) {
      changedDeps.push({ name: dep, from: prevDeps[dep], to: ver })
    }
  }
  for (const dep of Object.keys(prevDeps)) {
    if (!currentDeps[dep]) {
      removedDeps.push(`${dep}@${prevDeps[dep]}`)
    }
  }

  const depsDiff = (addedDeps.length || removedDeps.length || changedDeps.length)
    ? { added: addedDeps, removed: removedDeps, changed: changedDeps }
    : null

  // ── File diffs ──
  const prevFileSet = new Set(prevFiles)
  const currFileSet = new Set(currentFiles)
  const addedFiles = currentFiles.filter((f: string) => !prevFileSet.has(f))
  const removedFiles = prevFiles.filter((f: string) => !currFileSet.has(f))

  const fileDiff = (addedFiles.length || removedFiles.length)
    ? { added: addedFiles.slice(0, 20), removed: removedFiles.slice(0, 20), totalFilesPrev: prevFiles.length, totalFilesCurr: currentFiles.length }
    : null

  // ── Summary ──
  const parts: string[] = []
  if (scriptDiffs.length > 0) parts.push(`${scriptDiffs.length} script change${scriptDiffs.length > 1 ? 's' : ''}`)
  if (addedDeps.length > 0) parts.push(`${addedDeps.length} new dep${addedDeps.length > 1 ? 's' : ''}`)
  if (removedDeps.length > 0) parts.push(`${removedDeps.length} removed dep${removedDeps.length > 1 ? 's' : ''}`)
  if (addedFiles.length > 0) parts.push(`${addedFiles.length} new file${addedFiles.length > 1 ? 's' : ''}`)

  return {
    name,
    previousVersion: prev.version,
    currentVersion: version,
    isNew: false,
    scriptDiff: scriptDiffs.length > 0 ? scriptDiffs[0] : null,
    depsDiff,
    fileDiff,
    summary: parts.length > 0
      ? `${prev.version} → ${version}: ${parts.join(', ')}`
      : `${prev.version} → ${version}: no significant changes`,
  }
}

/**
 * Diff all packages in node_modules against their snapshots.
 * Only returns packages that have changes.
 */
export function diffAllPackages(nodeModulesDir: string): PackageDiff[] {
  const diffs: PackageDiff[] = []

  if (!fs.existsSync(nodeModulesDir)) return diffs

  const entries = fs.readdirSync(nodeModulesDir)
  for (const entry of entries) {
    if (entry.startsWith('.')) continue

    if (entry.startsWith('@')) {
      try {
        const scopeDir = path.join(nodeModulesDir, entry)
        for (const scopeEntry of fs.readdirSync(scopeDir)) {
          const pkgDir = path.join(scopeDir, scopeEntry)
          const name = `${entry}/${scopeEntry}`
          const version = readVersion(pkgDir)
          if (version) {
            const diff = diffPackage(pkgDir, name, version)
            if (!diff.isNew && (diff.scriptDiff || diff.depsDiff || diff.fileDiff)) {
              diffs.push(diff)
            }
          }
        }
      } catch { /* skip */ }
    } else {
      const pkgDir = path.join(nodeModulesDir, entry)
      const version = readVersion(pkgDir)
      if (version) {
        const diff = diffPackage(pkgDir, entry, version)
        if (!diff.isNew && (diff.scriptDiff || diff.depsDiff || diff.fileDiff)) {
          diffs.push(diff)
        }
      }
    }
  }

  return diffs
}

/**
 * Snapshot all packages in node_modules for future diffing.
 */
export function snapshotAllPackages(nodeModulesDir: string): number {
  let count = 0
  if (!fs.existsSync(nodeModulesDir)) return count

  const entries = fs.readdirSync(nodeModulesDir)
  for (const entry of entries) {
    if (entry.startsWith('.')) continue
    if (entry.startsWith('@')) {
      try {
        for (const se of fs.readdirSync(path.join(nodeModulesDir, entry))) {
          const pkgDir = path.join(nodeModulesDir, entry, se)
          const ver = readVersion(pkgDir)
          if (ver) { snapshotPackage(pkgDir, `${entry}/${se}`, ver); count++ }
        }
      } catch { /* skip */ }
    } else {
      const pkgDir = path.join(nodeModulesDir, entry)
      const ver = readVersion(pkgDir)
      if (ver) { snapshotPackage(pkgDir, entry, ver); count++ }
    }
  }
  return count
}

// ── Helpers ──

function readVersion(pkgDir: string): string | null {
  try {
    const p = path.join(pkgDir, 'package.json')
    if (!fs.existsSync(p)) return null
    return JSON.parse(fs.readFileSync(p, 'utf8')).version || null
  } catch { return null }
}

/**
 * Simple line-level diff between two strings.
 */
function computeLineDiff(prev: string, curr: string): DiffLine[] {
  const prevLines = prev.split('\n').filter(Boolean)
  const currLines = curr.split('\n').filter(Boolean)
  const lines: DiffLine[] = []

  const prevSet = new Set(prevLines)
  const currSet = new Set(currLines)

  for (const line of prevLines) {
    if (!currSet.has(line)) {
      lines.push({ type: 'remove', content: line })
    } else {
      lines.push({ type: 'context', content: line })
    }
  }

  for (const line of currLines) {
    if (!prevSet.has(line)) {
      lines.push({ type: 'add', content: line })
    }
  }

  return lines
}

function listFiles(dir: string, maxDepth: number, currentDepth: number = 0): string[] {
  if (currentDepth >= maxDepth) return []
  const files: string[] = []

  try {
    const entries = fs.readdirSync(dir)
    for (const entry of entries) {
      if (entry === 'node_modules' || entry.startsWith('.')) continue
      const fullPath = path.join(dir, entry)
      const stat = fs.statSync(fullPath)
      const relativeName = entry

      if (stat.isFile()) {
        files.push(relativeName)
      } else if (stat.isDirectory()) {
        const subFiles = listFiles(fullPath, maxDepth, currentDepth + 1)
        files.push(...subFiles.map(f => `${relativeName}/${f}`))
      }
    }
  } catch { /* skip */ }

  return files
}

function safeName(name: string): string {
  return name.replace(/[^a-zA-Z0-9@._-]/g, '_')
}

/**
 * Format a diff for terminal output.
 */
export function formatDiffForTerminal(diff: PackageDiff): string {
  const lines: string[] = []

  lines.push(`\x1b[1m${diff.name}\x1b[0m ${diff.previousVersion} → ${diff.currentVersion}`)
  lines.push('')

  if (diff.scriptDiff) {
    const sd = diff.scriptDiff
    if (sd.added) {
      lines.push(`  \x1b[31m+ script added:\x1b[0m [${sd.hook}]`)
      lines.push(`  \x1b[32m+ ${sd.current}\x1b[0m`)
    } else if (sd.removed) {
      lines.push(`  \x1b[32m- script removed:\x1b[0m [${sd.hook}]`)
      lines.push(`  \x1b[31m- ${sd.previous}\x1b[0m`)
    } else if (sd.changed) {
      lines.push(`  \x1b[33m~ script changed:\x1b[0m [${sd.hook}]`)
      for (const dl of sd.diffLines) {
        if (dl.type === 'remove') lines.push(`  \x1b[31m- ${dl.content}\x1b[0m`)
        else if (dl.type === 'add') lines.push(`  \x1b[32m+ ${dl.content}\x1b[0m`)
        else lines.push(`  \x1b[2m  ${dl.content}\x1b[0m`)
      }
    }
    lines.push('')
  }

  if (diff.depsDiff) {
    const dd = diff.depsDiff
    if (dd.added.length > 0) {
      lines.push(`  \x1b[32m+ dependencies added:\x1b[0m ${dd.added.join(', ')}`)
    }
    if (dd.removed.length > 0) {
      lines.push(`  \x1b[31m- dependencies removed:\x1b[0m ${dd.removed.join(', ')}`)
    }
    for (const c of dd.changed) {
      lines.push(`  \x1b[33m~ ${c.name}:\x1b[0m ${c.from} → ${c.to}`)
    }
    lines.push('')
  }

  if (diff.fileDiff) {
    const fd = diff.fileDiff
    if (fd.added.length > 0) {
      lines.push(`  \x1b[32m+ ${fd.added.length} file${fd.added.length > 1 ? 's' : ''} added\x1b[0m`)
      for (const f of fd.added.slice(0, 5)) lines.push(`    \x1b[32m+ ${f}\x1b[0m`)
      if (fd.added.length > 5) lines.push(`    \x1b[2m...and ${fd.added.length - 5} more\x1b[0m`)
    }
    if (fd.removed.length > 0) {
      lines.push(`  \x1b[31m- ${fd.removed.length} file${fd.removed.length > 1 ? 's' : ''} removed\x1b[0m`)
      for (const f of fd.removed.slice(0, 5)) lines.push(`    \x1b[31m- ${f}\x1b[0m`)
    }
  }

  return lines.join('\n')
}
