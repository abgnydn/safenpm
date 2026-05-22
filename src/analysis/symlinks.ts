/**
 * Symlink audit. Walks every installed package directory and flags
 * any symlink whose resolved target escapes the package itself.
 *
 * Concrete attack pattern this catches: a package ships a symlink
 * at `node_modules/<name>/link.txt` pointing at `/etc/passwd` (or
 * `~/.ssh/id_rsa`, or a path inside another dep), then `postinstall`
 * does `cat link.txt`. The sandbox allow-list grants reads to the
 * package dir, but the kernel resolves the symlink during the read,
 * and on some platforms the read succeeds before the deny rule
 * fires. The cheap correct answer is to refuse to even consider a
 * package safe if it contains an escape symlink.
 *
 * We also flag absolute-path symlinks regardless of target — an
 * absolute symlink is non-portable and a red flag in a tarball that
 * was supposed to be a pure-source distribution.
 */
import fs from 'fs'
import path from 'path'

export interface SymlinkFinding {
  /** Package name (relative to node_modules). */
  pkg: string
  /** Symlink's path, relative to node_modules. */
  symlink: string
  /** What it resolved to (after one readlink hop). */
  target: string
  reason: 'escapes-package' | 'absolute-target' | 'broken'
}

export interface SymlinkAuditResult {
  /** Total packages walked. */
  packagesScanned: number
  /** Symlinks that escape their owning package. */
  findings: SymlinkFinding[]
}

const MAX_FILES_PER_PACKAGE = 5000
const MAX_DEPTH = 12

/**
 * Walk a node_modules tree, returning every problematic symlink.
 * Best-effort — unreadable directories are skipped without throwing.
 */
export function auditSymlinks(nodeModulesPath: string): SymlinkAuditResult {
  const findings: SymlinkFinding[] = []
  let packagesScanned = 0

  if (!fs.existsSync(nodeModulesPath)) {
    return { packagesScanned: 0, findings: [] }
  }

  let topLevel: fs.Dirent[]
  try {
    topLevel = fs.readdirSync(nodeModulesPath, { withFileTypes: true })
  } catch {
    return { packagesScanned: 0, findings: [] }
  }

  for (const entry of topLevel) {
    if (entry.name.startsWith('.')) continue
    if (!entry.isDirectory()) continue

    if (entry.name.startsWith('@')) {
      let scoped: fs.Dirent[]
      try {
        scoped = fs.readdirSync(path.join(nodeModulesPath, entry.name), { withFileTypes: true })
      } catch { continue }
      for (const s of scoped) {
        if (!s.isDirectory()) continue
        const pkgName = `${entry.name}/${s.name}`
        const pkgRoot = path.join(nodeModulesPath, entry.name, s.name)
        packagesScanned++
        walkPkg(pkgRoot, pkgRoot, pkgName, findings, 0, { count: 0 })
      }
    } else {
      const pkgRoot = path.join(nodeModulesPath, entry.name)
      packagesScanned++
      walkPkg(pkgRoot, pkgRoot, entry.name, findings, 0, { count: 0 })
    }
  }

  return { packagesScanned, findings }
}

function walkPkg(
  pkgRoot: string,
  current: string,
  pkgName: string,
  findings: SymlinkFinding[],
  depth: number,
  budget: { count: number },
): void {
  if (depth > MAX_DEPTH) return
  if (budget.count > MAX_FILES_PER_PACKAGE) return

  let entries: fs.Dirent[]
  try {
    entries = fs.readdirSync(current, { withFileTypes: true })
  } catch {
    return
  }

  for (const e of entries) {
    if (budget.count > MAX_FILES_PER_PACKAGE) return
    budget.count++
    const full = path.join(current, e.name)

    if (e.isSymbolicLink()) {
      classifyLink(full, pkgRoot, pkgName, findings)
      continue
    }

    if (e.isDirectory()) {
      // Skip nested node_modules — those are walked separately by the
      // outer loop; otherwise we'd re-scan every transitive dep.
      if (e.name === 'node_modules') continue
      walkPkg(pkgRoot, full, pkgName, findings, depth + 1, budget)
    }
  }
}

function classifyLink(
  linkPath: string,
  pkgRoot: string,
  pkgName: string,
  findings: SymlinkFinding[],
): void {
  let target: string
  try {
    target = fs.readlinkSync(linkPath)
  } catch {
    findings.push({
      pkg: pkgName,
      symlink: path.relative(pkgRoot, linkPath),
      target: '',
      reason: 'broken',
    })
    return
  }

  if (path.isAbsolute(target)) {
    findings.push({
      pkg: pkgName,
      symlink: path.relative(pkgRoot, linkPath),
      target,
      reason: 'absolute-target',
    })
    return
  }

  // Resolve the symlink relative to its own directory, then check
  // whether the resolved path stays inside pkgRoot. Use the resolved
  // string (no fs.realpathSync) so we don't dereference further
  // symlinks — we only care about the first hop.
  const resolved = path.resolve(path.dirname(linkPath), target)
  const rel = path.relative(pkgRoot, resolved)
  const escapes = rel.startsWith('..') || path.isAbsolute(rel)
  if (escapes) {
    findings.push({
      pkg: pkgName,
      symlink: path.relative(pkgRoot, linkPath),
      target,
      reason: 'escapes-package',
    })
  }
}

/**
 * High-severity-only filter — what the install pipeline should
 * actually surface vs. an audit log.
 */
export function dangerousSymlinks(result: SymlinkAuditResult): SymlinkFinding[] {
  return result.findings.filter((f) => f.reason !== 'broken')
}
