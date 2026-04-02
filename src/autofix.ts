/**
 * Auto-fix — when a typosquat or malicious package is detected,
 * automatically replace it with the legitimate version.
 *
 * Handles:
 *   - Typosquat replacement: remove suspect, install target
 *   - Malicious package removal: uninstall blocked packages
 *   - package.json cleanup: update deps/devDeps entries
 */

import { spawnSync } from 'child_process'
import fs from 'fs'
import path from 'path'
import { TyposquatResult } from './typosquat'
import { SandboxResult } from './types'

export interface FixAction {
  type: 'replace-typosquat' | 'remove-malicious'
  package: string
  version: string
  replacement: string | null   // null for remove-only
  applied: boolean
  detail: string
}

/**
 * Generate fix actions from scan/install results.
 * Does NOT apply them — call applyFixes() to execute.
 */
export function generateFixes(
  typosquats: TyposquatResult[],
  blockedResults: SandboxResult[],
): FixAction[] {
  const fixes: FixAction[] = []

  // Typosquat replacements
  for (const t of typosquats) {
    if (t.confidence === 'high' || t.confidence === 'medium') {
      fixes.push({
        type: 'replace-typosquat',
        package: t.suspect,
        version: 'latest',
        replacement: t.target,
        applied: false,
        detail: `Replace ${t.suspect} with ${t.target} (${t.technique}, ${t.confidence} confidence)`,
      })
    }
  }

  // Remove blocked malicious packages
  for (const r of blockedResults) {
    if (r.blocked && (r.reason === 'network' || r.reason === 'filesystem')) {
      fixes.push({
        type: 'remove-malicious',
        package: r.pkg.name,
        version: r.pkg.version,
        replacement: null,
        applied: false,
        detail: `Remove ${r.pkg.name}@${r.pkg.version} (blocked: ${r.reason})`,
      })
    }
  }

  return fixes
}

/**
 * Apply a single fix action.
 * Returns updated action with applied=true/false.
 */
export function applyFix(fix: FixAction, projectDir: string): FixAction {
  const pkgJsonPath = path.join(projectDir, 'package.json')

  switch (fix.type) {
    case 'replace-typosquat': {
      // Step 1: Remove the typosquat from node_modules and package.json
      const removeResult = spawnSync('npm', ['uninstall', fix.package], {
        cwd: projectDir,
        encoding: 'utf8',
        stdio: 'pipe',
        timeout: 30000,
      })

      if (removeResult.status !== 0) {
        // Try manual removal if npm uninstall fails
        manualRemove(fix.package, projectDir, pkgJsonPath)
      }

      // Step 2: Install the legitimate package
      if (fix.replacement) {
        const installResult = spawnSync('npm', ['install', '--ignore-scripts', fix.replacement], {
          cwd: projectDir,
          encoding: 'utf8',
          stdio: 'pipe',
          timeout: 60000,
        })
        fix.applied = installResult.status === 0
      } else {
        fix.applied = true
      }
      break
    }

    case 'remove-malicious': {
      const result = spawnSync('npm', ['uninstall', fix.package], {
        cwd: projectDir,
        encoding: 'utf8',
        stdio: 'pipe',
        timeout: 30000,
      })

      if (result.status !== 0) {
        manualRemove(fix.package, projectDir, pkgJsonPath)
      }
      fix.applied = true
      break
    }
  }

  return fix
}

/**
 * Apply all fixes in sequence.
 */
export function applyAllFixes(fixes: FixAction[], projectDir: string): FixAction[] {
  return fixes.map(f => applyFix(f, projectDir))
}

/**
 * Manual removal: delete from node_modules and strip from package.json.
 * Used when npm uninstall fails (e.g., corrupted state).
 */
function manualRemove(name: string, projectDir: string, pkgJsonPath: string): void {
  // Remove from node_modules
  const nmPath = name.startsWith('@')
    ? path.join(projectDir, 'node_modules', name)
    : path.join(projectDir, 'node_modules', name)

  try {
    if (fs.existsSync(nmPath)) {
      fs.rmSync(nmPath, { recursive: true, force: true })
    }
  } catch { /* best effort */ }

  // Strip from package.json
  try {
    if (fs.existsSync(pkgJsonPath)) {
      const pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'))
      let changed = false

      for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
        if (pkgJson[field] && pkgJson[field][name]) {
          delete pkgJson[field][name]
          changed = true
        }
      }

      if (changed) {
        fs.writeFileSync(pkgJsonPath, JSON.stringify(pkgJson, null, 2) + '\n', 'utf8')
      }
    }
  } catch { /* best effort */ }
}

/**
 * Preview what would be fixed without applying anything.
 */
export function previewFixes(fixes: FixAction[]): string[] {
  return fixes.map(f => {
    if (f.type === 'replace-typosquat') {
      return `replace ${f.package} → ${f.replacement}`
    }
    return `remove ${f.package}@${f.version}`
  })
}
