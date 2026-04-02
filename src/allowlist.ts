import fs from 'fs'
import path from 'path'
import os from 'os'

const RC_FILENAME = '.safenpmrc'

/**
 * Load the allowlist from all sources:
 *  1. --allow flags passed on the CLI
 *  2. .safenpmrc in the project root (cwd)
 *  3. ~/.safenpmrc in the home directory
 *
 * File format: one package name per line, # comments, blank lines ignored
 *
 * Example .safenpmrc:
 *   # native addons we trust
 *   bcrypt
 *   sharp
 *   @mapbox/node-pre-gyp
 */
export function loadAllowlist(cliAllows: string[]): Set<string> {
  const set = new Set<string>()

  // CLI flags first
  for (const name of cliAllows) {
    set.add(name.trim())
  }

  // Project-level rc
  const projectRc = path.join(process.cwd(), RC_FILENAME)
  mergeFromFile(projectRc, set)

  // User-level rc
  const userRc = path.join(os.homedir(), RC_FILENAME)
  mergeFromFile(userRc, set)

  return set
}

function mergeFromFile(filePath: string, set: Set<string>): void {
  try {
    if (!fs.existsSync(filePath)) return
    const content = fs.readFileSync(filePath, 'utf8')
    for (const raw of content.split('\n')) {
      const line = raw.trim()
      if (!line || line.startsWith('#')) continue
      set.add(line)
    }
  } catch {
    // silently ignore unreadable rc files
  }
}

export function isAllowed(packageName: string, allowlist: Set<string>): boolean {
  if (allowlist.has(packageName)) return true

  // support scope-level wildcards: --allow @mycompany/*
  for (const entry of allowlist) {
    if (entry.endsWith('/*')) {
      const scope = entry.slice(0, -2)
      if (packageName.startsWith(scope + '/')) return true
    }
  }

  return false
}
