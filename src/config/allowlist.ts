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
 * File format:
 *   - one package name per line
 *   - `# comments` and blank lines are ignored
 *   - lines starting with `!` are typosquat-ignore entries (see
 *     `loadTyposquatIgnores`), NOT allowlist entries
 *
 * Example .safenpmrc:
 *   # native addons we trust
 *   bcrypt
 *   sharp
 *   @mapbox/node-pre-gyp
 *
 *   # silence typosquat false-positives on internal packages
 *   !my-internal-react-thing
 *   !@acme/lodash-utils
 */
export function loadAllowlist(cliAllows: string[]): Set<string> {
  const set = new Set<string>()

  // CLI flags first
  for (const name of cliAllows) {
    set.add(name.trim())
  }

  // Project-level rc, then user-level rc.
  mergeFromFile(path.join(process.cwd(), RC_FILENAME), set, /* prefix */ '')
  mergeFromFile(path.join(os.homedir(), RC_FILENAME), set, '')

  return set
}

/**
 * Load typosquat ignore entries — package names that should NOT trip
 * the typosquat detector even if they're close to a popular name.
 * Format: lines in `.safenpmrc` starting with `!` (the `!` is stripped).
 */
export function loadTyposquatIgnores(): Set<string> {
  const set = new Set<string>()
  mergeFromFile(path.join(process.cwd(), RC_FILENAME), set, '!')
  mergeFromFile(path.join(os.homedir(), RC_FILENAME), set, '!')
  return set
}

/**
 * Merge a single rc file into `set`.
 *
 * `prefix === ''` collects lines that DON'T start with `!` (allowlist
 * semantics). `prefix === '!'` collects lines that start with `!`,
 * stripping the prefix.
 */
function mergeFromFile(filePath: string, set: Set<string>, prefix: '' | '!'): void {
  try {
    if (!fs.existsSync(filePath)) return
    const content = fs.readFileSync(filePath, 'utf8')
    for (const raw of content.split('\n')) {
      const line = raw.trim()
      if (!line || line.startsWith('#')) continue
      if (prefix === '') {
        if (line.startsWith('!')) continue
        set.add(line)
      } else {
        if (!line.startsWith('!')) continue
        const name = line.slice(1).trim()
        if (name) set.add(name)
      }
    }
  } catch {
    // silently ignore unreadable rc files
  }
}

export function isAllowed(packageName: string, allowlist: ReadonlySet<string>): boolean {
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
