import fs from 'fs'
import path from 'path'
import { PackageScript } from '../types'

const HOOKS = ['preinstall', 'install', 'postinstall', 'prepare']

/**
 * Cap on how deep we recurse into `node_modules/<a>/node_modules/<b>/...`
 * when looking for install scripts. With modern flat hoisting most
 * trees terminate at depth 1; nested copies happen on version
 * conflicts. 8 is the maximum nesting depth npm allows for hoisting
 * conflict resolution in practice, so this matches reality without
 * blowing the stack on a pathological tree.
 */
const MAX_NESTED_DEPTH = 8

export function findInstallScripts(nodeModulesPath: string): PackageScript[] {
  const results: PackageScript[] = []
  walk(nodeModulesPath, results, 0)
  return results
}

function walk(nodeModulesPath: string, out: PackageScript[], depth: number): void {
  if (depth > MAX_NESTED_DEPTH) return
  if (!fs.existsSync(nodeModulesPath)) return

  let entries: fs.Dirent[]
  try {
    entries = fs.readdirSync(nodeModulesPath, { withFileTypes: true })
  } catch {
    return
  }

  for (const entry of entries) {
    if (!entry.isDirectory()) continue
    if (entry.name.startsWith('.')) continue

    if (entry.name.startsWith('@')) {
      // scoped package — one level deeper
      const scopePath = path.join(nodeModulesPath, entry.name)
      let scoped: fs.Dirent[]
      try {
        scoped = fs.readdirSync(scopePath, { withFileTypes: true })
      } catch {
        continue
      }
      for (const s of scoped) {
        if (!s.isDirectory()) continue
        const pkgPath = path.join(scopePath, s.name)
        probe(pkgPath, `${entry.name}/${s.name}`, out)
        // recurse into any nested node_modules at this package
        walk(path.join(pkgPath, 'node_modules'), out, depth + 1)
      }
    } else {
      const pkgPath = path.join(nodeModulesPath, entry.name)
      probe(pkgPath, entry.name, out)
      walk(path.join(pkgPath, 'node_modules'), out, depth + 1)
    }
  }
}

function probe(pkgPath: string, fallbackName: string, out: PackageScript[]) {
  const pkgJsonPath = path.join(pkgPath, 'package.json')
  if (!fs.existsSync(pkgJsonPath)) return

  let pkg: Record<string, any>
  try {
    pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'))
  } catch {
    return
  }

  for (const hook of HOOKS) {
    const script = pkg?.scripts?.[hook]
    if (typeof script === 'string' && script.trim()) {
      out.push({
        name: pkg.name ?? fallbackName,
        version: pkg.version ?? 'unknown',
        path: pkgPath,
        script,
        hook,
      })
      break // only take the first matching hook per package
    }
  }
}
