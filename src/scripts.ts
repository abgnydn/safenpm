import fs from 'fs'
import path from 'path'
import { PackageScript } from './types'

const HOOKS = ['preinstall', 'install', 'postinstall', 'prepare']

export function findInstallScripts(nodeModulesPath: string): PackageScript[] {
  const results: PackageScript[] = []

  if (!fs.existsSync(nodeModulesPath)) return results

  const entries = fs.readdirSync(nodeModulesPath, { withFileTypes: true })

  for (const entry of entries) {
    if (!entry.isDirectory()) continue
    if (entry.name.startsWith('.')) continue

    if (entry.name.startsWith('@')) {
      // scoped package — go one level deeper
      const scopePath = path.join(nodeModulesPath, entry.name)
      const scoped = fs.readdirSync(scopePath, { withFileTypes: true })
      for (const s of scoped) {
        if (!s.isDirectory()) continue
        probe(path.join(scopePath, s.name), `${entry.name}/${s.name}`, results)
      }
    } else {
      probe(path.join(nodeModulesPath, entry.name), entry.name, results)
    }
  }

  return results
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
