/**
 * Cross-cutting CLI helpers. Kept tiny — anything that grows beyond
 * three or four lines should move into its command module instead.
 */
import fs from 'fs'
import path from 'path'
import { getReporter } from '../report'

/**
 * Several commands (scan, fix, diff) need a populated node_modules.
 * This centralizes the "missing → error in human or JSON mode" check
 * and returns the absolute path so callers can pass it on.
 *
 * Returns `{ exitCode }` when missing; callers should bail with it.
 */
export function requireNodeModules(
  jsonFlag: boolean,
): { nodeModulesPath: string } | { exitCode: number } {
  const nodeModulesPath = path.join(process.cwd(), 'node_modules')
  if (fs.existsSync(nodeModulesPath)) return { nodeModulesPath }

  if (jsonFlag) {
    console.log(JSON.stringify({ error: 'no node_modules found' }))
  } else {
    getReporter({ json: false }).error('no node_modules found — run npm install first')
  }
  return { exitCode: 1 }
}
