#!/usr/bin/env node
/**
 * Runtime enforcement hook. Loaded via `node --require` (see
 * `safenpm run --enforce-runtime`).
 *
 * Intercepts `require()` for every CJS module, checks whether the
 * calling package is allowed to access the requested builtin
 * according to the on-disk policy file, and throws `SafenpmDenied`
 * if not. The hook itself is loaded once at startup — after that
 * every require() pays one extra map lookup per call.
 *
 * Limitations:
 *   - CJS only. ESM `import` resolution goes through a different
 *     mechanism (`--experimental-loader`); ESM enforcement is a
 *     separate hook deferred to 0.4.
 *   - Cannot prevent a package from reaching `process.binding(…)`
 *     directly — `process.binding` is itself a builtin-equivalent
 *     and the analyzer flags it at install time, but a determined
 *     attacker can bypass the loader. Defence-in-depth, not absolute.
 *   - Native addons that `dlopen` further code at runtime escape
 *     this hook entirely. The native-addon scanner (analysis/native.ts)
 *     surfaces those at install time.
 */
import Module from 'module'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { classifyRequireId, packageOfFile } from './utils'
import { isAllowed, loadPolicy, normaliseBuiltin, type Policy } from './policy'

/**
 * Loud, named error so test fixtures can `catch` on the class name
 * and so the stack trace clearly attributes the block to safenpm.
 */
export class SafenpmDenied extends Error {
  override name = 'SafenpmDenied'
  constructor(public callerPkg: string, public id: string) {
    super(`safenpm: package "${callerPkg}" is not allowed to require("${id}") under the current runtime policy`)
  }
}

const policy: Policy = loadPolicy()
const denyLog: Array<{ pkg: string; id: string; timestamp: string }> = []

const original = Module.prototype.require
Module.prototype.require = function patchedRequire(this: NodeJS.Module, id: string) {
  const kind = classifyRequireId(id)
  if (kind === 'builtin') {
    const caller = packageOfFile(this.filename)
    if (!isAllowed(policy, caller, id)) {
      denyLog.push({
        pkg: caller, id: normaliseBuiltin(id),
        timestamp: new Date().toISOString(),
      })
      throw new SafenpmDenied(caller, id)
    }
  }
  return original.call(this, id)
} as typeof Module.prototype.require

function flushDenies(): void {
  if (denyLog.length === 0) return
  try {
    const dir = path.join(os.homedir(), '.safenpm', 'enforce-denies')
    fs.mkdirSync(dir, { recursive: true })
    const file = path.join(
      dir,
      `${new Date().toISOString().replace(/[:.]/g, '-')}-${process.pid}.json`,
    )
    fs.writeFileSync(file, JSON.stringify({
      timestamp: new Date().toISOString(),
      cwd: process.cwd(),
      denies: denyLog,
    }, null, 2), 'utf8')
  } catch { /* best effort */ }
}

process.on('exit', flushDenies)
process.on('SIGINT', () => { flushDenies(); process.exit(130) })
process.on('SIGTERM', () => { flushDenies(); process.exit(143) })
