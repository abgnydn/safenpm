#!/usr/bin/env node
/**
 * Runtime require()-tracer. Loaded via `node --require` (see
 * `safenpm trace` in cli/commands/trace.ts). Records, for each
 * package that called `require()`, the set of module IDs it touched.
 * Writes the result to ~/.safenpm/pkg-traces/<run-id>.json on process
 * exit.
 *
 * Limitations (documented openly in docs/runtime-isolation.md):
 *   - CommonJS only. ESM `import` goes through a different mechanism
 *     and is NOT captured here.
 *   - Loaded into the same process as the user's code. A malicious
 *     module can in principle undo this hook before it runs anything
 *     dangerous; treat traces as observability, not enforcement.
 *   - The hook's own `require()` calls (process.on, fs, path) are
 *     attributed to '<root>' since the hook itself lives outside
 *     node_modules.
 */
import Module from 'module'
import fs from 'fs'
import os from 'os'
import path from 'path'
import {
  buildTrace,
  classifyRequireId,
  defaultTraceDir,
  packageOfFile,
} from './utils'

type RequireKind = 'builtin' | 'relative' | 'absolute' | 'package'
const observations = new Map<string, Map<string, RequireKind>>()
const startMs = Date.now()
const startCwd = process.cwd()

const originalRequire = Module.prototype.require
Module.prototype.require = function patchedRequire(this: NodeJS.Module, id: string) {
  try {
    const caller = packageOfFile(this.filename)
    const kind = classifyRequireId(id)
    let map = observations.get(caller)
    if (!map) {
      map = new Map()
      observations.set(caller, map)
    }
    // Only record the FIRST observation per (caller, id) so multiple
    // `require('https')` calls don't bloat the trace.
    if (!map.has(id)) map.set(id, kind)
  } catch {
    // Never let the hook throw — the consumer's code must run.
  }
  return originalRequire.call(this, id)
} as typeof Module.prototype.require

function flush(): void {
  try {
    const dir = defaultTraceDir(os.homedir())
    fs.mkdirSync(dir, { recursive: true })
    const trace = buildTrace(observations, { startMs, cwd: startCwd })
    const filename = `${new Date().toISOString().replace(/[:.]/g, '-')}-${process.pid}.json`
    fs.writeFileSync(path.join(dir, filename), JSON.stringify(trace, null, 2), 'utf8')
  } catch { /* best effort */ }
}

process.on('exit', flush)
process.on('SIGINT', () => { flush(); process.exit(130) })
process.on('SIGTERM', () => { flush(); process.exit(143) })
