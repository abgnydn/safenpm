import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import fs from 'fs'
import os from 'os'
import path from 'path'

// audit/log.ts caches `path.join(os.homedir(), '.safenpm')` at module
// load time, so we have to (a) set SAFENPM_TEST_HOME before any
// imports run via `vi.hoisted`, then (b) mock `os.homedir()` to
// return it. The fixed-path approach is necessary because the
// module's `const AUDIT_DIR` resolves once and stays frozen.
const FIXED_HOME = vi.hoisted(() => {
  const dir = require('fs').mkdtempSync(
    require('path').join(require('os').tmpdir(), 'safenpm-audit-home-'),
  )
  process.env.SAFENPM_TEST_HOME = dir
  return dir
})

vi.mock('os', async () => {
  const actual = await vi.importActual<typeof import('os')>('os')
  const homedir = () => process.env.SAFENPM_TEST_HOME ?? actual.homedir()
  return { ...actual, homedir, default: { ...actual, homedir } }
})

import { readAuditLog, writeAuditLog } from './log'
import type { AnalysisResult } from '../analysis/analyzer'
import type { SandboxResult } from '../types'

const AUDIT_DIR = path.join(FIXED_HOME, '.safenpm')
const AUDIT_FILE = path.join(AUDIT_DIR, 'audit.log')

beforeEach(() => {
  // Reset just the .safenpm subdir between tests — keeping FIXED_HOME
  // stable so the module's baked-in paths still resolve.
  if (fs.existsSync(AUDIT_DIR)) {
    fs.rmSync(AUDIT_DIR, { recursive: true, force: true })
  }
})

afterEach(() => {
  if (fs.existsSync(AUDIT_DIR)) {
    fs.rmSync(AUDIT_DIR, { recursive: true, force: true })
  }
})

function result(name: string, opts: Partial<SandboxResult> = {}): SandboxResult {
  return {
    pkg: { name, version: '1.0.0', hook: 'postinstall', script: 'echo', path: '/tmp/x' },
    blocked: false, skipped: false, reason: 'clean',
    output: '', durationMs: 5,
    ...opts,
  }
}

describe('writeAuditLog → readAuditLog round-trip', () => {
  it('appends a single JSON-lines entry containing the run summary', () => {
    writeAuditLog([result('clean-lib')], [], 'sandbox-exec')

    const entries = readAuditLog()
    expect(entries).toHaveLength(1)
    expect(entries[0]?.backend).toBe('sandbox-exec')
    expect(entries[0]?.summary).toEqual({ total: 1, blocked: 0, allowed: 0, clean: 1 })
    expect(entries[0]?.packages[0]?.name).toBe('clean-lib')
    expect(entries[0]?.packages[0]?.result).toBe('clean')
  })

  it('counts blocked / allowed / clean correctly in the summary', () => {
    writeAuditLog(
      [
        result('clean-lib'),
        result('phone-home', { blocked: true, reason: 'network' }),
        result('trusted', { skipped: true, reason: 'allowed' }),
      ],
      [], 'sandbox-exec',
    )
    const e = readAuditLog()[0]!
    expect(e.summary).toEqual({ total: 3, blocked: 1, allowed: 1, clean: 1 })
  })

  it('returns the last N entries when the file holds more', () => {
    for (let i = 0; i < 25; i++) {
      writeAuditLog([result(`pkg-${i}`)], [], 'sandbox-exec')
    }
    const entries = readAuditLog(5)
    expect(entries).toHaveLength(5)
    expect(entries[0]?.packages[0]?.name).toBe('pkg-20')
    expect(entries[4]?.packages[0]?.name).toBe('pkg-24')
  })

  it('attaches riskScore + warnings when an AnalysisResult is supplied', () => {
    const analysis: AnalysisResult = {
      pkg: { name: 'risky', version: '1.0.0', hook: 'postinstall', script: 'curl x', path: '' },
      riskScore: 75,
      warnings: [
        { rule: 'NETWORK_ACCESS', description: '', severity: 'high' },
        { rule: 'SHELL_EXEC', description: '', severity: 'medium' },
      ],
    }
    writeAuditLog([result('risky')], [analysis], 'sandbox-exec')

    const entry = readAuditLog()[0]!.packages[0]!
    expect(entry.riskScore).toBe(75)
    expect(entry.warnings).toEqual(['NETWORK_ACCESS', 'SHELL_EXEC'])
  })

  it('omits riskScore + warnings when no analysis is available', () => {
    writeAuditLog([result('plain')], [], 'sandbox-exec')
    const entry = readAuditLog()[0]!.packages[0]!
    expect(entry.riskScore).toBeUndefined()
    expect(entry.warnings).toBeUndefined()
  })
})

describe('readAuditLog — resilience', () => {
  it('returns [] when the log file does not exist', () => {
    expect(readAuditLog()).toEqual([])
  })

  it('skips corrupt JSON lines and returns the parseable ones', () => {
    fs.mkdirSync(AUDIT_DIR, { recursive: true })
    const goodEntry = JSON.stringify({
      timestamp: '2026-05-21T00:00:00Z', cwd: '/x', backend: 'b',
      packages: [], summary: { total: 0, blocked: 0, allowed: 0, clean: 0 },
    })
    fs.writeFileSync(AUDIT_FILE, `${goodEntry}\nNOT JSON\n${goodEntry}\n`)
    const entries = readAuditLog()
    expect(entries).toHaveLength(2)
  })
})

describe('writeAuditLog — best-effort failure mode', () => {
  it('does not throw when the audit directory cannot be created', () => {
    // Plant a regular file where ensureDir() would try to mkdir.
    fs.writeFileSync(AUDIT_DIR, 'not a directory')
    expect(() => writeAuditLog([result('x')], [], 'sandbox-exec')).not.toThrow()
    // cleanup so afterEach can rmSync without recursing into a file
    fs.unlinkSync(AUDIT_DIR)
  })
})
