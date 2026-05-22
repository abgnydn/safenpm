import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import fs from 'fs'
import os from 'os'
import path from 'path'

// audit.ts reads `~/.safenpm/audit.log` via the audit/log module, which
// caches `os.homedir()` at module load. Same hoisted-home pattern as
// src/audit/log.test.ts so each test gets an isolated home dir.
const FIXED_HOME = vi.hoisted(() => {
  const dir = require('fs').mkdtempSync(
    require('path').join(require('os').tmpdir(), 'safenpm-audit-cmd-home-'),
  )
  process.env.SAFENPM_TEST_HOME = dir
  return dir
})

vi.mock('os', async () => {
  const actual = await vi.importActual<typeof import('os')>('os')
  const homedir = () => process.env.SAFENPM_TEST_HOME ?? actual.homedir()
  return { ...actual, homedir, default: { ...actual, homedir } }
})

import { run } from './audit'
import { writeAuditLog } from '../../audit/log'
import type { SandboxResult } from '../../types'

const AUDIT_DIR = path.join(FIXED_HOME, '.safenpm')

let lines: string[]

beforeEach(() => {
  if (fs.existsSync(AUDIT_DIR)) fs.rmSync(AUDIT_DIR, { recursive: true, force: true })
  lines = []
  vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => { lines.push(args.join(' ')) })
})

afterEach(() => {
  if (fs.existsSync(AUDIT_DIR)) fs.rmSync(AUDIT_DIR, { recursive: true, force: true })
  vi.restoreAllMocks()
})

function result(name: string, over: Partial<SandboxResult> = {}): SandboxResult {
  return {
    pkg: { name, version: '1.0.0', hook: 'postinstall', script: 'echo', path: '/tmp/x' },
    blocked: false, skipped: false, reason: 'clean',
    output: '', durationMs: 5,
    ...over,
  }
}

describe('safenpm audit', () => {
  it('returns exit 0 and prints a helpful message when no audit log exists', async () => {
    const code = await run([])
    expect(code).toBe(0)
    expect(lines.join('\n')).toMatch(/no audit entries found/)
  })

  it('prints an empty JSON array in --json mode when there is no log', async () => {
    const code = await run(['--json'])
    expect(code).toBe(0)
    expect(JSON.parse(lines.join('\n'))).toEqual([])
  })

  it('renders blocked runs in red with the block reason', async () => {
    writeAuditLog([
      result('phone-home', { blocked: true, reason: 'network' }),
      result('clean-lib'),
    ], [], 'sandbox-exec')

    const code = await run([])
    expect(code).toBe(0)
    const out = lines.join('\n')
    expect(out).toMatch(/1 blocked/)
    expect(out).toMatch(/phone-home@1\.0\.0/)
    expect(out).toMatch(/\[network\]/)
  })

  it('emits structured JSON when --json is passed and entries exist', async () => {
    writeAuditLog([result('lib-a')], [], 'sandbox-exec')
    const code = await run(['--json'])
    expect(code).toBe(0)

    const parsed = JSON.parse(lines.join('\n'))
    expect(Array.isArray(parsed)).toBe(true)
    expect(parsed[0].backend).toBe('sandbox-exec')
    expect(parsed[0].summary.total).toBe(1)
  })

  it('respects a positional limit argument', async () => {
    for (let i = 0; i < 15; i++) {
      writeAuditLog([result(`pkg-${i}`)], [], 'sandbox-exec')
    }
    await run(['3', '--json'])
    const parsed = JSON.parse(lines.join('\n'))
    expect(parsed).toHaveLength(3)
    // last three runs in chronological order
    expect(parsed.map((e: { packages: { name: string }[] }) => e.packages[0]?.name))
      .toEqual(['pkg-12', 'pkg-13', 'pkg-14'])
  })
})
