import { describe, expect, it } from 'vitest'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { run } from './unsandboxed'
import type { PackageScript } from '../types'

function pkgWith(script: string): PackageScript {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'safenpm-unsandboxed-'))
  return { name: 'x', version: '1.0.0', hook: 'postinstall', path: dir, script }
}

describe('unsandboxed.run', () => {
  it('runs a clean script and always returns clean / blocked=false', () => {
    const pkg = pkgWith('echo hello')
    const r = run(pkg)
    expect(r.blocked).toBe(false)
    expect(r.skipped).toBe(false)
    expect(r.reason).toBe('clean')
    expect(r.output).toContain('hello')
    expect(r.durationMs).toBeGreaterThanOrEqual(0)
    fs.rmSync(pkg.path, { recursive: true, force: true })
  })

  it('returns clean even when the script EXITS NON-ZERO — by design', () => {
    // The "unsandboxed" backend never blocks; the install/index.ts
    // warning is the policy signal that no sandboxing happened. The
    // result.blocked=false is intentional regardless of exit code.
    const pkg = pkgWith('exit 1')
    const r = run(pkg)
    expect(r.blocked).toBe(false)
    expect(r.reason).toBe('clean')
    fs.rmSync(pkg.path, { recursive: true, force: true })
  })

  it('joins stdout + stderr in output', () => {
    const pkg = pkgWith('echo to-stdout; echo to-stderr 1>&2')
    const r = run(pkg)
    expect(r.output).toContain('to-stdout')
    expect(r.output).toContain('to-stderr')
    fs.rmSync(pkg.path, { recursive: true, force: true })
  })
})
