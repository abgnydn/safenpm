import { describe, expect, it } from 'vitest'
import { classify } from './classify'
import type { PackageScript } from '../types'

const pkg: PackageScript = {
  name: 'x',
  version: '1.0.0',
  path: '/tmp',
  script: 'echo hi',
  hook: 'postinstall',
}

// classify takes a `ReturnType<typeof spawnSync>` shape, so we mock the
// minimum surface area used: { status, signal, stdout, stderr }.
type Spawn = Parameters<typeof classify>[1]
const mk = (over: Partial<Spawn>): Spawn => ({
  status: 0,
  signal: null,
  stdout: '',
  stderr: '',
  ...over,
} as Spawn)

describe('classify', () => {
  it('marks a clean exit as clean', () => {
    const r = classify(pkg, mk({ status: 0, stdout: 'hi' }), 5)
    expect(r.blocked).toBe(false)
    expect(r.reason).toBe('clean')
    expect(r.output).toBe('hi')
  })

  it('classifies sandbox-deny network output as network block', () => {
    const r = classify(pkg, mk({ status: 1, stderr: 'sandbox: deny network-outbound' }), 50)
    expect(r.blocked).toBe(true)
    expect(r.reason).toBe('network')
  })

  it('classifies ECONNREFUSED as network block', () => {
    const r = classify(pkg, mk({ status: 1, stderr: 'connect ECONNREFUSED 1.1.1.1' }), 50)
    expect(r.reason).toBe('network')
  })

  it('classifies EACCES on .ssh as filesystem block', () => {
    const r = classify(pkg, mk({ status: 1, stderr: 'EACCES: /Users/x/.ssh/id_rsa' }), 50)
    expect(r.reason).toBe('filesystem')
  })

  it('flags sandbox-violation exit codes even with no message', () => {
    const r = classify(pkg, mk({ status: 65, stderr: '' }), 50)
    expect(r.blocked).toBe(true)
    expect(r.reason).toBe('network')
    expect(r.output).toContain('Blocked based on exit code 65')
  })

  it('flags SIGKILL kills as blocked', () => {
    const r = classify(pkg, mk({ status: null, signal: 'SIGKILL' }), 50)
    expect(r.blocked).toBe(true)
  })

  it('flags SIGABRT kills as blocked (regression: phone-home flake)', () => {
    // macOS sandbox-exec terminates a sandbox violator that hits a
    // denied syscall during libc/libuv init with SIGABRT, not SIGKILL.
    // Before this regression test, classify treated SIGABRT as a
    // plain "error" and the install returned blocked=false.
    const r = classify(pkg, mk({ status: null, signal: 'SIGABRT', stderr: '' }), 50)
    expect(r.blocked).toBe(true)
    expect(r.reason).toBe('network')
  })

  it('flags any signal-based death as blocked (SIGBUS, SIGSEGV, etc.)', () => {
    for (const sig of ['SIGBUS', 'SIGSEGV', 'SIGILL', 'SIGFPE'] as const) {
      const r = classify(pkg, mk({ status: null, signal: sig }), 50)
      expect(r.blocked, `signal=${sig}`).toBe(true)
    }
  })

  it('flags a SIGTERM near the timeout window as a network block', () => {
    const r = classify(pkg, mk({ status: null, signal: 'SIGTERM' }), 29_500)
    expect(r.blocked).toBe(true)
    expect(r.reason).toBe('network')
  })

  it('leaves "error" reason when nothing matches', () => {
    const r = classify(pkg, mk({ status: 2, stderr: 'syntax error' }), 5)
    expect(r.blocked).toBe(false)
    expect(r.reason).toBe('error')
  })
})
