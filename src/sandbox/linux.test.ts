import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

// Capture every spawnSync call so tests can inspect the args + env
// that the backend would have passed to firejail. Both `isAvailable`
// (which runs `which firejail`) and `run` (which runs firejail itself)
// go through this mock.
const spawnCalls: Array<{
  cmd: string
  args: readonly string[]
  opts: Record<string, unknown>
}> = []
let nextSpawnResult: {
  status?: number | null
  signal?: NodeJS.Signals | null
  stdout?: string
  stderr?: string
} = { status: 0, stdout: '', stderr: '' }

vi.mock('child_process', () => ({
  spawnSync: (cmd: string, args: readonly string[], opts: Record<string, unknown>) => {
    spawnCalls.push({ cmd, args, opts })
    return {
      // Use === undefined so `status: null` survives — `??` collapses
      // null to the default, which would mask SIGKILL-with-no-status.
      status: nextSpawnResult.status === undefined ? 0 : nextSpawnResult.status,
      signal: nextSpawnResult.signal === undefined ? null : nextSpawnResult.signal,
      stdout: nextSpawnResult.stdout ?? '',
      stderr: nextSpawnResult.stderr ?? '',
      pid: 0, output: [], error: undefined,
    } as ReturnType<typeof import('child_process').spawnSync>
  },
}))

vi.mock('os', async () => {
  const actual = await vi.importActual<typeof import('os')>('os')
  return {
    ...actual,
    platform: () => 'linux',
    homedir: () => '/home/test-user',
    default: { ...actual, platform: () => 'linux', homedir: () => '/home/test-user' },
  }
})

import { isAvailable, run, HOME_BLACKLIST_PATHS } from './linux'
import type { PackageScript } from '../types'

const pkg: PackageScript = {
  name: 'demo', version: '1.0.0', hook: 'postinstall',
  path: '/tmp/demo-pkg', script: 'echo hi',
}

beforeEach(() => {
  spawnCalls.length = 0
  nextSpawnResult = { status: 0, stdout: '', stderr: '' }
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('linux.isAvailable', () => {
  it('returns true when `which firejail` exits 0', () => {
    nextSpawnResult = { status: 0 }
    expect(isAvailable()).toBe(true)
    expect(spawnCalls[0]?.cmd).toBe('which')
    expect(spawnCalls[0]?.args).toEqual(['firejail'])
  })

  it('returns false when `which firejail` exits non-zero', () => {
    nextSpawnResult = { status: 1 }
    expect(isAvailable()).toBe(false)
  })
})

describe('linux.run — argument construction', () => {
  it('invokes firejail with --net=none and --quiet, --noprofile', () => {
    run(pkg, /* strict */ false)
    const call = spawnCalls.find((c) => c.cmd === 'firejail')!
    expect(call.args).toContain('--net=none')
    expect(call.args).toContain('--quiet')
    expect(call.args).toContain('--noprofile')
  })

  it('passes the script via `sh -c` after a `--` separator', () => {
    run(pkg, false)
    const call = spawnCalls.find((c) => c.cmd === 'firejail')!
    const dashIdx = call.args.indexOf('--')
    expect(dashIdx).toBeGreaterThan(-1)
    expect(call.args.slice(dashIdx + 1)).toEqual(['sh', '-c', 'echo hi'])
  })

  it('runs from pkg.path with a cleaned env', () => {
    run(pkg, false)
    const call = spawnCalls.find((c) => c.cmd === 'firejail')!
    expect(call.opts.cwd).toBe('/tmp/demo-pkg')
    const env = call.opts.env as Record<string, string>
    // cleanEnv strips known-sensitive keys; spot-check that NPM_TOKEN
    // is gone even if it was present in the test process env.
    expect(env.NPM_TOKEN).toBeUndefined()
    expect(env.GITHUB_TOKEN).toBeUndefined()
    expect(env.AWS_SECRET_ACCESS_KEY).toBeUndefined()
  })

  it('does NOT blacklist credential paths in loose mode', () => {
    run(pkg, /* strict */ false)
    const call = spawnCalls.find((c) => c.cmd === 'firejail')!
    expect(call.args.find((a) => a.includes('--blacklist'))).toBeUndefined()
    expect(call.args.find((a) => a.includes('--read-only'))).toBeUndefined()
  })

  it('adds a --blacklist for each credential path in strict mode', () => {
    run(pkg, /* strict */ true)
    const call = spawnCalls.find((c) => c.cmd === 'firejail')!
    for (const rel of HOME_BLACKLIST_PATHS) {
      expect(call.args).toContain(`--blacklist=/home/test-user/${rel}`)
    }
  })

  it('locks the home dir read-only in strict mode', () => {
    run(pkg, /* strict */ true)
    const call = spawnCalls.find((c) => c.cmd === 'firejail')!
    expect(call.args).toContain('--read-only=/home/test-user')
  })
})

describe('linux.run — classify integration', () => {
  it('returns a clean result when firejail exits 0 with no error patterns', () => {
    nextSpawnResult = { status: 0, stdout: 'hi', stderr: '' }
    const r = run(pkg, true)
    expect(r.blocked).toBe(false)
    expect(r.reason).toBe('clean')
  })

  it('flags a SIGKILL termination as a network block (sandbox kill)', () => {
    nextSpawnResult = { status: null, signal: 'SIGKILL' }
    const r = run(pkg, true)
    expect(r.blocked).toBe(true)
    expect(r.reason).toBe('network')
  })

  it('flags a getaddrinfo EAI_AGAIN stderr message as a network block', () => {
    nextSpawnResult = { status: 1, stderr: 'getaddrinfo EAI_AGAIN evil.com' }
    const r = run(pkg, true)
    expect(r.blocked).toBe(true)
    expect(r.reason).toBe('network')
  })
})
