import { beforeEach, describe, expect, it, vi } from 'vitest'

// Mock each backend's availability check so the dispatch order is
// fully observable from a single platform. The seam in index.ts
// (`__resetBackendCacheForTests`) lets us flip availability between
// tests without re-importing the module.
const mocks = vi.hoisted(() => ({
  macosAvailable: false,
  linuxAvailable: false,
  windowsFwAvailable: false,
  wslFirejailAvailable: false,
  macosRun: vi.fn(),
  linuxRun: vi.fn(),
  winFwRun: vi.fn(),
  winWslRun: vi.fn(),
  unsandboxedRun: vi.fn(),
}))

vi.mock('./macos', () => ({
  isAvailable: () => mocks.macosAvailable,
  run: mocks.macosRun,
}))
vi.mock('./linux', () => ({
  isAvailable: () => mocks.linuxAvailable,
  run: mocks.linuxRun,
}))
vi.mock('./windows', () => ({
  isFirewallAvailable: () => mocks.windowsFwAvailable,
  isWslFirejailAvailable: () => mocks.wslFirejailAvailable,
  runFirewall: mocks.winFwRun,
  runWsl: mocks.winWslRun,
}))
vi.mock('./unsandboxed', () => ({
  run: mocks.unsandboxedRun,
}))

import {
  __resetBackendCacheForTests,
  backendName,
  getBackend,
  isSandboxAvailable,
  runInSandbox,
} from './index'
import type { PackageScript } from '../types'

const pkg: PackageScript = {
  name: 'demo', version: '1.0.0', hook: 'postinstall',
  path: '/tmp/x', script: 'echo hi',
}

beforeEach(() => {
  mocks.macosAvailable = false
  mocks.linuxAvailable = false
  mocks.windowsFwAvailable = false
  mocks.wslFirejailAvailable = false
  mocks.macosRun.mockClear()
  mocks.linuxRun.mockClear()
  mocks.winFwRun.mockClear()
  mocks.winWslRun.mockClear()
  mocks.unsandboxedRun.mockClear()
  __resetBackendCacheForTests()
})

describe('detectBackend priority', () => {
  it('picks macOS sandbox-exec when available', () => {
    mocks.macosAvailable = true
    mocks.linuxAvailable = true   // both present — macOS wins
    expect(getBackend()).toBe('sandbox-exec')
  })

  it('picks Linux firejail when macOS is unavailable', () => {
    mocks.linuxAvailable = true
    mocks.windowsFwAvailable = true
    expect(getBackend()).toBe('firejail')
  })

  it('picks Windows firewall when neither macOS nor Linux is available', () => {
    mocks.windowsFwAvailable = true
    mocks.wslFirejailAvailable = true
    expect(getBackend()).toBe('windows-firewall')
  })

  it('picks WSL firejail when no other backend is present', () => {
    mocks.wslFirejailAvailable = true
    expect(getBackend()).toBe('wsl-firejail')
  })

  it('falls back to none when nothing is available', () => {
    expect(getBackend()).toBe('none')
  })
})

describe('getBackend caching', () => {
  it('returns the cached value on repeat calls without re-detecting', () => {
    mocks.macosAvailable = true
    expect(getBackend()).toBe('sandbox-exec')

    // Flip availability behind the cache — getBackend should not notice.
    mocks.macosAvailable = false
    expect(getBackend()).toBe('sandbox-exec')
  })

  it('re-detects after __resetBackendCacheForTests', () => {
    mocks.macosAvailable = true
    expect(getBackend()).toBe('sandbox-exec')

    mocks.macosAvailable = false
    mocks.linuxAvailable = true
    __resetBackendCacheForTests()
    expect(getBackend()).toBe('firejail')
  })
})

describe('isSandboxAvailable', () => {
  it('returns true for any real backend', () => {
    mocks.macosAvailable = true
    expect(isSandboxAvailable()).toBe(true)
  })

  it('returns false when only the "none" backend would be selected', () => {
    expect(isSandboxAvailable()).toBe(false)
  })
})

describe('backendName labels', () => {
  it('returns the human-readable label for each backend', () => {
    mocks.macosAvailable = true
    expect(backendName()).toBe('sandbox-exec (macOS)')

    __resetBackendCacheForTests()
    mocks.macosAvailable = false
    mocks.linuxAvailable = true
    expect(backendName()).toBe('firejail (Linux)')

    __resetBackendCacheForTests()
    mocks.linuxAvailable = false
    expect(backendName()).toBe('none')
  })
})

describe('runInSandbox dispatch', () => {
  it('routes to macos.run with strict flag forwarded', () => {
    mocks.macosAvailable = true
    runInSandbox(pkg, /* strict */ true)
    expect(mocks.macosRun).toHaveBeenCalledWith(pkg, true)
    expect(mocks.linuxRun).not.toHaveBeenCalled()
  })

  it('routes to linux.run on Linux', () => {
    mocks.linuxAvailable = true
    runInSandbox(pkg, false)
    expect(mocks.linuxRun).toHaveBeenCalledWith(pkg, false)
  })

  it('routes to unsandboxed.run when no real backend is available', () => {
    runInSandbox(pkg)
    expect(mocks.unsandboxedRun).toHaveBeenCalledWith(pkg)
    expect(mocks.macosRun).not.toHaveBeenCalled()
    expect(mocks.linuxRun).not.toHaveBeenCalled()
  })

  it('defaults strict=true when omitted', () => {
    mocks.macosAvailable = true
    runInSandbox(pkg)
    expect(mocks.macosRun).toHaveBeenCalledWith(pkg, true)
  })
})
