/**
 * Public sandbox API. Detects the best platform backend at first use,
 * caches it, and dispatches `runInSandbox` to that backend.
 *
 * Backend priority:
 *   macOS  → sandbox-exec
 *   Linux  → firejail
 *   Win32  → firewall (if admin) → WSL+firejail → none
 *
 * Keep this file thin — anything backend-specific goes in the per-OS
 * module. Anything cross-cutting (env strip, classification) lives in
 * env.ts / classify.ts.
 */
import type { PackageScript, SandboxResult } from '../types'

import * as macos from './macos'
import * as linux from './linux'
import * as windows from './windows'
import * as unsandboxed from './unsandboxed'

export { STRIPPED_ENV_KEYS, cleanEnv } from './env'

export type SandboxBackend =
  | 'sandbox-exec'
  | 'firejail'
  | 'windows-firewall'
  | 'wsl-firejail'
  | 'none'

function detectBackend(): SandboxBackend {
  if (macos.isAvailable()) return 'sandbox-exec'
  if (linux.isAvailable()) return 'firejail'
  if (windows.isFirewallAvailable()) return 'windows-firewall'
  if (windows.isWslFirejailAvailable()) return 'wsl-firejail'
  return 'none'
}

let _cachedBackend: SandboxBackend | null = null

export function getBackend(): SandboxBackend {
  if (_cachedBackend === null) {
    _cachedBackend = detectBackend()
  }
  return _cachedBackend
}

/** Test seam — reset the cache so a different platform can be re-detected. */
export function __resetBackendCacheForTests(): void {
  _cachedBackend = null
}

export function isSandboxAvailable(): boolean {
  return getBackend() !== 'none'
}

const BACKEND_LABELS: Record<SandboxBackend, string> = {
  'sandbox-exec': 'sandbox-exec (macOS)',
  'firejail': 'firejail (Linux)',
  'windows-firewall': 'Windows Firewall + ACLs (admin)',
  'wsl-firejail': 'firejail via WSL (Windows)',
  'none': 'none',
}

export function backendName(): string {
  return BACKEND_LABELS[getBackend()]
}

export function runInSandbox(pkg: PackageScript, strict: boolean = true): SandboxResult {
  switch (getBackend()) {
    case 'sandbox-exec':     return macos.run(pkg, strict)
    case 'firejail':         return linux.run(pkg, strict)
    case 'windows-firewall': return windows.runFirewall(pkg, strict)
    case 'wsl-firejail':     return windows.runWsl(pkg, strict)
    case 'none':             return unsandboxed.run(pkg)
  }
}
