/**
 * macOS sandbox-exec backend.
 *
 * sandbox-exec is shipped with the OS and uses TinyScheme profiles. We
 * compile two profiles: a strict deny-by-default one for `safenpm i`,
 * and a network-only profile for `--loose`. The strict profile must
 * list every directory we want to allow reads from — anything not
 * listed is rejected, including /etc/resolv.conf, /System headers, etc.
 *
 * Path escaping: profile values are quoted TinyScheme strings. We
 * escape embedded quotes only; backslashes aren't special in TinyScheme
 * string literals so we leave them alone. macOS package paths don't
 * normally contain newlines so we don't try to defend against them.
 */
import { spawnSync } from 'child_process'
import fs from 'fs'
import os from 'os'
import path from 'path'
import type { PackageScript, SandboxResult } from '../types'
import { cleanEnv } from './env'
import { classify, SANDBOX_TIMEOUT_MS } from './classify'

/** Strict profile: deny by default, allow only the package dir + system reads. */
export function buildStrictProfile(pkgPath: string): string {
  const escaped = pkgPath.replace(/"/g, '\\"')
  const home = os.homedir().replace(/"/g, '\\"')

  return `
(version 1)
(deny default)

;; process: allow execution of shell + common tools
(allow process-exec
  (literal "/bin/sh")
  (literal "/bin/bash")
  (literal "/usr/bin/env")
  (literal "/usr/bin/node")
  (literal "/usr/local/bin/node")
  (subpath "${escaped}")
)
(allow process-fork)
(allow process-exec-interpreter)

;; signals + sysctl
(allow signal (target self))
(allow sysctl-read)

;; mach / ipc
;; Allow the broad set of mach services native compiles need
;; (notification center, distributed notifications, CommandLineTools
;; helpers, etc), but explicitly deny the DNS / networking-adjacent
;; ones. Without these denies, a child process can resolve a hostname
;; via com.apple.dnssd-uds / mDNSResponder before the (deny network*)
;; rules fire, and an https.get() call leaks through intermittently.
(allow mach-lookup)
(deny mach-lookup
  (global-name "com.apple.dnssd-uds")
  (global-name "com.apple.mDNSResponder")
  (global-name "com.apple.networkd")
  (global-name "com.apple.cfnetwork.AuthBrokerAgent")
  (global-name "com.apple.usymptomsd")
  (global-name "com.apple.SystemConfiguration.PPPController")
  (global-name "com.apple.SystemConfiguration.SCNetworkReachability")
)
(allow ipc-posix-shm-read*)
(allow ipc-posix-shm-write-data)

;; filesystem: read access
(allow file-read*
  (subpath "/usr")
  (subpath "/bin")
  (subpath "/sbin")
  (subpath "/Library")
  (subpath "/System")
  (subpath "/private/var")
  (subpath "/dev")
  (subpath "/tmp")
  (subpath "/private/tmp")
  (subpath "${escaped}")
  (subpath "${escaped}/../")
)

;; filesystem: deny sensitive dirs (must come after the broad allows)
(deny file-read-data
  (subpath "${home}/.ssh")
  (subpath "${home}/.aws")
  (subpath "${home}/.gnupg")
  (subpath "${home}/.config")
  (subpath "${home}/.npmrc")
  (subpath "${home}/.netrc")
  (subpath "${home}/.docker")
  (subpath "${home}/.kube")
  (literal "${home}/.bash_history")
  (literal "${home}/.zsh_history")
  (literal "${home}/.env")
)

;; filesystem: writes only into pkg dir / /tmp / null devices
(allow file-write*
  (subpath "${escaped}")
  (subpath "/tmp")
  (subpath "/private/tmp")
  (literal "/dev/null")
  (literal "/dev/zero")
  (literal "/dev/random")
  (literal "/dev/urandom")
)

;; network: deny everything
(deny network-outbound)
(deny network-inbound)
(deny network-bind)
(deny network*)
`
}

/**
 * Loose profile: network-only deny. Filesystem stays unrestricted so
 * native-compile flows that read system headers/.gyp paths work. Users
 * are warned in the CLI that on-disk credentials remain readable.
 */
export const LOOSE_PROFILE: string = `
(version 1)
(allow default)
(deny network-outbound)
(deny network-inbound)
(deny network-bind)
(deny network*)
`

export function isAvailable(): boolean {
  if (os.platform() !== 'darwin') return false
  return spawnSync('which', ['sandbox-exec'], { encoding: 'utf8' }).status === 0
}

export function run(pkg: PackageScript, strict: boolean): SandboxResult {
  const start = Date.now()
  // Per-invocation trace file. sandbox-exec writes every deny event
  // it processed here (whether the process recovers gracefully or
  // not). Post-run we scan it for unexpected denies that the child's
  // stderr would have missed — that was the original SIGABRT-flake
  // class of bug (kill happened, but stderr stayed empty so classify
  // saw no signal). We surface ANY entry in the trace as a sandbox
  // violation indicator regardless of exit code.
  const traceFile = path.join(
    os.tmpdir(),
    `safenpm-sb-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}.log`,
  )
  const profile = strict
    ? withTrace(buildStrictProfile(pkg.path), traceFile)
    : LOOSE_PROFILE

  const result = spawnSync(
    'sandbox-exec',
    ['-p', profile, 'sh', '-c', pkg.script],
    {
      cwd: pkg.path,
      env: cleanEnv(),
      timeout: SANDBOX_TIMEOUT_MS,
      encoding: 'utf8',
    },
  )

  const decision = classify(pkg, result, Date.now() - start)
  return augmentWithTrace(decision, traceFile)
}

/**
 * Insert a `(trace …)` directive at the top of a strict profile.
 * sandbox-exec accumulates ALL evaluated operations into the file —
 * we only care about denies. The file is cleaned up immediately
 * after we've parsed it.
 */
function withTrace(profile: string, traceFile: string): string {
  // `(trace …)` lives just under `(version 1)` to apply to the whole
  // profile. The string-escape of the path matches the convention used
  // elsewhere in buildStrictProfile.
  const escaped = traceFile.replace(/"/g, '\\"')
  return profile.replace('(version 1)', `(version 1)\n(trace "${escaped}")`)
}

/**
 * If the sandbox trace recorded any deny operations, override the
 * classifier's "clean" verdict — even when the child's stderr was
 * empty and exit code was 0. The kernel killed something quietly and
 * we don't want to call that clean.
 *
 * Best-effort cleanup of the trace file regardless of outcome.
 */
function augmentWithTrace(result: SandboxResult, traceFile: string): SandboxResult {
  // Cap how much we read — a long install script can produce a
  // multi-MB trace and we don't need the whole thing to look for
  // deny lines.
  const MAX_TRACE_READ = 2 * 1024 * 1024
  let traceContent = ''
  try {
    if (fs.existsSync(traceFile)) {
      const stat = fs.statSync(traceFile)
      if (stat.size <= MAX_TRACE_READ) {
        traceContent = fs.readFileSync(traceFile, 'utf8')
      } else {
        const fd = fs.openSync(traceFile, 'r')
        const buf = Buffer.alloc(MAX_TRACE_READ)
        fs.readSync(fd, buf, 0, MAX_TRACE_READ, 0)
        fs.closeSync(fd)
        traceContent = buf.toString('utf8')
      }
      fs.unlinkSync(traceFile)
    }
  } catch { /* best effort */ }

  if (!traceContent) return result

  // The trace format is one s-expression per evaluated op. Denies
  // appear as either `;# DENY …` headers or as ops with a deny
  // disposition. We do the cheapest possible match.
  const hasDeny = /\bdeny\b/i.test(traceContent)
  if (!hasDeny) return result

  // Already classified as blocked → nothing to change.
  if (result.blocked) {
    return {
      ...result,
      output: result.output + `\n[safenpm] sandbox-exec trace recorded deny events (confirmed block).`,
    }
  }

  // Was clean, but the kernel denied something — flip to blocked.
  // First deny line gives us a reason hint.
  const firstDeny = traceContent.split('\n').find((l) => /deny/i.test(l)) ?? ''
  const looksNetwork = /network/i.test(firstDeny)
  return {
    ...result,
    blocked: true,
    reason: looksNetwork ? 'network' : 'filesystem',
    output: result.output + `\n[safenpm] sandbox trace recorded a quiet deny — escalating clean→blocked.\n  trace excerpt: ${firstDeny.slice(0, 200)}`,
  }
}
