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
import os from 'os'
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
  const profile = strict ? buildStrictProfile(pkg.path) : LOOSE_PROFILE

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

  return classify(pkg, result, Date.now() - start)
}
