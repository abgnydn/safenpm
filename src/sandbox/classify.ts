import type { spawnSync } from 'child_process'
import type { PackageScript, SandboxResult, SandboxReason } from '../types'

/** Output patterns that indicate the sandbox killed a network attempt. */
const NETWORK_VIOLATION_PATTERNS: readonly RegExp[] = [
  /sandbox.*deny.*network/i,
  /Operation not permitted/i,
  /ECONNREFUSED/i,
  /ENETUNREACH/i,
  /getaddrinfo.*EAI_AGAIN/i,
  /connect EACCES/i,
  /An attempt was made to access a socket/i, // Windows
  /firewall.*block/i,                         // Windows
  /network is unreachable/i,                  // WSL
]

/** Output patterns that indicate a filesystem-restriction kill. */
const FS_VIOLATION_PATTERNS: readonly RegExp[] = [
  /sandbox.*deny.*file/i,
  /EACCES.*\.ssh/i,
  /EACCES.*\.aws/i,
  /Permission denied/i,
  /Access is denied/i, // Windows
]

/**
 * Exit codes that strongly suggest a sandbox violation rather than
 * application error: sandbox-exec uses 65 (EX_DATAERR); firejail uses
 * 126 for command-not-allowed; signal-based kills surface as 137 / 143.
 */
const SANDBOX_VIOLATION_EXIT_CODES: ReadonlySet<number> = new Set([65, 126, 137, 143])

const SCRIPT_TIMEOUT_MS = 30_000
const TIMEOUT_THRESHOLD_MS = SCRIPT_TIMEOUT_MS - 1_000

type SpawnResult = ReturnType<typeof spawnSync>

/**
 * Classify a finished child-process run into a SandboxResult.
 *
 * Detection runs three layers — pattern match on stderr, exit-code
 * sniff, and signal sniff — and picks the most specific reason. When
 * we block solely on exit code with no pattern match, we annotate the
 * output so a human investigator can tell why.
 */
export function classify(
  pkg: PackageScript,
  result: SpawnResult,
  durationMs: number,
): SandboxResult {
  const output = [result.stdout, result.stderr].filter(Boolean).join('\n')
  const failed = result.status !== 0
  const timedOut = result.signal === 'SIGTERM' && durationMs >= TIMEOUT_THRESHOLD_MS

  if (!failed) {
    return { pkg, blocked: false, skipped: false, reason: 'clean', output, durationMs }
  }

  const looksLikeNetwork = NETWORK_VIOLATION_PATTERNS.some((p) => p.test(output))
  const looksLikeFs = FS_VIOLATION_PATTERNS.some((p) => p.test(output))
  const exitCode = result.status ?? 0
  const suspiciousExitCode = SANDBOX_VIOLATION_EXIT_CODES.has(exitCode)
  // Any signal-based death is strong evidence the sandbox killed the
  // process. macOS sandbox-exec terminates violators with SIGKILL, but
  // when a libc/libuv path aborts the process internally (e.g. DNS or
  // mach-lookup denied during socket setup) the resulting death is
  // SIGABRT — that was the original "Did not block phone-home" flake:
  // SIGABRT classified as `error` instead of `blocked`. Treat every
  // non-null signal as suspicious; legitimate scripts almost never
  // abort by signal.
  const killedBySignal = result.signal !== null && result.signal !== undefined

  let reason: SandboxReason = 'error'
  if (looksLikeNetwork) {
    reason = 'network'
  } else if (looksLikeFs) {
    reason = 'filesystem'
  } else if (suspiciousExitCode || killedBySignal) {
    // Sandbox almost certainly killed it but the locale-specific
    // message didn't match our patterns. Better to over-flag than miss.
    reason = 'network'
  } else if (timedOut) {
    // A hanging script is most often blocked on a socket we denied.
    reason = 'network'
  }

  const blocked = reason !== 'error' || suspiciousExitCode || killedBySignal
  const detectionNote = !looksLikeNetwork && !looksLikeFs && blocked
    ? `\n[safenpm] Blocked based on exit code ${exitCode}${result.signal ? ` (signal: ${result.signal})` : ''} — pattern matching inconclusive`
    : ''

  return {
    pkg,
    blocked,
    skipped: false,
    reason,
    output: output + detectionNote,
    durationMs,
  }
}

export const SANDBOX_TIMEOUT_MS = SCRIPT_TIMEOUT_MS
