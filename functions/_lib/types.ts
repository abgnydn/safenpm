/**
 * Shape of every entry stored in the `safenpm:flagged` hash. Written
 * by signal.ts on incoming reports; read by intel.ts and stats.ts to
 * surface aggregates to clients.
 *
 * `scriptHashes` is the deduplicated set of script hashes observed
 * across all reports — if it grows past 3 the package is treated as
 * "inconsistent" and not flagged, since unique hashes per reporter is
 * the hallmark of spam reports rather than a real malicious payload.
 */
export interface FlaggedEntry {
  reportCount: number
  distinctReporters: number
  reasons: Record<string, number>
  firstSeen: string
  lastSeen: string
  scriptHash: string
  scriptHashes: string[]
  platforms: Record<string, number>
}

/**
 * Validated payload from POST /api/v1/signal.
 */
export interface Signal {
  machineId: string
  package: string
  version: string
  hook: string
  script: string
  scriptHash: string
  scriptLength: number
  reason: string
  timestamp: string
  platform: string
}

export interface IntelQuery {
  packages: Array<{ name: string; version: string }>
}

export interface IntelResult {
  name: string
  version: string
  flagged: boolean
  reportCount: number
  firstSeen: string | null
  lastSeen: string | null
  topReasons: string[]
  dataFresh: boolean
}
