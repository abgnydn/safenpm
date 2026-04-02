export interface PackageScript {
  name: string
  version: string
  path: string
  script: string
  hook: string
}

/** Possible reasons for a sandbox result */
export type SandboxReason = 'network' | 'filesystem' | 'clean' | 'error' | 'allowed'

export interface SandboxResult {
  pkg: PackageScript
  blocked: boolean
  skipped: boolean
  reason: SandboxReason
  output: string
  durationMs: number
}

export interface Signal {
  machineId: string
  package: string
  version: string
  hook: string
  script: string           // truncated preview (first 500 chars)
  scriptHash: string       // sha256 of full script for dedup/correlation
  scriptLength: number     // full script length for context
  reason: string
  timestamp: string
  platform: string
}

export interface InstallOptions {
  packages: string[]
  dryRun: boolean
  allow: string[]
  noReport: boolean
  json: boolean
  interactive: boolean
  loose: boolean
  scan: boolean        // --scan: deep scan mode (all v0.4 checks)
}

export interface JsonOutput {
  version: string
  backend: string
  timestamp: string
  packages: JsonPackageResult[]
  typosquats: JsonTyposquatResult[]
  lockfileAudit: JsonLockfileResult | null
  reputationSummary: JsonReputationSummary | null
  summary: {
    total: number
    blocked: number
    allowed: number
    clean: number
    warnings: number
    typosquats: number
    maintainerChanges: number
    lockfileIssues: number
    reputationScore: number
  }
}

export interface JsonPackageResult {
  name: string
  version: string
  hook: string
  script: string
  result: 'blocked' | 'clean' | 'allowed'
  reason: string
  durationMs: number
  riskScore: number
  warnings: { rule: string; severity: string; description: string }[]
  threatIntel?: { flagged: boolean; reportCount: number; topReasons: string[] }
  maintainerChanged?: boolean
  behaviorDiff?: { newWarnings: string[]; riskDelta: number }
}

export interface JsonTyposquatResult {
  suspect: string
  target: string
  distance: number
  technique: string
  confidence: string
}

export interface JsonLockfileResult {
  exists: boolean
  format: string | null
  totalPackages: number
  score: number
  issues: { severity: string; type: string; package: string; detail: string }[]
}

export interface JsonReputationSummary {
  overallScore: number
  totalPackages: number
  averageScore: number
  tiers: Record<string, number>
  riskiest: { name: string; version: string; score: number; tier: string }[]
}
