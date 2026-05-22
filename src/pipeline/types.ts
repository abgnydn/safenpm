/**
 * Pipeline abstraction for the pre-execution analysis phase of
 * `safenpm install`. Each Step is an independently runnable check
 * (typosquat, lockfile audit, threat-intel query, …) that produces a
 * tagged `Finding`. The orchestrator (install/index.ts) decides what
 * to do with each finding — print, surface as JSON, short-circuit, etc.
 *
 * Steps must NOT print anything themselves. Reporting is the caller's
 * job; that boundary keeps steps pure and unit-testable.
 */
import type { AnalysisResult } from '../analysis/analyzer'
import type { DiffResult } from '../analysis/diffing'
import type { LockfileAuditResult } from '../analysis/lockfile'
import type { NpmAuditResult } from '../analysis/npm-audit'
import type { ReputationSummary } from '../analysis/reputation'
import type { SymlinkAuditResult } from '../analysis/symlinks'
import type { TyposquatResult } from '../analysis/typosquat'
import type { MaintainerInfo } from '../network/maintainer'
import type { ThreatIntelResult } from '../network/threatintel'
import type { InstallOptions, PackageScript } from '../types'

export interface AnalysisContext {
  cwd: string
  nodeModulesPath: string
  /** All package names found under node_modules (flat + scoped). */
  allPackageNames: string[]
  /** Packages that declared an install script. May be empty. */
  scripts: PackageScript[]
  opts: InstallOptions
}

/** Discriminated union of every result a Step can produce. */
export type Finding =
  | { kind: 'typosquats';    results: TyposquatResult[] }
  | { kind: 'lockfile';      result: LockfileAuditResult }
  | { kind: 'reputation';    summary: ReputationSummary }
  | { kind: 'npm-audit';     result: NpmAuditResult }
  | { kind: 'symlinks';      result: SymlinkAuditResult }
  | { kind: 'analysis';      results: AnalysisResult[] }
  | { kind: 'diffs';         results: DiffResult[] }
  | { kind: 'threat-intel';  results: ThreatIntelResult[] }
  | { kind: 'maintainers';   results: MaintainerInfo[] }

export type FindingKind = Finding['kind']

/** Type-safe extraction: pick the Finding variant for a given kind. */
export type FindingOf<K extends FindingKind> = Extract<Finding, { kind: K }>

export interface Step<F extends Finding = Finding> {
  /** Stable identifier — used in tests and audit logs, never shown to users. */
  readonly name: string
  /** Returns false to skip this step for the given options. */
  enabled(opts: InstallOptions): boolean
  /** Pure-ish: may hit network/disk, but must not write to stdout/stderr. */
  run(ctx: AnalysisContext): Promise<F> | F
}
