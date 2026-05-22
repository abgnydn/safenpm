/**
 * Reporter strategy — `safenpm` emits two output modes from the same
 * control flow:
 *
 *   - human  → coloured terminal output, section headers, summaries
 *   - json   → silent; the orchestrator assembles a single JSON
 *              payload at the end and prints it in one shot
 *
 * Every visual emit in install / scan / fix / diff / doctor goes
 * through this interface. The factory picks the implementation off
 * `opts.json`, so call sites stop writing `if (!opts.json) ...`
 * everywhere — the right thing happens by construction.
 *
 * Method names mirror the original `logger` 1:1. Each method emits
 * exactly what the released CLI does (golden snapshots enforce that),
 * so the JSON reporter is a literal no-op of the human version.
 */
import type { AnalysisResult } from '../analysis/analyzer'
import type { DiffResult } from '../analysis/diffing'
import type { LockfileAuditResult } from '../analysis/lockfile'
import type { NpmAuditResult } from '../analysis/npm-audit'
import type { ReputationSummary } from '../analysis/reputation'
import type { TyposquatResult } from '../analysis/typosquat'
import type { MaintainerInfo } from '../network/maintainer'
import type { ThreatIntelResult } from '../network/threatintel'
import { createHumanReporter } from './human'
import { createJsonReporter } from './json'

export interface Reporter {
  // banners ---------------------------------------------------------
  banner(): void
  dryRunBanner(): void

  // env metadata ----------------------------------------------------
  backendInfo(name: string): void
  allowlistInfo(count: number): void
  auditInfo(): void

  // micro-events ----------------------------------------------------
  step(msg: string): void
  info(msg: string): void
  success(msg: string): void
  warn(msg: string): void
  error(msg: string): void

  // per-package outcomes --------------------------------------------
  allowed(pkg: string, version: string): void
  blocked(pkg: string, version: string, hook: string, reason: string): void
  skipped(pkg: string, version: string): void
  dryRunItem(pkg: string, version: string, hook: string, script: string, isAllowed: boolean): void

  // section headers + result renderers (1:1 with the v1 logger) -----
  typosquatHeader(): void
  typosquatResult(r: TyposquatResult): void
  lockfileHeader(): void
  lockfileResult(r: LockfileAuditResult): void
  reputationHeader(): void
  reputationResult(s: ReputationSummary): void
  npmAuditHeader(): void
  npmAuditResult(r: NpmAuditResult): void
  symlinkHeader(): void
  symlinkResult(findings: ReadonlyArray<{ pkg: string; symlink: string; target: string; reason: string }>): void
  analysisHeader(): void
  analysisResult(r: AnalysisResult): void
  diffHeader(): void
  diffResult(d: DiffResult): void
  threatIntelHeader(): void
  threatIntelResult(r: ThreatIntelResult): void
  maintainerHeader(): void
  maintainerResult(m: MaintainerInfo): void

  // closing summary -------------------------------------------------
  summary(total: number, blocked: number, skipped?: number, warnings?: number): void

  // interactive — JSON reporter throws if called --------------------
  interactivePrompt(pkg: string, version: string, hook: string): string

  // raw blank line — call sites that previously called console.log()
  // for vertical-spacing should use this instead so JSON mode stays
  // silent without further guards.
  blank(): void
}

export function getReporter(opts: { json: boolean }): Reporter {
  return opts.json ? createJsonReporter() : createHumanReporter()
}
