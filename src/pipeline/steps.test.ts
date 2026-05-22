import { describe, expect, it } from 'vitest'
import {
  PRE_SCRIPT_STEPS,
  POST_SCRIPT_STEPS,
  typosquatStep,
  lockfileStep,
  reputationStep,
  npmAuditStep,
  symlinkStep,
  analysisStep,
  diffStep,
  threatIntelStep,
  maintainerStep,
} from './steps'
import type { AnalysisContext } from './types'
import type { InstallOptions } from '../types'

const baseOpts: InstallOptions = {
  packages: [], dryRun: false, allow: [], noReport: false,
  json: false, interactive: false, loose: false, scan: false,
}

const ctx: AnalysisContext = {
  cwd: '/tmp/none-existent-pipeline-test',
  nodeModulesPath: '/tmp/none-existent-pipeline-test/node_modules',
  allPackageNames: [],
  scripts: [],
  opts: baseOpts,
}

describe('pipeline step lists', () => {
  it('PRE_SCRIPT_STEPS leads with the always-on symlink audit then the --scan-only checks', () => {
    expect(PRE_SCRIPT_STEPS.map((s) => s.name)).toEqual([
      'symlinks', 'typosquats', 'lockfile', 'reputation', 'npm-audit',
    ])
  })

  it('POST_SCRIPT_STEPS includes analysis / behavior-diff / threat-intel / maintainers (in order)', () => {
    expect(POST_SCRIPT_STEPS.map((s) => s.name)).toEqual([
      'analysis', 'behavior-diff', 'threat-intel', 'maintainers',
    ])
  })
})

describe('step.enabled gating', () => {
  it('scan-only steps are gated off when opts.scan is false', () => {
    for (const step of [typosquatStep, lockfileStep, reputationStep, npmAuditStep, diffStep, maintainerStep]) {
      expect(step.enabled({ ...baseOpts, scan: false })).toBe(false)
      expect(step.enabled({ ...baseOpts, scan: true })).toBe(true)
    }
  })

  it('analysis + threat-intel + symlink always run regardless of --scan', () => {
    expect(analysisStep.enabled({ ...baseOpts, scan: false })).toBe(true)
    expect(threatIntelStep.enabled({ ...baseOpts, scan: false })).toBe(true)
    expect(symlinkStep.enabled({ ...baseOpts, scan: false })).toBe(true)
    expect(analysisStep.enabled({ ...baseOpts, scan: true })).toBe(true)
    expect(threatIntelStep.enabled({ ...baseOpts, scan: true })).toBe(true)
    expect(symlinkStep.enabled({ ...baseOpts, scan: true })).toBe(true)
  })
})

describe('step.run shape', () => {
  it('typosquatStep emits { kind: "typosquats", results: [] } on an empty package list', () => {
    const r = typosquatStep.run(ctx)
    expect(r.kind).toBe('typosquats')
    expect(Array.isArray(r.results)).toBe(true)
  })

  it('lockfileStep emits { kind: "lockfile", result } even when no lockfile exists', () => {
    const r = lockfileStep.run(ctx)
    expect(r.kind).toBe('lockfile')
    expect(r.result.exists).toBe(false)
  })

  it('reputationStep emits { kind: "reputation", summary } on an empty node_modules', () => {
    const r = reputationStep.run(ctx)
    expect(r.kind).toBe('reputation')
    expect(r.summary.totalPackages).toBe(0)
  })

  it('analysisStep emits { kind: "analysis", results: [] } when there are no scripts', () => {
    const r = analysisStep.run(ctx)
    expect(r.kind).toBe('analysis')
    expect(r.results).toEqual([])
  })
})
