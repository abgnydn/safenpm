import { describe, expect, it } from 'vitest'
import { byKind, runPipeline } from './runner'
import type { AnalysisContext, Finding, Step } from './types'
import type { InstallOptions } from '../types'

const opts = (over: Partial<InstallOptions> = {}): InstallOptions => ({
  packages: [],
  dryRun: false,
  allow: [],
  noReport: false,
  json: false,
  interactive: false,
  loose: false,
  scan: false,
  ...over,
})

const ctx = (overrides: Partial<AnalysisContext> = {}): AnalysisContext => ({
  cwd: '/tmp/proj',
  nodeModulesPath: '/tmp/proj/node_modules',
  allPackageNames: [],
  scripts: [],
  opts: opts(),
  ...overrides,
})

const typoStep: Step = {
  name: 'typosquats',
  enabled: (o) => o.scan,
  run: () => ({ kind: 'typosquats', results: [] }),
}

const analysisStep: Step = {
  name: 'analysis',
  enabled: () => true,
  run: () => ({ kind: 'analysis', results: [] }),
}

describe('runPipeline', () => {
  it('skips disabled steps', async () => {
    const findings = await runPipeline([typoStep, analysisStep], ctx({ opts: opts({ scan: false }) }))
    expect(findings.map((f) => f.kind)).toEqual(['analysis'])
  })

  it('runs steps in declaration order', async () => {
    const seen: string[] = []
    const a: Step = {
      name: 'a', enabled: () => true,
      run: () => { seen.push('a'); return { kind: 'typosquats', results: [] } },
    }
    const b: Step = {
      name: 'b', enabled: () => true,
      run: () => { seen.push('b'); return { kind: 'analysis', results: [] } },
    }
    await runPipeline([a, b], ctx())
    expect(seen).toEqual(['a', 'b'])
  })

  it('awaits async run', async () => {
    const step: Step = {
      name: 'slow', enabled: () => true,
      run: () => new Promise<Finding>((r) => setImmediate(() => r({ kind: 'analysis', results: [] }))),
    }
    const findings = await runPipeline([step], ctx())
    expect(findings).toHaveLength(1)
    expect(findings[0]!.kind).toBe('analysis')
  })
})

describe('byKind', () => {
  it('extracts the matching finding by kind', () => {
    const findings: Finding[] = [
      { kind: 'typosquats', results: [] },
      { kind: 'analysis', results: [] },
    ]
    expect(byKind(findings, 'analysis')?.kind).toBe('analysis')
  })

  it('returns undefined when no finding matches', () => {
    const findings: Finding[] = [{ kind: 'analysis', results: [] }]
    expect(byKind(findings, 'typosquats')).toBeUndefined()
  })

  it('narrows the type so consumers can access kind-specific fields', () => {
    const findings: Finding[] = [{ kind: 'analysis', results: [] }]
    const a = byKind(findings, 'analysis')
    // Type-narrowing test — if this compiles, .results is the AnalysisResult[] field.
    expect(a?.results).toEqual([])
  })
})
