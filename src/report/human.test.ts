/**
 * Unit tests for the human (terminal) Reporter. The golden snapshots
 * cover end-to-end CLI output, but they only fire on a handful of
 * fixture scenarios. These tests pin individual reporter methods so
 * that subtle plural/severity/empty-set bugs surface immediately
 * rather than "somewhere in the next 24-fixture re-capture".
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createHumanReporter } from './human'

function strip(s: string): string {
  // Remove ANSI escape sequences so assertions can match on raw text.
  return s.replace(/\x1b\[[0-9;]*m/g, '')
}

let out: string[]
let reporter: ReturnType<typeof createHumanReporter>

beforeEach(() => {
  out = []
  vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
    out.push(args.join(' '))
  })
  reporter = createHumanReporter()
})

afterEach(() => {
  vi.restoreAllMocks()
})

const stripped = () => out.map(strip).join('\n')

describe('banner / blank / step / micro-events', () => {
  it('banner prints the safenpm wordmark surrounded by blank lines', () => {
    reporter.banner()
    expect(out[0]).toBe('')
    expect(strip(out[1] ?? '')).toMatch(/safenpm.*sandboxed installs/)
    expect(out[2]).toBe('')
  })

  it('dryRunBanner differs from banner in the subtitle', () => {
    reporter.dryRunBanner()
    expect(strip(out.join('\n'))).toMatch(/dry run \(no scripts will be executed\)/)
  })

  it('step / info / success / warn / error each emit one line', () => {
    reporter.step('one')
    reporter.info('two')
    reporter.success('three')
    reporter.warn('four')
    reporter.error('five')
    expect(out.map(strip)).toEqual([
      '  → one',
      '  two',
      '  ✓ three',
      '  ⚠  four',
      '  ✕ five',
    ])
  })
})

describe('allowlistInfo plural handling', () => {
  it('says "1 package whitelisted" (singular) for count=1', () => {
    reporter.allowlistInfo(1)
    expect(strip(out[0]!)).toMatch(/allowlist: 1 package whitelisted/)
  })

  it('says "3 packages whitelisted" (plural) for count=3', () => {
    reporter.allowlistInfo(3)
    expect(strip(out[0]!)).toMatch(/allowlist: 3 packages whitelisted/)
  })

  it('emits nothing when count=0', () => {
    reporter.allowlistInfo(0)
    expect(out).toHaveLength(0)
  })
})

describe('per-package outcomes', () => {
  it('allowed → "✓ clean"', () => {
    reporter.allowed('lodash', '4.17.21')
    expect(strip(out[0]!)).toBe('  ✓ clean   lodash@4.17.21')
  })

  it('skipped → "↳ allow ... (allowlisted)"', () => {
    reporter.skipped('bcrypt', '5.0.0')
    expect(strip(out[0]!)).toMatch(/↳ allow.*bcrypt@5\.0\.0.*allowlisted/)
  })

  it('blocked renders package, hook, reason, signal note', () => {
    reporter.blocked('phone-home', '0.0.1', 'postinstall', 'network')
    const text = stripped()
    expect(text).toMatch(/✕ blocked.*phone-home@0\.0\.1/)
    expect(text).toMatch(/hook:\s+postinstall/)
    expect(text).toMatch(/reason:\s+attempted network access/)
    expect(text).toMatch(/signal: reported anonymously/)
  })

  it('blocked maps "filesystem" reason to the right human phrase', () => {
    reporter.blocked('snoop', '1.0.0', 'postinstall', 'filesystem')
    expect(stripped()).toMatch(/attempted to access restricted files/)
  })

  it('blocked falls back to "script exited with error (X)" for unknown reasons', () => {
    reporter.blocked('weird', '1.0.0', 'install', 'exit-code-1')
    expect(stripped()).toMatch(/script exited with error \(exit-code-1\)/)
  })
})

describe('summary plural / breakdown formatting', () => {
  it('all clear for a 1-script run', () => {
    reporter.summary(1, 0)
    expect(stripped()).toMatch(/all clear — 1 script processed/)
  })

  it('"scripts" plural when total > 1', () => {
    reporter.summary(5, 0)
    expect(stripped()).toMatch(/5 scripts processed/)
  })

  it('renders a breakdown including blocked / allowlisted / clean / warnings counts', () => {
    reporter.summary(5, 1, 1, 1)
    const text = stripped()
    expect(text).toMatch(/1 blocked out of 5 install scripts/)
    expect(text).toMatch(/breakdown:.*1 blocked.*1 allowlisted.*3 clean.*1 warnings/s)
    expect(text).toMatch(/signals reported to safenpm network/)
  })
})

describe('collection section headers + bodies', () => {
  it('typosquatHeader followed by typosquatResult emits one entry block', () => {
    reporter.typosquatHeader()
    reporter.typosquatResult({
      suspect: 'axois', target: 'axios', distance: 1,
      technique: 'char-swap', confidence: 'high',
    })
    expect(stripped()).toMatch(/typosquat detection/)
    expect(stripped()).toMatch(/axois.*looks like.*axios/)
    expect(stripped()).toMatch(/technique: char-swap.*distance: 1.*confidence: high/)
  })

  it('lockfileResult on a missing lockfile prints the "no package-lock.json" warning', () => {
    reporter.lockfileHeader()
    reporter.lockfileResult({
      exists: false, format: null, totalPackages: 0, issues: [], score: 50,
    })
    expect(stripped()).toMatch(/no package-lock\.json found/)
  })

  it('threatIntelResult skips entries with flagged=false', () => {
    reporter.threatIntelResult({
      name: 'safe', version: '1.0.0',
      flagged: false, reportCount: 0,
      firstSeen: null, lastSeen: null,
      topReasons: [], dataFresh: true,
    })
    expect(out).toEqual([])
  })

  it('threatIntelResult on a flagged package prints a COMMUNITY ALERT', () => {
    reporter.threatIntelResult({
      name: 'evil-pkg', version: '0.0.1',
      flagged: true, reportCount: 47,
      firstSeen: '2026-03-28T00:00:00Z',
      lastSeen: new Date().toISOString(),
      topReasons: ['credential exfiltration', 'network access'],
      dataFresh: true,
    })
    const text = stripped()
    expect(text).toMatch(/COMMUNITY ALERT\s+evil-pkg@0\.0\.1/)
    expect(text).toMatch(/47 reports from other developers/)
    expect(text).toMatch(/top reason: credential exfiltration/)
  })

  it('maintainerResult skips entries with maintainerChanged=false', () => {
    reporter.maintainerResult({
      name: 'stable', version: '1.0.0',
      currentPublisher: 'alice', previousPublisher: 'alice',
      maintainerChanged: false, isNewPackage: false,
      publisherHistory: ['alice'], accountAge: null,
    })
    expect(out).toEqual([])
  })

  it('analysisResult renders severity-tagged warnings', () => {
    reporter.analysisResult({
      pkg: { name: 'x', version: '1.0.0', hook: 'postinstall', script: '', path: '' },
      riskScore: 70,
      warnings: [
        { rule: 'NETWORK_ACCESS', description: 'curl found', severity: 'high' },
        { rule: 'EVAL', description: 'eval()', severity: 'medium' },
      ],
    })
    const text = stripped()
    expect(text).toMatch(/x@1\.0\.0.*risk: 70\/100/)
    expect(text).toMatch(/HIGH.*curl found/)
    expect(text).toMatch(/MEDIUM.*eval\(\)/)
  })
})

describe('npm audit rendering', () => {
  it('prints "no known advisories" for an empty result that ran', () => {
    reporter.npmAuditResult({
      ran: true, total: 0,
      totals: { info: 0, low: 0, moderate: 0, high: 0, critical: 0 },
      vulnerabilities: [],
    })
    expect(stripped()).toMatch(/no known advisories/)
  })

  it('prints an unavailable note when the audit could not run', () => {
    reporter.npmAuditResult({
      ran: false, total: 0,
      totals: { info: 0, low: 0, moderate: 0, high: 0, critical: 0 },
      vulnerabilities: [],
    })
    expect(stripped()).toMatch(/npm audit unavailable/)
  })

  it('lists up to 5 advisories with severity, range, and fix availability', () => {
    reporter.npmAuditResult({
      ran: true, total: 7,
      totals: { info: 0, low: 1, moderate: 1, high: 2, critical: 3 },
      vulnerabilities: Array.from({ length: 7 }, (_, i) => ({
        name: `pkg-${i}`,
        severity: 'high' as const,
        range: '<1.0.0', via: [],
        fixAvailable: i % 2 === 0,
      })),
    })
    const text = stripped()
    expect(text).toMatch(/7 advisories/)
    expect(text).toMatch(/and 2 more — run `npm audit`/)
    expect(text).toMatch(/HIGH\s+pkg-0/)
    expect(text).toMatch(/fix available/)
    expect(text).toMatch(/no fix available/)
  })
})
