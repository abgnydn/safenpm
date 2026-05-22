import { describe, expect, it } from 'vitest'
import { shapeAuditReport } from './npm-audit'

describe('shapeAuditReport — v2 wire format', () => {
  it('returns ran=false on a non-object / null input', () => {
    expect(shapeAuditReport(null).ran).toBe(false)
    expect(shapeAuditReport('not an object').ran).toBe(false)
    expect(shapeAuditReport(42).ran).toBe(false)
  })

  it('parses an empty vulnerabilities map as ran=true / total=0', () => {
    const r = shapeAuditReport({
      auditReportVersion: 2,
      vulnerabilities: {},
      metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 } },
    })
    expect(r.ran).toBe(true)
    expect(r.total).toBe(0)
    expect(r.vulnerabilities).toEqual([])
  })

  it('parses a populated v2 report and sorts critical/high first', () => {
    const r = shapeAuditReport({
      auditReportVersion: 2,
      vulnerabilities: {
        'lodash': {
          name: 'lodash', severity: 'high',
          via: ['CVE-2020-8203'],
          range: '<4.17.20',
          fixAvailable: true,
        },
        'tar': {
          name: 'tar', severity: 'critical',
          via: [{ name: 'tar', source: 1234 }],
          range: '<6.1.9',
          fixAvailable: false,
        },
        'minimist': {
          name: 'minimist', severity: 'low',
          via: [],
          range: '<1.2.6',
          fixAvailable: true,
        },
      },
      metadata: { vulnerabilities: { info: 0, low: 1, moderate: 0, high: 1, critical: 1 } },
    })
    expect(r.ran).toBe(true)
    expect(r.total).toBe(3)
    expect(r.totals).toEqual({ info: 0, low: 1, moderate: 0, high: 1, critical: 1 })
    // sorted: critical → high → low
    expect(r.vulnerabilities.map((v) => v.name)).toEqual(['tar', 'lodash', 'minimist'])
    expect(r.vulnerabilities[0]?.fixAvailable).toBe(false)
    expect(r.vulnerabilities[1]?.fixAvailable).toBe(true)
  })

  it('extracts via names from both string and object shapes', () => {
    const r = shapeAuditReport({
      auditReportVersion: 2,
      vulnerabilities: {
        'foo': {
          severity: 'moderate',
          via: ['advisory-id', { name: 'upstream-pkg' }, { not_a_name: 'ignored' }],
          range: '*', fixAvailable: false,
        },
      },
    })
    expect(r.vulnerabilities[0]?.via).toEqual(['advisory-id', 'upstream-pkg'])
  })

  it('drops entries with unrecognised severities', () => {
    const r = shapeAuditReport({
      auditReportVersion: 2,
      vulnerabilities: {
        'good':   { severity: 'high',  via: [], range: '<1', fixAvailable: false },
        'bogus':  { severity: 'invalid', via: [], range: '<1', fixAvailable: false },
      },
    })
    expect(r.vulnerabilities.map((v) => v.name)).toEqual(['good'])
  })

  it('falls back to totals from the vulnerability list when metadata is missing', () => {
    const r = shapeAuditReport({
      auditReportVersion: 2,
      vulnerabilities: {
        'a': { severity: 'high',     via: [], range: '<1', fixAvailable: false },
        'b': { severity: 'high',     via: [], range: '<1', fixAvailable: false },
        'c': { severity: 'moderate', via: [], range: '<1', fixAvailable: false },
      },
      // no metadata
    })
    expect(r.totals).toEqual({ info: 0, low: 0, moderate: 1, high: 2, critical: 0 })
  })
})
