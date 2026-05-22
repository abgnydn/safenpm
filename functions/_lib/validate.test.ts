import { describe, expect, it } from 'vitest'
import {
  parseSignal,
  parseIntelQuery,
  parseFlaggedEntry,
  PACKAGE_NAME_RE,
} from './validate'

describe('parseSignal', () => {
  const valid = {
    machineId: 'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d',
    package: 'evil-pkg',
    version: '1.0.0',
    hook: 'postinstall',
    script: 'curl evil.com',
    scriptHash: 'a'.repeat(32),
    scriptLength: 12,
    reason: 'network access',
    timestamp: '2026-05-21T10:00:00.000Z',
    platform: 'darwin',
  }

  it('accepts a well-formed signal', () => {
    expect(parseSignal(valid)).toEqual(valid)
  })

  it('rejects non-object bodies', () => {
    expect(parseSignal(null)).toBeNull()
    expect(parseSignal('string')).toBeNull()
    expect(parseSignal(42)).toBeNull()
  })

  it('rejects invalid package names', () => {
    expect(parseSignal({ ...valid, package: 'NotLowerCase' })).toBeNull()
    expect(parseSignal({ ...valid, package: '' })).toBeNull()
    expect(parseSignal({ ...valid, package: 'a'.repeat(215) })).toBeNull()
  })

  it('rejects unknown reasons', () => {
    expect(parseSignal({ ...valid, reason: 'made-up-reason' })).toBeNull()
  })

  it('rejects too-short or non-hex scriptHash', () => {
    expect(parseSignal({ ...valid, scriptHash: 'short' })).toBeNull()
    expect(parseSignal({ ...valid, scriptHash: 'g'.repeat(32) })).toBeNull()
  })

  it('falls back to anonymous machineId and unknown hook/platform', () => {
    const r = parseSignal({
      ...valid,
      machineId: undefined,
      hook: undefined,
      platform: undefined,
    })!
    expect(r.machineId).toBe('anonymous')
    expect(r.hook).toBe('unknown')
    expect(r.platform).toBe('unknown')
  })

  it('accepts the literal "anonymous" machineId', () => {
    expect(parseSignal({ ...valid, machineId: 'anonymous' })?.machineId).toBe('anonymous')
  })

  it('rejects machineId shorter than the entropy floor (Sybil resistance)', () => {
    expect(parseSignal({ ...valid, machineId: 'm-abc' })).toBeNull()
    expect(parseSignal({ ...valid, machineId: 'a' })).toBeNull()
    expect(parseSignal({ ...valid, machineId: '123456789012345' })).toBeNull() // 15 chars
  })

  it('rejects machineId with disallowed characters', () => {
    expect(parseSignal({ ...valid, machineId: 'a/'.repeat(10) })).toBeNull()
    expect(parseSignal({ ...valid, machineId: 'a ' + 'b'.repeat(20) })).toBeNull()
    expect(parseSignal({ ...valid, machineId: 'a;rm -rf /' + 'b'.repeat(20) })).toBeNull()
  })

  it('rejects machineId longer than 64 chars', () => {
    expect(parseSignal({ ...valid, machineId: 'a'.repeat(65) })).toBeNull()
  })

  it('truncates script preview to 500 chars', () => {
    const r = parseSignal({ ...valid, script: 'x'.repeat(1000) })!
    expect(r.script.length).toBe(500)
  })

  it('accepts scoped package names', () => {
    expect(parseSignal({ ...valid, package: '@foo/bar' })).not.toBeNull()
  })
})

describe('parseIntelQuery', () => {
  it('accepts a well-formed query', () => {
    const r = parseIntelQuery({ packages: [{ name: 'a', version: '1' }] })!
    expect(r.packages).toHaveLength(1)
  })

  it('rejects batches over the 500-package cap', () => {
    const big = { packages: Array.from({ length: 501 }, () => ({ name: 'x', version: '1' })) }
    expect(parseIntelQuery(big)).toBeNull()
  })

  it('rejects packages missing name or version', () => {
    expect(parseIntelQuery({ packages: [{ name: 'a' }] })).toBeNull()
    expect(parseIntelQuery({ packages: [{ version: '1' }] })).toBeNull()
  })

  it('rejects non-array packages field', () => {
    expect(parseIntelQuery({ packages: 'nope' })).toBeNull()
    expect(parseIntelQuery({})).toBeNull()
  })
})

describe('parseFlaggedEntry', () => {
  const full = {
    reportCount: 5,
    distinctReporters: 3,
    reasons: { 'network access': 3, 'eval/obfuscation': 2 },
    firstSeen: '2026-05-01T00:00:00Z',
    lastSeen: '2026-05-21T00:00:00Z',
    scriptHash: 'a'.repeat(32),
    scriptHashes: ['a'.repeat(32), 'b'.repeat(32)],
    platforms: { darwin: 3, linux: 2 },
  }

  it('parses a string-encoded entry', () => {
    expect(parseFlaggedEntry(JSON.stringify(full))).toEqual(full)
  })

  it('parses a pre-parsed object', () => {
    expect(parseFlaggedEntry(full)).toEqual(full)
  })

  it('returns null on invalid JSON', () => {
    expect(parseFlaggedEntry('{not json')).toBeNull()
  })

  it('returns null on missing reasons/platforms', () => {
    expect(parseFlaggedEntry({ ...full, reasons: 'nope' })).toBeNull()
    expect(parseFlaggedEntry({ ...full, platforms: null })).toBeNull()
  })

  it('synthesizes scriptHashes from scriptHash for legacy entries', () => {
    const legacy = { ...full, scriptHashes: undefined }
    const r = parseFlaggedEntry(legacy)!
    expect(r.scriptHashes).toEqual([full.scriptHash])
  })

  it('falls back distinctReporters to reportCount when absent', () => {
    const r = parseFlaggedEntry({ ...full, distinctReporters: undefined })!
    expect(r.distinctReporters).toBe(full.reportCount)
  })
})

describe('PACKAGE_NAME_RE', () => {
  it('accepts conventional npm names', () => {
    expect(PACKAGE_NAME_RE.test('lodash')).toBe(true)
    expect(PACKAGE_NAME_RE.test('foo-bar')).toBe(true)
    expect(PACKAGE_NAME_RE.test('@scope/pkg')).toBe(true)
  })
  it('rejects uppercase, dots-leading, or empty', () => {
    expect(PACKAGE_NAME_RE.test('Foo')).toBe(false)
    expect(PACKAGE_NAME_RE.test('.dotfile')).toBe(false)
    expect(PACKAGE_NAME_RE.test('')).toBe(false)
  })
})
