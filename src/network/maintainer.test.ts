import { describe, expect, it } from 'vitest'
import {
  extractMaintainerInfo,
  flaggedMaintainerChanges,
  mockMaintainerInfo,
  type MaintainerInfo,
} from './maintainer'

/**
 * Fixture mirroring the npm registry's "abbreviated metadata" shape
 * for a package with three versions published by two distinct
 * accounts — the second one being a publisher change after a long
 * gap, the kind of pattern that catches account takeovers.
 */
const registryFixture = {
  name: 'demo-pkg',
  versions: {
    '1.0.0': { _npmUser: { name: 'alice' } },
    '1.1.0': { _npmUser: { name: 'alice' } },
    '2.0.0': { _npmUser: { name: 'mallory' } },
  },
  time: {
    created:  '2024-01-01T00:00:00Z',
    modified: '2026-04-15T00:00:00Z',
    '1.0.0':  '2024-01-01T00:00:00Z',
    '1.1.0':  '2024-06-01T00:00:00Z',
    '2.0.0':  '2026-04-15T00:00:00Z',
  },
}

describe('extractMaintainerInfo', () => {
  it('flags a maintainer change when the publisher differs from the previous version', () => {
    const info = extractMaintainerInfo('demo-pkg', '2.0.0', registryFixture)
    expect(info.maintainerChanged).toBe(true)
    expect(info.currentPublisher).toBe('mallory')
    expect(info.previousPublisher).toBe('alice')
  })

  it('does not flag when the same person published the previous version', () => {
    const info = extractMaintainerInfo('demo-pkg', '1.1.0', registryFixture)
    expect(info.maintainerChanged).toBe(false)
    expect(info.currentPublisher).toBe('alice')
    expect(info.previousPublisher).toBe('alice')
  })

  it('does not mark the FIRST version of a multi-version package as a new package', () => {
    // isNewPackage reflects "the registry only knows one version of
    // this name", not "this is the first version of many". Querying
    // 1.0.0 of a package that already has 1.1.0 + 2.0.0 published
    // should return previousPublisher=null but isNewPackage=false.
    const info = extractMaintainerInfo('demo-pkg', '1.0.0', registryFixture)
    expect(info.isNewPackage).toBe(false)
    expect(info.previousPublisher).toBeNull()
  })

  it('marks a package with a single published version as new', () => {
    const onlyOne = {
      versions: { '1.0.0': { _npmUser: { name: 'alice' } } },
      time: { '1.0.0': '2024-01-01T00:00:00Z' },
    }
    const info = extractMaintainerInfo('only-one', '1.0.0', onlyOne)
    expect(info.isNewPackage).toBe(true)
  })

  it('returns null publishers when the requested version is not in the registry', () => {
    const info = extractMaintainerInfo('demo-pkg', '99.0.0', registryFixture)
    expect(info.currentPublisher).toBeNull()
    expect(info.previousPublisher).toBeNull()
    expect(info.maintainerChanged).toBe(false)
  })

  it('returns the distinct publisher history (last 10)', () => {
    const info = extractMaintainerInfo('demo-pkg', '2.0.0', registryFixture)
    expect(info.publisherHistory).toEqual(['alice', 'mallory'])
  })

  it('handles a registry with no versions or time data', () => {
    const info = extractMaintainerInfo('empty', '1.0.0', {})
    expect(info.currentPublisher).toBeNull()
    expect(info.publisherHistory).toEqual([])
  })

  it('skips versions whose _npmUser.name is missing', () => {
    const incomplete = {
      versions: {
        '1.0.0': { _npmUser: { name: 'alice' } },
        '2.0.0': { /* no _npmUser */ },
      },
      time: { '1.0.0': '2024-01-01T00:00:00Z', '2.0.0': '2024-02-01T00:00:00Z' },
    }
    const info = extractMaintainerInfo('x', '2.0.0', incomplete)
    expect(info.currentPublisher).toBeNull()
  })
})

describe('flaggedMaintainerChanges', () => {
  const make = (over: Partial<MaintainerInfo>): MaintainerInfo => ({
    name: 'x', version: '1.0.0',
    currentPublisher: null, previousPublisher: null,
    maintainerChanged: false, isNewPackage: false,
    publisherHistory: [], accountAge: null,
    ...over,
  })

  it('filters to entries where maintainerChanged=true', () => {
    const r = flaggedMaintainerChanges([
      make({ name: 'a', maintainerChanged: false }),
      make({ name: 'b', maintainerChanged: true }),
      make({ name: 'c', maintainerChanged: true }),
    ])
    expect(r.map((x) => x.name)).toEqual(['b', 'c'])
  })
})

describe('mockMaintainerInfo', () => {
  it('returns one unknown-info entry per input package', () => {
    const r = mockMaintainerInfo([
      { name: 'a', version: '1' },
      { name: 'b', version: '2' },
    ])
    expect(r).toHaveLength(2)
    expect(r.every((x) => !x.maintainerChanged)).toBe(true)
  })
})
