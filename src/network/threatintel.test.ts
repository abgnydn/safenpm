import { describe, expect, it } from 'vitest'
import { mockThreatIntel, parseIntelResponse } from './threatintel'

describe('mockThreatIntel', () => {
  it('returns one unflagged result per input package', () => {
    const r = mockThreatIntel([
      { name: 'lodash', version: '4.17.21' },
      { name: '@scope/pkg', version: '1.0.0' },
    ])
    expect(r).toHaveLength(2)
    expect(r.every((x) => !x.flagged)).toBe(true)
    expect(r[0]?.name).toBe('lodash')
  })

  it('returns an empty array on empty input', () => {
    expect(mockThreatIntel([])).toEqual([])
  })
})

describe('parseIntelResponse — happy path', () => {
  it('parses a well-formed response and zips it against the request', () => {
    const body = JSON.stringify({
      results: [{
        name: 'evil-pkg', version: '0.0.1',
        flagged: true, reportCount: 47,
        firstSeen: '2026-03-28T00:00:00Z',
        lastSeen: '2026-05-21T00:00:00Z',
        topReasons: ['credential exfiltration', 'network access'],
      }],
    })
    const r = parseIntelResponse(body, [{ name: 'evil-pkg', version: '0.0.1' }])
    expect(r).not.toBeNull()
    expect(r![0]?.flagged).toBe(true)
    expect(r![0]?.reportCount).toBe(47)
    expect(r![0]?.topReasons).toEqual(['credential exfiltration', 'network access'])
  })

  it('fills missing entries with unflagged so the result length matches the request', () => {
    const body = JSON.stringify({
      results: [{ name: 'present', version: '1.0.0', flagged: false }],
    })
    const r = parseIntelResponse(body, [
      { name: 'present', version: '1.0.0' },
      { name: 'absent',  version: '2.0.0' },
    ])
    expect(r).not.toBeNull()
    expect(r).toHaveLength(2)
    expect(r![1]?.name).toBe('absent')
    expect(r![1]?.flagged).toBe(false)
  })
})

describe('parseIntelResponse — resilience', () => {
  it('returns null on invalid JSON', () => {
    expect(parseIntelResponse('{not json', [])).toBeNull()
  })

  it('returns null when the body is not an object', () => {
    expect(parseIntelResponse('42', [])).toBeNull()
    expect(parseIntelResponse('"string"', [])).toBeNull()
  })

  it('returns null when results is not an array', () => {
    expect(parseIntelResponse('{"results": "nope"}', [])).toBeNull()
    expect(parseIntelResponse('{"no_results_field": true}', [])).toBeNull()
  })

  it('drops malformed entries instead of corrupting the output', () => {
    const body = JSON.stringify({
      results: [
        { name: 'good', version: '1.0.0', flagged: true, reportCount: 5 },
        { name: 'bad-no-version' }, // missing version
        { /* totally empty */ },
        null,
        'string',
      ],
    })
    const r = parseIntelResponse(body, [{ name: 'good', version: '1.0.0' }])
    expect(r).not.toBeNull()
    expect(r).toHaveLength(1)
    expect(r![0]?.name).toBe('good')
    expect(r![0]?.flagged).toBe(true)
  })

  it('never trusts non-number reportCount or non-string firstSeen/lastSeen', () => {
    const body = JSON.stringify({
      results: [{
        name: 'a', version: '1', flagged: true,
        reportCount: 'lots',           // wrong type
        firstSeen: 42,                  // wrong type
        lastSeen: null,                 // null is acceptable as "unknown"
        topReasons: ['ok', 42, null],   // mixed: only strings should pass
      }],
    })
    const r = parseIntelResponse(body, [{ name: 'a', version: '1' }])!
    expect(r[0]?.reportCount).toBe(0)
    expect(r[0]?.firstSeen).toBeNull()
    expect(r[0]?.lastSeen).toBeNull()
    expect(r[0]?.topReasons).toEqual(['ok'])
  })
})
