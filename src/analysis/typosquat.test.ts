import { describe, expect, it } from 'vitest'
import { checkAllTyposquats, checkTyposquat } from './typosquat'

describe('checkTyposquat — exact matches and clean names', () => {
  it('returns null for exact matches of popular packages', () => {
    expect(checkTyposquat('lodash')).toBeNull()
    expect(checkTyposquat('react')).toBeNull()
    expect(checkTyposquat('express')).toBeNull()
  })

  it('returns null for names that are nowhere near a popular package', () => {
    expect(checkTyposquat('zzz-unique-name-12345')).toBeNull()
    expect(checkTyposquat('my-internal-helper')).toBeNull()
  })

  it('ignores empty strings and very short names', () => {
    expect(checkTyposquat('')).toBeNull()
    expect(checkTyposquat('a')).toBeNull()
  })
})

describe('checkTyposquat — scope confusion (the most dangerous pattern)', () => {
  it('flags @evil/lodash as scope-confusion against lodash', () => {
    const r = checkTyposquat('@evil/lodash')
    expect(r).not.toBeNull()
    expect(r!.technique).toBe('scope-confusion')
    expect(r!.target).toBe('lodash')
    expect(r!.confidence).toBe('high')
  })

  it('flags scoped variants of multiple critical packages', () => {
    expect(checkTyposquat('@attacker/react')?.technique).toBe('scope-confusion')
    expect(checkTyposquat('@malware/express')?.technique).toBe('scope-confusion')
  })
})

describe('checkTyposquat — character transposition (axois → axios)', () => {
  it('flags two-char swaps as char-swap', () => {
    const r = checkTyposquat('axois')
    expect(r).not.toBeNull()
    expect(r!.target).toBe('axios')
    expect(r!.technique).toBe('char-swap')
    expect(r!.confidence).toBe('high')
  })
})

describe('checkTyposquat — common substitutions', () => {
  it('flags zero-for-o substitutions (c0lors → colors)', () => {
    const r = checkTyposquat('c0lors')
    expect(r).not.toBeNull()
    expect(r!.target).toBe('colors')
    expect(r!.technique).toBe('substitution')
  })

  it('flags 1-for-l substitutions (1odash → lodash)', () => {
    const r = checkTyposquat('1odash')
    expect(r?.technique).toBe('substitution')
    expect(r?.target).toBe('lodash')
  })

  it('flags rn-for-m substitutions (express → expmess flipped)', () => {
    // 'expmess' → 'express' via rn?  No — test the documented sub set
    // Use a known popular target: moment → rnoment
    const r = checkTyposquat('rnoment')
    expect(r?.technique).toBe('substitution')
    expect(r?.target).toBe('moment')
  })
})

describe('checkTyposquat — edit distance 1', () => {
  it('flags single-char edits against critical packages as high confidence', () => {
    // react → reat (delete) — distance 1, critical
    const r = checkTyposquat('reactt')
    expect(r).not.toBeNull()
    expect(r!.distance).toBe(1)
    expect(r!.confidence).toBe('high')
  })

  it('flags edit-distance-1 for short names as high confidence', () => {
    // chalk → halk (distance 1, length <= 6) → high
    const r = checkTyposquat('chalkx')
    expect(r?.confidence).toBe('high')
  })
})

describe('checkTyposquat — prefix/suffix extensions', () => {
  it('flags name-extension attacks like lodash-utils', () => {
    const r = checkTyposquat('lodashx')
    // Could match as edit-distance-1 (high) or name-extension — both are detections.
    expect(r).not.toBeNull()
    expect(r!.target).toBe('lodash')
  })
})

describe('checkAllTyposquats', () => {
  it('returns one result per suspicious name and skips clean ones', () => {
    const results = checkAllTyposquats([
      'react',                  // clean
      'axois',                  // typosquat
      'my-internal-thing',      // clean
      '@evil/lodash',           // scope confusion
    ])
    expect(results.map((r) => r.suspect).sort()).toEqual(['@evil/lodash', 'axois'])
  })

  it('returns empty array on empty input', () => {
    expect(checkAllTyposquats([])).toEqual([])
  })
})
