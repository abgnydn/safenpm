import { describe, expect, it } from 'vitest'
import type { TyposquatResult } from '../analysis/typosquat'
import type { SandboxResult } from '../types'
import { generateFixes, previewFixes } from './autofix'

function typo(suspect: string, target: string, confidence: TyposquatResult['confidence']): TyposquatResult {
  return { suspect, target, distance: 1, technique: 'edit-distance-1', confidence }
}

function blocked(name: string, version: string, reason: SandboxResult['reason']): SandboxResult {
  return {
    pkg: { name, version, hook: 'postinstall', script: '', path: '' },
    blocked: true, skipped: false, reason,
    output: '', durationMs: 0,
  }
}

describe('generateFixes — typosquat replacements', () => {
  it('emits a replace-typosquat for high-confidence findings', () => {
    const fixes = generateFixes([typo('axois', 'axios', 'high')], [])
    expect(fixes).toHaveLength(1)
    expect(fixes[0]?.type).toBe('replace-typosquat')
    expect(fixes[0]?.replacement).toBe('axios')
  })

  it('emits a replace-typosquat for medium-confidence findings too', () => {
    const fixes = generateFixes([typo('lodahs', 'lodash', 'medium')], [])
    expect(fixes).toHaveLength(1)
    expect(fixes[0]?.type).toBe('replace-typosquat')
  })

  it('skips low-confidence findings to avoid acting on false positives', () => {
    const fixes = generateFixes([typo('something', 'react', 'low')], [])
    expect(fixes).toHaveLength(0)
  })
})

describe('generateFixes — blocked malicious removals', () => {
  it('emits remove-malicious for network blocks', () => {
    const fixes = generateFixes([], [blocked('phone-home', '0.0.1', 'network')])
    expect(fixes).toHaveLength(1)
    expect(fixes[0]?.type).toBe('remove-malicious')
    expect(fixes[0]?.replacement).toBeNull()
  })

  it('emits remove-malicious for filesystem blocks', () => {
    const fixes = generateFixes([], [blocked('scan-fs', '1.0.0', 'filesystem')])
    expect(fixes[0]?.type).toBe('remove-malicious')
  })

  it('ignores blocks with reasons other than network/filesystem', () => {
    // e.g. a non-zero exit that wasn't a network/fs block — don't auto-remove.
    const fixes = generateFixes([], [blocked('legit-build', '1.0.0', 'exit-code-1')])
    expect(fixes).toHaveLength(0)
  })
})

describe('previewFixes', () => {
  it('renders both shapes in a single pass', () => {
    const fixes = generateFixes(
      [typo('axois', 'axios', 'high')],
      [blocked('phone-home', '0.0.1', 'network')],
    )
    const preview = previewFixes(fixes)
    expect(preview).toEqual([
      'replace axois → axios',
      'remove phone-home@0.0.1',
    ])
  })
})
