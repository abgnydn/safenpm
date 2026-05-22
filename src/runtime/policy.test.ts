import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import fs from 'fs'
import os from 'os'
import path from 'path'
import {
  DEFAULT_DENY,
  POLICY_FILE,
  defaultPolicy,
  isAllowed,
  loadPolicy,
  normalizePolicy,
  policyFromTrace,
  savePolicy,
} from './policy'

let dir: string
beforeEach(() => {
  dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'safenpm-policy-')))
})
afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true })
})

describe('defaultPolicy', () => {
  it('contains the documented default-allow utilities (path, util, ...)', () => {
    const p = defaultPolicy()
    expect(p.defaultAllow).toContain('path')
    expect(p.defaultAllow).toContain('util')
    expect(p.defaultAllow).toContain('events')
    expect(p.defaultAllow).toContain('fs')
  })
  it('lists the dangerous-tier builtins as default-deny', () => {
    const p = defaultPolicy()
    expect(p.defaultDeny).toContain('child_process')
    expect(p.defaultDeny).toContain('https')
    expect(p.defaultDeny).toContain('net')
    expect(p.defaultDeny).toContain('vm')
    expect(p.defaultDeny).toContain('worker_threads')
  })
  it('starts with no per-package overrides', () => {
    expect(defaultPolicy().packages).toEqual({})
  })
})

describe('isAllowed — decision matrix', () => {
  const p = defaultPolicy()

  it('allows default-allow builtins for any package', () => {
    expect(isAllowed(p, 'anypkg', 'path')).toBe(true)
    expect(isAllowed(p, 'anypkg', 'util')).toBe(true)
    expect(isAllowed(p, 'anypkg', 'fs')).toBe(true)
  })

  it('denies default-deny builtins for any package without an explicit allow', () => {
    expect(isAllowed(p, 'anypkg', 'child_process')).toBe(false)
    expect(isAllowed(p, 'anypkg', 'https')).toBe(false)
    expect(isAllowed(p, 'anypkg', 'vm')).toBe(false)
  })

  it('per-package allow overrides default-deny', () => {
    const withBcrypt = { ...p, packages: { bcrypt: { allow: ['child_process'] } } }
    expect(isAllowed(withBcrypt, 'bcrypt', 'child_process')).toBe(true)
    // …but only for that specific package
    expect(isAllowed(withBcrypt, 'evil', 'child_process')).toBe(false)
  })

  it('per-package deny overrides default-allow', () => {
    const lockedDown = { ...p, packages: { suspicious: { deny: ['fs', 'crypto'] } } }
    expect(isAllowed(lockedDown, 'suspicious', 'fs')).toBe(false)
    expect(isAllowed(lockedDown, 'suspicious', 'crypto')).toBe(false)
    expect(isAllowed(lockedDown, 'someone-else', 'fs')).toBe(true)
  })

  it('per-package deny wins over per-package allow on the same builtin', () => {
    const conflict = { ...p, packages: { weird: { allow: ['vm'], deny: ['vm'] } } }
    expect(isAllowed(conflict, 'weird', 'vm')).toBe(false)
  })

  it('strips `node:` prefix before lookup', () => {
    expect(isAllowed(p, 'pkg', 'node:fs')).toBe(true)
    expect(isAllowed(p, 'pkg', 'node:child_process')).toBe(false)
  })

  it('unknown builtins default to allow (future Node releases never break installs)', () => {
    expect(isAllowed(p, 'pkg', 'totally_new_node_module_v25')).toBe(true)
  })
})

describe('normalizePolicy — defensive loading', () => {
  it('returns the default policy for non-object input', () => {
    expect(normalizePolicy(null)).toEqual(defaultPolicy())
    expect(normalizePolicy(42)).toEqual(defaultPolicy())
    expect(normalizePolicy('string')).toEqual(defaultPolicy())
  })
  it('drops malformed entries instead of crashing', () => {
    const r = normalizePolicy({
      defaultAllow: ['path', 42, 'fs'],         // non-string filtered out
      defaultDeny: 'not-an-array',              // wrong type → default
      packages: {
        'good': { allow: ['fs'] },
        'malformed': 'not-an-object',           // entry dropped
        'mixed': { allow: ['ok', 99], deny: ['vm'] },
      },
    })
    expect(r.defaultAllow).toEqual(['path', 'fs'])
    expect(r.defaultDeny).toEqual([...DEFAULT_DENY])
    expect(r.packages['good']).toEqual({ allow: ['fs'] })
    expect(r.packages['malformed']).toBeUndefined()
    expect(r.packages['mixed']?.allow).toEqual(['ok'])
    expect(r.packages['mixed']?.deny).toEqual(['vm'])
  })
})

describe('loadPolicy', () => {
  it('returns defaults when no file exists', () => {
    expect(loadPolicy(dir)).toEqual(defaultPolicy())
  })
  it('returns defaults on malformed JSON', () => {
    fs.writeFileSync(path.join(dir, POLICY_FILE), '{not json')
    expect(loadPolicy(dir)).toEqual(defaultPolicy())
  })
  it('reads a well-formed policy file', () => {
    const content = {
      version: 1,
      defaultAllow: ['path'],
      defaultDeny: ['vm'],
      packages: { bcrypt: { allow: ['child_process'] } },
    }
    fs.writeFileSync(path.join(dir, POLICY_FILE), JSON.stringify(content))
    const r = loadPolicy(dir)
    expect(r.defaultAllow).toEqual(['path'])
    expect(r.packages['bcrypt']?.allow).toEqual(['child_process'])
  })
})

describe('savePolicy', () => {
  it('writes with stable sorted key order so diffs stay readable', () => {
    const p = defaultPolicy()
    p.packages['z-pkg'] = { allow: ['child_process', 'fs'] }
    p.packages['a-pkg'] = { deny: ['vm'] }
    savePolicy(dir, p)
    const raw = JSON.parse(fs.readFileSync(path.join(dir, POLICY_FILE), 'utf8'))
    expect(Object.keys(raw.packages)).toEqual(['a-pkg', 'z-pkg'])
    expect(raw.packages['z-pkg'].allow).toEqual(['child_process', 'fs']) // sorted
  })
})

describe('policyFromTrace', () => {
  it('builds a policy with allow-lists only for dangerous builtins each pkg uses', () => {
    const trace = {
      packages: {
        '<root>': { builtin: ['fs'] },             // root excluded
        'bcrypt': { builtin: ['fs', 'child_process', 'node:os'] },
        'lodash': { builtin: ['util'] },           // no dangerous builtins → no entry
      },
    }
    const p = policyFromTrace(trace)
    expect(p.packages['bcrypt']?.allow).toEqual(['child_process'])
    expect(p.packages['lodash']).toBeUndefined()
    expect(p.packages['<root>']).toBeUndefined()
  })
})
