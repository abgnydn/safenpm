import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { auditLockfile, significantLockfileIssues } from './lockfile'

let dir: string

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'safenpm-lock-'))
})

afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true })
})

function writeLock(content: object): void {
  fs.writeFileSync(path.join(dir, 'package-lock.json'), JSON.stringify(content, null, 2))
}

describe('auditLockfile — file state', () => {
  it('reports a synthetic "no-lockfile" issue and score 50 when missing', () => {
    const r = auditLockfile(dir)
    expect(r.exists).toBe(false)
    expect(r.score).toBe(50)
    expect(r.issues[0]?.type).toBe('no-lockfile')
  })

  it('reports parse-error severity high when lockfile is malformed', () => {
    fs.writeFileSync(path.join(dir, 'package-lock.json'), '{this is not json')
    const r = auditLockfile(dir)
    expect(r.exists).toBe(true)
    expect(r.format).toBeNull()
    expect(r.score).toBe(0)
    expect(r.issues[0]?.severity).toBe('high')
    expect(r.issues[0]?.type).toBe('parse-error')
  })
})

describe('auditLockfile — v2/v3 (modern lockfiles)', () => {
  it('detects format v3 and flags missing integrity hash', () => {
    writeLock({
      lockfileVersion: 3,
      packages: {
        '': { name: 'app' },
        'node_modules/foo': {
          version: '1.0.0',
          resolved: 'https://registry.npmjs.org/foo/-/foo-1.0.0.tgz',
          // intentionally no integrity
        },
      },
    })
    const r = auditLockfile(dir)
    expect(r.format).toBe('v3')
    expect(r.totalPackages).toBe(1)
    const types = r.issues.map((i) => i.type)
    expect(types).toContain('missing-integrity')
  })

  it('flags HIGH severity for git+ resolved URLs', () => {
    writeLock({
      lockfileVersion: 3,
      packages: {
        '': {},
        'node_modules/sneaky': {
          version: '0.1.0',
          resolved: 'git+ssh://git@github.com/attacker/sneaky.git#abc123',
          integrity: 'sha512-deadbeef',
        },
      },
    })
    const r = auditLockfile(dir)
    const git = r.issues.find((i) => i.type === 'git-dependency')
    expect(git).toBeDefined()
    expect(git!.severity).toBe('high')
  })

  it('flags HIGH severity for file: resolved URLs', () => {
    writeLock({
      lockfileVersion: 3,
      packages: {
        '': {},
        'node_modules/local-evil': {
          version: '0.0.1',
          resolved: 'file:../somewhere-outside',
          integrity: 'sha512-deadbeef',
        },
      },
    })
    const r = auditLockfile(dir)
    const fileIssue = r.issues.find((i) => i.type === 'file-dependency')
    expect(fileIssue?.severity).toBe('high')
  })

  it('flags HIGH severity for non-npm tarball registries', () => {
    writeLock({
      lockfileVersion: 3,
      packages: {
        '': {},
        'node_modules/typosquat': {
          version: '1.0.0',
          resolved: 'https://my-fake-registry.example.com/typosquat-1.0.0.tgz',
          integrity: 'sha512-deadbeef',
        },
      },
    })
    const r = auditLockfile(dir)
    const custom = r.issues.find((i) => i.type === 'custom-registry')
    expect(custom?.severity).toBe('high')
  })

  it('does not flag the official npm registry tarball', () => {
    writeLock({
      lockfileVersion: 3,
      packages: {
        '': {},
        'node_modules/lodash': {
          version: '4.17.21',
          resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz',
          integrity: 'sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==',
        },
      },
    })
    const r = auditLockfile(dir)
    expect(r.issues.find((i) => i.type === 'custom-registry')).toBeUndefined()
    expect(r.issues.find((i) => i.type === 'missing-integrity')).toBeUndefined()
  })

  it('flags weak-hash (low severity) for non-sha512 integrity', () => {
    writeLock({
      lockfileVersion: 3,
      packages: {
        '': {},
        'node_modules/old-pkg': {
          version: '1.0.0',
          resolved: 'https://registry.npmjs.org/old-pkg/-/old-pkg-1.0.0.tgz',
          integrity: 'sha1-abcdef0123456789',
        },
      },
    })
    const r = auditLockfile(dir)
    const weak = r.issues.find((i) => i.type === 'weak-hash')
    expect(weak?.severity).toBe('low')
  })

  it('flags has-install-script as a low-severity heads-up', () => {
    writeLock({
      lockfileVersion: 3,
      packages: {
        '': {},
        'node_modules/native-mod': {
          version: '1.0.0',
          resolved: 'https://registry.npmjs.org/native-mod/-/native-mod-1.0.0.tgz',
          integrity: 'sha512-deadbeef',
          hasInstallScript: true,
        },
      },
    })
    const r = auditLockfile(dir)
    expect(r.issues.find((i) => i.type === 'has-install-script')?.severity).toBe('low')
  })
})

describe('auditLockfile — v1 (legacy lockfiles)', () => {
  it('detects format v1 and recurses into nested deps', () => {
    writeLock({
      lockfileVersion: 1,
      dependencies: {
        foo: {
          version: '1.0.0',
          resolved: 'https://registry.npmjs.org/foo/-/foo-1.0.0.tgz',
          integrity: 'sha512-aaaa',
          dependencies: {
            bar: {
              version: '2.0.0',
              // intentionally no resolved + no integrity
            },
          },
        },
      },
    })
    const r = auditLockfile(dir)
    expect(r.format).toBe('v1')
    expect(r.issues.find((i) => i.package.includes('bar'))).toBeDefined()
  })
})

describe('significantLockfileIssues', () => {
  it('filters to high + medium severities', () => {
    writeLock({
      lockfileVersion: 3,
      packages: {
        '': {},
        'node_modules/git': {
          resolved: 'git+ssh://x.git',
          integrity: 'sha512-x',
        },
        'node_modules/weak': {
          resolved: 'https://registry.npmjs.org/weak/-/weak-1.tgz',
          integrity: 'sha1-aaaa',
        },
      },
    })
    const r = auditLockfile(dir)
    const sig = significantLockfileIssues(r)
    expect(sig.every((i) => i.severity === 'high' || i.severity === 'medium')).toBe(true)
    expect(sig.find((i) => i.type === 'weak-hash')).toBeUndefined()
  })
})
