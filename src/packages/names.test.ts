import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { getAllPackageNames, validatePackageName } from './names'

describe('validatePackageName — npm naming rules', () => {
  it('accepts conventional unscoped names', () => {
    expect(validatePackageName('lodash')).toBeNull()
    expect(validatePackageName('foo-bar')).toBeNull()
    expect(validatePackageName('a-b.c_d')).toBeNull()
  })

  it('accepts scoped names', () => {
    expect(validatePackageName('@scope/pkg')).toBeNull()
    expect(validatePackageName('@a/b')).toBeNull()
  })

  it('accepts scope-level wildcards used by the allowlist', () => {
    expect(validatePackageName('@scope/*')).toBeNull()
  })

  it('rejects empty names', () => {
    expect(validatePackageName('')).toMatch(/empty/i)
  })

  it('rejects names exceeding 214 characters', () => {
    expect(validatePackageName('a'.repeat(215))).toMatch(/too long/i)
  })

  it('rejects uppercase letters', () => {
    expect(validatePackageName('LoDash')).toMatch(/invalid/i)
  })

  it('rejects names starting with . or _ (npm spec)', () => {
    expect(validatePackageName('.dotfile')).toMatch(/invalid/i)
    expect(validatePackageName('_underscore')).toMatch(/invalid/i)
  })

  it('rejects path-traversal attempts', () => {
    // The npm name regex never permits `/` outside the `@scope/name`
    // shape, so attempts like `../etc/passwd` or `pkg/../boom` cannot
    // pass — this protects the rest of the codebase from receiving an
    // already-broken name.
    expect(validatePackageName('../etc/passwd')).toMatch(/invalid/i)
    expect(validatePackageName('pkg/../boom')).toMatch(/invalid/i)
    expect(validatePackageName('foo/bar')).toMatch(/invalid/i)
  })

  it('rejects whitespace, control characters, and shell metas', () => {
    expect(validatePackageName('foo bar')).toMatch(/invalid/i)
    expect(validatePackageName('foo\nbar')).toMatch(/invalid/i)
    expect(validatePackageName('foo;rm -rf /')).toMatch(/invalid/i)
    expect(validatePackageName('foo`whoami`')).toMatch(/invalid/i)
  })

  it('rejects unicode lookalikes (e.g. cyrillic а instead of latin a)', () => {
    // Cyrillic 'а' (U+0430) looks identical to latin 'a' but is not in
    // the allowed character set.
    expect(validatePackageName('reаct')).toMatch(/invalid/i)
  })
})

describe('getAllPackageNames', () => {
  let nm: string

  beforeEach(() => {
    nm = fs.mkdtempSync(path.join(os.tmpdir(), 'safenpm-names-'))
  })

  afterEach(() => {
    fs.rmSync(nm, { recursive: true, force: true })
  })

  it('lists unscoped + scoped packages', () => {
    fs.mkdirSync(path.join(nm, 'lodash'))
    fs.mkdirSync(path.join(nm, '@scope', 'pkg'), { recursive: true })
    const names = getAllPackageNames(nm)
    expect(names.sort()).toEqual(['@scope/pkg', 'lodash'])
  })

  it('skips dotfile entries (.bin, .cache, .package-lock.json)', () => {
    fs.mkdirSync(path.join(nm, '.bin'))
    fs.mkdirSync(path.join(nm, '.cache'))
    fs.writeFileSync(path.join(nm, '.package-lock.json'), '{}')
    fs.mkdirSync(path.join(nm, 'real'))
    expect(getAllPackageNames(nm)).toEqual(['real'])
  })

  it('skips dotfile entries inside a scope', () => {
    fs.mkdirSync(path.join(nm, '@scope', '.hidden'), { recursive: true })
    fs.mkdirSync(path.join(nm, '@scope', 'visible'), { recursive: true })
    expect(getAllPackageNames(nm)).toEqual(['@scope/visible'])
  })

  it('returns an empty array for a non-existent node_modules', () => {
    expect(getAllPackageNames(path.join(nm, 'missing'))).toEqual([])
  })

  it('does not crash on an empty node_modules', () => {
    expect(getAllPackageNames(nm)).toEqual([])
  })
})
