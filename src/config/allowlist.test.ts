import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { isAllowed, loadAllowlist, loadTyposquatIgnores } from './allowlist'

describe('isAllowed — exact match', () => {
  it('returns true for an exact package name', () => {
    const set = new Set(['bcrypt'])
    expect(isAllowed('bcrypt', set)).toBe(true)
  })

  it('returns false when the name is not in the set', () => {
    const set = new Set(['bcrypt'])
    expect(isAllowed('sharp', set)).toBe(false)
  })

  it('matches scoped names exactly', () => {
    const set = new Set(['@mapbox/node-pre-gyp'])
    expect(isAllowed('@mapbox/node-pre-gyp', set)).toBe(true)
    expect(isAllowed('@mapbox/other', set)).toBe(false)
  })
})

describe('isAllowed — scope wildcards', () => {
  it('matches every package under @scope/* when the wildcard entry is present', () => {
    const set = new Set(['@acme/*'])
    expect(isAllowed('@acme/foo', set)).toBe(true)
    expect(isAllowed('@acme/anything-here', set)).toBe(true)
  })

  it('does NOT let @acme/* leak to a sibling scope or unscoped lookalike', () => {
    const set = new Set(['@acme/*'])
    expect(isAllowed('@acmex/foo', set)).toBe(false)
    expect(isAllowed('acme/foo', set)).toBe(false)
    // Especially important: a name *starting* with the scope but
    // unscoped (`@acmebad`) must not be considered allowed.
    expect(isAllowed('@acmebad', set)).toBe(false)
  })

  it('rejects the bare scope itself when only @scope/* is allowed', () => {
    const set = new Set(['@acme/*'])
    expect(isAllowed('@acme', set)).toBe(false)
  })
})

describe('loadAllowlist', () => {
  let projectDir: string
  let originalCwd: string
  let originalHome: string | undefined

  beforeEach(() => {
    projectDir = fs.mkdtempSync(path.join(os.tmpdir(), 'safenpm-allow-proj-'))
    originalCwd = process.cwd()
    originalHome = process.env.HOME
    process.chdir(projectDir)
    // Isolate the user-level rc lookup to a writable tmpdir, so
    // tests don't observe whatever lives in the real ~/.safenpmrc.
    const fakeHome = fs.mkdtempSync(path.join(os.tmpdir(), 'safenpm-allow-home-'))
    process.env.HOME = fakeHome
  })

  afterEach(() => {
    process.chdir(originalCwd)
    if (originalHome === undefined) delete process.env.HOME
    else process.env.HOME = originalHome
    fs.rmSync(projectDir, { recursive: true, force: true })
  })

  it('returns CLI flags even when no rc files exist', () => {
    const set = loadAllowlist(['bcrypt', 'sharp'])
    expect(set.has('bcrypt')).toBe(true)
    expect(set.has('sharp')).toBe(true)
  })

  it('merges entries from .safenpmrc in the project root', () => {
    fs.writeFileSync(path.join(projectDir, '.safenpmrc'), '# comment\nfsevents\n\n@scope/*\n')
    const set = loadAllowlist([])
    expect(set.has('fsevents')).toBe(true)
    expect(set.has('@scope/*')).toBe(true)
    // Comments and blank lines must not become entries.
    expect(set.has('# comment')).toBe(false)
    expect(set.has('')).toBe(false)
  })

  it('merges CLI flags AND project rc together', () => {
    fs.writeFileSync(path.join(projectDir, '.safenpmrc'), 'fsevents\n')
    const set = loadAllowlist(['bcrypt'])
    expect(set.has('fsevents')).toBe(true)
    expect(set.has('bcrypt')).toBe(true)
  })

  it('trims whitespace on every entry', () => {
    fs.writeFileSync(path.join(projectDir, '.safenpmrc'), '   bcrypt   \n\tsharp\t\n')
    const set = loadAllowlist([])
    expect(set.has('bcrypt')).toBe(true)
    expect(set.has('sharp')).toBe(true)
    expect(set.has('   bcrypt   ')).toBe(false)
  })

  it('survives an unreadable / malformed rc file without throwing', () => {
    // Directory in place of a file — fs.readFileSync would throw EISDIR.
    fs.mkdirSync(path.join(projectDir, '.safenpmrc'))
    expect(() => loadAllowlist(['bcrypt'])).not.toThrow()
  })

  it('does NOT pick up !-prefixed lines as allowlist entries', () => {
    fs.writeFileSync(
      path.join(projectDir, '.safenpmrc'),
      'bcrypt\n!my-internal-react-thing\n@acme/sharp\n',
    )
    const set = loadAllowlist([])
    expect(set.has('bcrypt')).toBe(true)
    expect(set.has('@acme/sharp')).toBe(true)
    expect(set.has('!my-internal-react-thing')).toBe(false)
    expect(set.has('my-internal-react-thing')).toBe(false)
  })
})

describe('loadTyposquatIgnores', () => {
  let projectDir: string
  let originalCwd: string
  let originalHome: string | undefined

  beforeEach(() => {
    projectDir = fs.mkdtempSync(path.join(os.tmpdir(), 'safenpm-tsi-proj-'))
    originalCwd = process.cwd()
    originalHome = process.env.HOME
    process.chdir(projectDir)
    const fakeHome = fs.mkdtempSync(path.join(os.tmpdir(), 'safenpm-tsi-home-'))
    process.env.HOME = fakeHome
  })

  afterEach(() => {
    process.chdir(originalCwd)
    if (originalHome === undefined) delete process.env.HOME
    else process.env.HOME = originalHome
    fs.rmSync(projectDir, { recursive: true, force: true })
  })

  it('collects only !-prefixed entries and strips the !', () => {
    fs.writeFileSync(
      path.join(projectDir, '.safenpmrc'),
      'bcrypt\n!lodash-utils\n!@acme/react-helpers\n# comment\n',
    )
    const set = loadTyposquatIgnores()
    expect(set.has('lodash-utils')).toBe(true)
    expect(set.has('@acme/react-helpers')).toBe(true)
    expect(set.has('bcrypt')).toBe(false)
  })

  it('returns an empty set when no rc file exists', () => {
    expect(loadTyposquatIgnores().size).toBe(0)
  })

  it('trims whitespace after the ! prefix', () => {
    fs.writeFileSync(path.join(projectDir, '.safenpmrc'), '!   spaced-name   \n')
    expect(loadTyposquatIgnores().has('spaced-name')).toBe(true)
  })
})
