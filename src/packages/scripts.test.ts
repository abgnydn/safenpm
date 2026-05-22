import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { findInstallScripts } from './scripts'

let nm: string

beforeEach(() => {
  nm = fs.mkdtempSync(path.join(os.tmpdir(), 'safenpm-scripts-'))
})

afterEach(() => {
  fs.rmSync(nm, { recursive: true, force: true })
})

function writePkg(name: string, pkg: object): void {
  const pkgDir = path.join(nm, ...name.split('/'))
  fs.mkdirSync(pkgDir, { recursive: true })
  fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify(pkg))
}

describe('findInstallScripts', () => {
  it('returns an empty array for a non-existent node_modules', () => {
    expect(findInstallScripts(path.join(nm, 'missing'))).toEqual([])
  })

  it('returns an empty array when no packages declare install hooks', () => {
    writePkg('plain', { name: 'plain', version: '1.0.0' })
    expect(findInstallScripts(nm)).toEqual([])
  })

  it('finds a postinstall script', () => {
    writePkg('with-postinstall', {
      name: 'with-postinstall', version: '1.0.0',
      scripts: { postinstall: 'echo hi' },
    })
    const r = findInstallScripts(nm)
    expect(r).toHaveLength(1)
    expect(r[0]).toMatchObject({
      name: 'with-postinstall', version: '1.0.0',
      script: 'echo hi', hook: 'postinstall',
    })
  })

  it('only reports the FIRST matching hook per package (preinstall wins over install)', () => {
    writePkg('multi-hook', {
      name: 'multi-hook', version: '1.0.0',
      scripts: {
        preinstall: 'echo a',
        install: 'echo b',
        postinstall: 'echo c',
      },
    })
    const r = findInstallScripts(nm)
    expect(r).toHaveLength(1)
    expect(r[0]?.hook).toBe('preinstall')
  })

  it('descends into scoped packages and uses the @scope/name shape', () => {
    writePkg('@acme/native-bind', {
      name: '@acme/native-bind', version: '1.0.0',
      scripts: { install: 'node-gyp build' },
    })
    const r = findInstallScripts(nm)
    expect(r).toHaveLength(1)
    expect(r[0]?.name).toBe('@acme/native-bind')
  })

  it('skips dotfile dirs and non-directory entries', () => {
    fs.mkdirSync(path.join(nm, '.bin'))
    fs.writeFileSync(path.join(nm, '.package-lock.json'), '{}')
    writePkg('real', { name: 'real', version: '1.0.0', scripts: { postinstall: 'echo hi' } })
    const r = findInstallScripts(nm)
    expect(r).toHaveLength(1)
    expect(r[0]?.name).toBe('real')
  })

  it('ignores packages with whitespace-only scripts', () => {
    writePkg('blank', { name: 'blank', version: '1.0.0', scripts: { postinstall: '   ' } })
    expect(findInstallScripts(nm)).toEqual([])
  })

  it('survives a malformed package.json', () => {
    fs.mkdirSync(path.join(nm, 'broken'))
    fs.writeFileSync(path.join(nm, 'broken', 'package.json'), '{not json')
    expect(findInstallScripts(nm)).toEqual([])
  })
})
