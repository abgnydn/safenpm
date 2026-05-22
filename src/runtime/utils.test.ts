import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import fs from 'fs'
import os from 'os'
import path from 'path'
import {
  buildTrace,
  categorizeBuiltin,
  classifyRequireId,
  defaultTraceDir,
  diffTraces,
  listTraceFiles,
  packageOfFile,
  readTraceFile,
  type RuntimeTrace,
} from './utils'

describe('packageOfFile', () => {
  it('returns <root> for paths outside any node_modules segment', () => {
    expect(packageOfFile('/Users/me/proj/src/index.js')).toBe('<root>')
    expect(packageOfFile('/abs/file.js')).toBe('<root>')
    expect(packageOfFile(undefined)).toBe('<root>')
  })

  it('extracts an unscoped package name', () => {
    expect(packageOfFile('/x/node_modules/lodash/index.js')).toBe('lodash')
    expect(packageOfFile('/x/node_modules/axios/lib/core.js')).toBe('axios')
  })

  it('extracts a scoped package name', () => {
    expect(packageOfFile('/x/node_modules/@scope/pkg/index.js')).toBe('@scope/pkg')
    expect(packageOfFile('/x/node_modules/@a/b/c/d.js')).toBe('@a/b')
  })

  it('attributes nested deps to the INNERMOST package', () => {
    // node_modules/a/node_modules/b/x.js → b (b is the actual caller)
    expect(packageOfFile('/x/node_modules/a/node_modules/b/x.js')).toBe('b')
  })

  it('handles Windows-style backslash paths', () => {
    expect(packageOfFile('C:\\proj\\node_modules\\lodash\\index.js')).toBe('lodash')
    expect(packageOfFile('C:\\proj\\node_modules\\@scope\\pkg\\x.js')).toBe('@scope/pkg')
  })

  it('returns <root> for a partial node_modules segment with no following name', () => {
    expect(packageOfFile('/x/node_modules/')).toBe('<root>')
  })
})

describe('classifyRequireId', () => {
  it('classifies builtins (bare + node: prefix)', () => {
    expect(classifyRequireId('fs')).toBe('builtin')
    expect(classifyRequireId('https')).toBe('builtin')
    expect(classifyRequireId('child_process')).toBe('builtin')
    expect(classifyRequireId('node:fs')).toBe('builtin')
  })

  it('classifies relative requires', () => {
    expect(classifyRequireId('./foo')).toBe('relative')
    expect(classifyRequireId('../bar')).toBe('relative')
  })

  it('classifies absolute requires', () => {
    expect(classifyRequireId('/abs/file')).toBe('absolute')
    expect(classifyRequireId('C:\\abs\\file')).toBe('absolute')
  })

  it('classifies bare package names', () => {
    expect(classifyRequireId('lodash')).toBe('package')
    expect(classifyRequireId('axios')).toBe('package')
    expect(classifyRequireId('@scope/pkg')).toBe('package')
  })

  it('classifies subpath imports as package', () => {
    expect(classifyRequireId('lodash/merge')).toBe('package')
    expect(classifyRequireId('@scope/pkg/lib/deep')).toBe('package')
  })

  it('does NOT misclassify an attacker-controlled name as builtin', () => {
    // A package called 'fs-shim' is a normal name; 'fs' is the only
    // builtin. A package literally named 'fsx' would be 'package'.
    expect(classifyRequireId('fs-shim')).toBe('package')
    expect(classifyRequireId('fsx')).toBe('package')
  })
})

describe('buildTrace', () => {
  it('produces a stable, sorted shape from the observation map', () => {
    const obs = new Map<string, Map<string, 'builtin' | 'relative' | 'absolute' | 'package'>>()
    obs.set('phone-home', new Map<string, 'builtin' | 'package' | 'relative' | 'absolute'>([
      ['https', 'builtin'],
      ['fs', 'builtin'],
      ['./util', 'relative'],
      ['lodash', 'package'],
    ]))
    obs.set('<root>', new Map<string, 'builtin' | 'package' | 'relative' | 'absolute'>([
      ['phone-home', 'package'],
    ]))

    const trace = buildTrace(obs, { startMs: Date.now() - 100, cwd: '/x' })
    expect(trace.cwd).toBe('/x')
    expect(trace.durationMs).toBeGreaterThanOrEqual(100)
    expect(trace.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/)
    expect(trace.packages['phone-home']).toEqual({
      builtin: ['fs', 'https'],  // sorted
      package: ['lodash'],
      relative: 1,
      absolute: 0,
    })
    expect(trace.packages['<root>']).toEqual({
      builtin: [], package: ['phone-home'], relative: 0, absolute: 0,
    })
  })

  it('strips the `node:` prefix from builtin names for consistent diffs', () => {
    const obs = new Map<string, Map<string, 'builtin' | 'relative' | 'absolute' | 'package'>>()
    obs.set('pkg', new Map<string, 'builtin' | 'package' | 'relative' | 'absolute'>([
      ['node:fs', 'builtin'],
      ['fs', 'builtin'],
    ]))
    const trace = buildTrace(obs, { startMs: Date.now(), cwd: '/x' })
    expect(trace.packages['pkg']!.builtin).toEqual(['fs'])
  })
})

describe('diffTraces', () => {
  const base: RuntimeTrace = {
    timestamp: '2026-01-01T00:00:00Z', cwd: '/x', durationMs: 100,
    packages: {
      lodash: { builtin: ['util'], package: [], relative: 0, absolute: 0 },
      stable: { builtin: ['fs'], package: ['debug'], relative: 0, absolute: 0 },
    },
  }

  it('reports new builtin requires across versions', () => {
    const curr: RuntimeTrace = {
      ...base,
      packages: {
        ...base.packages,
        lodash: { builtin: ['util', 'child_process'], package: [], relative: 0, absolute: 0 },
      },
    }
    const diff = diffTraces(base, curr)
    expect(diff).toEqual([
      { packageName: 'lodash', newBuiltins: ['child_process'], newPackages: [] },
    ])
  })

  it('reports newly-added packages too', () => {
    const curr: RuntimeTrace = {
      ...base,
      packages: {
        ...base.packages,
        stable: { builtin: ['fs'], package: ['debug', 'request'], relative: 0, absolute: 0 },
      },
    }
    const diff = diffTraces(base, curr)
    expect(diff[0]!.newPackages).toEqual(['request'])
  })

  it('treats a brand-new package as all-new (no prev to compare to)', () => {
    const curr: RuntimeTrace = {
      ...base,
      packages: {
        ...base.packages,
        fresh: { builtin: ['https'], package: ['axios'], relative: 0, absolute: 0 },
      },
    }
    const diff = diffTraces(base, curr).find((d) => d.packageName === 'fresh')!
    expect(diff.newBuiltins).toEqual(['https'])
    expect(diff.newPackages).toEqual(['axios'])
  })

  it('returns an empty list when nothing changed', () => {
    expect(diffTraces(base, base)).toEqual([])
  })
})

describe('defaultTraceDir', () => {
  it('joins under .safenpm/pkg-traces', () => {
    expect(defaultTraceDir('/Users/x')).toMatch(/[/\\]\.safenpm[/\\]pkg-traces$/)
  })
})

describe('categorizeBuiltin', () => {
  it('flags every direct network / arbitrary-code builtin as critical', () => {
    for (const name of [
      'child_process', 'cluster', 'worker_threads',
      'http', 'https', 'http2', 'net', 'dgram', 'tls', 'dns',
      'vm', 'inspector', 'module',
    ]) {
      expect(categorizeBuiltin(name), name).toBe('critical')
    }
  })

  it('flags fs / crypto / os / process as high', () => {
    expect(categorizeBuiltin('fs')).toBe('high')
    expect(categorizeBuiltin('fs/promises')).toBe('high')
    expect(categorizeBuiltin('crypto')).toBe('high')
    expect(categorizeBuiltin('os')).toBe('high')
    expect(categorizeBuiltin('process')).toBe('high')
  })

  it('strips the `node:` prefix before tiering', () => {
    expect(categorizeBuiltin('node:child_process')).toBe('critical')
    expect(categorizeBuiltin('node:fs')).toBe('high')
    expect(categorizeBuiltin('node:path')).toBe('medium')
  })

  it('defaults to medium for everything else', () => {
    expect(categorizeBuiltin('path')).toBe('medium')
    expect(categorizeBuiltin('util')).toBe('medium')
    expect(categorizeBuiltin('events')).toBe('medium')
  })
})

describe('listTraceFiles / readTraceFile', () => {
  let dir: string

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'safenpm-trace-list-'))
  })

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true })
  })

  it('listTraceFiles returns [] when dir is missing', () => {
    expect(listTraceFiles(path.join(dir, 'missing'))).toEqual([])
  })

  it('listTraceFiles returns [] when dir is empty', () => {
    expect(listTraceFiles(dir)).toEqual([])
  })

  it('listTraceFiles returns only .json files, sorted ascending', () => {
    fs.writeFileSync(path.join(dir, 'b.json'), '{}')
    fs.writeFileSync(path.join(dir, 'a.json'), '{}')
    fs.writeFileSync(path.join(dir, 'c.txt'), 'nope')
    const r = listTraceFiles(dir).map((f) => path.basename(f))
    expect(r).toEqual(['a.json', 'b.json'])
  })

  it('readTraceFile returns null on missing / malformed JSON', () => {
    expect(readTraceFile(path.join(dir, 'missing.json'))).toBeNull()
    fs.writeFileSync(path.join(dir, 'corrupt.json'), '{not valid')
    expect(readTraceFile(path.join(dir, 'corrupt.json'))).toBeNull()
  })

  it('readTraceFile returns null when the shape is wrong (missing fields)', () => {
    fs.writeFileSync(path.join(dir, 'partial.json'), JSON.stringify({ timestamp: 'x' }))
    expect(readTraceFile(path.join(dir, 'partial.json'))).toBeNull()
  })

  it('readTraceFile parses a well-formed trace', () => {
    const trace: RuntimeTrace = {
      timestamp: '2026-05-22T00:00:00.000Z', cwd: '/x', durationMs: 5,
      packages: { foo: { builtin: ['fs'], package: [], relative: 0, absolute: 0 } },
    }
    const file = path.join(dir, 'ok.json')
    fs.writeFileSync(file, JSON.stringify(trace))
    expect(readTraceFile(file)).toEqual(trace)
  })
})
