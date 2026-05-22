import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { requireNodeModules } from './util'

let workDir: string
let origCwd: string
let stdoutCalls: unknown[]

beforeEach(() => {
  // realpathSync resolves macOS's /tmp → /private/tmp symlink so the
  // path we compute matches what process.cwd() reports inside the
  // chdir'd dir. Without this the equality assertion fails on macOS.
  workDir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'safenpm-util-')))
  origCwd = process.cwd()
  process.chdir(workDir)
  stdoutCalls = []
  vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => { stdoutCalls.push(args.join(' ')) })
})

afterEach(() => {
  process.chdir(origCwd)
  fs.rmSync(workDir, { recursive: true, force: true })
  vi.restoreAllMocks()
})

describe('requireNodeModules', () => {
  it('returns the absolute path when node_modules exists', () => {
    fs.mkdirSync(path.join(workDir, 'node_modules'))
    const r = requireNodeModules(false)
    expect(r).toEqual({ nodeModulesPath: path.join(workDir, 'node_modules') })
  })

  it('returns exit code 1 and a JSON error in --json mode when missing', () => {
    const r = requireNodeModules(true)
    expect(r).toEqual({ exitCode: 1 })
    const out = stdoutCalls.join('\n')
    expect(JSON.parse(out)).toEqual({ error: 'no node_modules found' })
  })

  it('returns exit code 1 and a human error when missing in non-json mode', () => {
    const r = requireNodeModules(false)
    expect(r).toEqual({ exitCode: 1 })
    const out = stdoutCalls.join('\n')
    expect(out).toMatch(/no node_modules found/)
  })

  it('does not consult the parent directory', () => {
    // Even if a parent dir has node_modules, requireNodeModules checks cwd only.
    fs.mkdirSync(path.join(workDir, 'sub'))
    fs.mkdirSync(path.join(workDir, 'node_modules'))
    process.chdir(path.join(workDir, 'sub'))
    const r = requireNodeModules(false)
    expect('exitCode' in r).toBe(true)
  })
})
