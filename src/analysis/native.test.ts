import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { auditNativeAddons, scanSymbols } from './native'

let nm: string

beforeEach(() => {
  nm = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'safenpm-native-')))
})

afterEach(() => {
  fs.rmSync(nm, { recursive: true, force: true })
})

/**
 * Build a tiny fake addon whose binary content is "<header-bytes><name>\\0<more>".
 * The exact bytes don't need to be a valid Mach-O / ELF — the scanner
 * just looks for `<symname>\0` patterns in the file.
 */
function writeFakeAddon(rel: string, embeddedSymbols: string[]): void {
  const full = path.join(nm, ...rel.split('/'))
  fs.mkdirSync(path.dirname(full), { recursive: true })
  const parts: Buffer[] = [Buffer.from('SYNTHADDON', 'utf8')]
  for (const s of embeddedSymbols) {
    parts.push(Buffer.from(`${s}\0`, 'utf8'))
  }
  parts.push(Buffer.from('END', 'utf8'))
  fs.writeFileSync(full, Buffer.concat(parts))
}

describe('scanSymbols (pure)', () => {
  it('flags execvp / system / dlopen in a buffer', () => {
    const buf = Buffer.from('xx\x00execvp\x00stuff\x00system\x00more\x00dlopen\x00', 'utf8')
    const r = scanSymbols(buf)
    const names = r.map((x) => x.name)
    expect(names).toContain('execvp')
    expect(names).toContain('system')
    expect(names).toContain('dlopen')
  })

  it('flags socket / connect (network category)', () => {
    const buf = Buffer.from('header\x00socket\x00connect\x00', 'utf8')
    const r = scanSymbols(buf)
    expect(r.map((x) => x.name).sort()).toEqual(['connect', 'socket'])
    expect(r.every((x) => x.category === 'network')).toBe(true)
  })

  it('does NOT match substrings that are part of larger identifiers', () => {
    // `socket_internal` should not match the `socket` symbol because
    // the NUL terminator forces the match boundary.
    const buf = Buffer.from('socket_internal\x00connectionPool\x00', 'utf8')
    expect(scanSymbols(buf)).toEqual([])
  })

  it('returns empty for a buffer with no dangerous symbol names', () => {
    expect(scanSymbols(Buffer.from('hello world\x00foo\x00bar\x00', 'utf8'))).toEqual([])
  })
})

describe('auditNativeAddons (walk + scan)', () => {
  it('returns scanned: 0 for missing node_modules', () => {
    expect(auditNativeAddons(path.join(nm, 'missing'))).toEqual({ scanned: 0, suspicious: [] })
  })

  it('returns scanned: 0 when no .node files exist', () => {
    fs.mkdirSync(path.join(nm, 'plain'), { recursive: true })
    fs.writeFileSync(path.join(nm, 'plain', 'index.js'), 'console.log("hi")')
    expect(auditNativeAddons(nm)).toEqual({ scanned: 0, suspicious: [] })
  })

  it('walks node_modules and finds .node files in nested build dirs', () => {
    writeFakeAddon('sharp/build/Release/sharp.node', ['execvp', 'dlopen'])
    const r = auditNativeAddons(nm)
    expect(r.scanned).toBe(1)
    expect(r.suspicious).toHaveLength(1)
    expect(r.suspicious[0]?.pkg).toBe('sharp')
    expect(r.suspicious[0]?.symbols.map((s) => s.name).sort()).toEqual(['dlopen', 'execvp'])
  })

  it('attributes scoped packages correctly', () => {
    writeFakeAddon('@acme/native-mod/x.node', ['socket'])
    const r = auditNativeAddons(nm)
    expect(r.suspicious[0]?.pkg).toBe('@acme/native-mod')
  })

  it('records sha256 + size for each addon (for future registry comparison)', () => {
    writeFakeAddon('mod/x.node', ['execvp'])
    const r = auditNativeAddons(nm)
    expect(r.suspicious[0]?.sha256).toMatch(/^[a-f0-9]{64}$/)
    expect(r.suspicious[0]?.size).toBeGreaterThan(0)
  })

  it('does not flag an addon whose only symbols are below the high-risk threshold', () => {
    // recvfrom is medium-risk only, so an addon with only that
    // appears in `scanned` but not `suspicious`.
    writeFakeAddon('quiet/x.node', ['recvfrom'])
    const r = auditNativeAddons(nm)
    expect(r.scanned).toBe(1)
    expect(r.suspicious).toEqual([])
  })

  it('does NOT follow symlinks to .node files (those are handled by symlinks.ts)', () => {
    writeFakeAddon('real/x.node', ['execvp'])
    fs.mkdirSync(path.join(nm, 'aliased'), { recursive: true })
    fs.symlinkSync(path.join(nm, 'real', 'x.node'), path.join(nm, 'aliased', 'x.node'))
    const r = auditNativeAddons(nm)
    // Only the real one counted, not the symlink.
    expect(r.scanned).toBe(1)
  })

  it('handles Windows DLL backdoor symbols (LoadLibraryA / CreateProcessA)', () => {
    writeFakeAddon('windll/x.node', ['LoadLibraryA', 'CreateProcessA'])
    const r = auditNativeAddons(nm)
    expect(r.suspicious[0]?.symbols.map((s) => s.name).sort()).toEqual(['CreateProcessA', 'LoadLibraryA'])
  })
})
