import { describe, expect, it } from 'vitest'
import { isParseError, parseInstallArgs } from './args'

const ok = (result: ReturnType<typeof parseInstallArgs>) => {
  if (isParseError(result)) throw new Error(`expected success, got: ${result.message}`)
  return result
}

describe('parseInstallArgs', () => {
  it('parses an empty argv into a default-config install', () => {
    const r = ok(parseInstallArgs([]))
    expect(r).toEqual({
      packages: [], dryRun: false, allow: [], noReport: false,
      json: false, interactive: false, loose: false, scan: false,
    })
  })

  it('captures bare positionals as package names', () => {
    const r = ok(parseInstallArgs(['axios', 'lodash']))
    expect(r.packages).toEqual(['axios', 'lodash'])
  })

  it('handles --dry-run and its -n shorthand', () => {
    expect(ok(parseInstallArgs(['--dry-run'])).dryRun).toBe(true)
    expect(ok(parseInstallArgs(['-n'])).dryRun).toBe(true)
  })

  it('parses --allow with a separate value', () => {
    const r = ok(parseInstallArgs(['--allow', 'bcrypt,sharp']))
    expect(r.allow).toEqual(['bcrypt', 'sharp'])
  })

  it('parses --allow with =value form', () => {
    const r = ok(parseInstallArgs(['--allow=bcrypt,@mapbox/x']))
    expect(r.allow).toEqual(['bcrypt', '@mapbox/x'])
  })

  it('rejects invalid package names in --allow', () => {
    const r = parseInstallArgs(['--allow', 'BadName'])
    expect(isParseError(r)).toBe(true)
    if (isParseError(r)) expect(r.message).toMatch(/invalid --allow value/)
  })

  it('flips --json / --interactive / --loose / --scan', () => {
    const r = ok(parseInstallArgs(['--json', '--interactive', '--loose', '--scan']))
    expect(r.json).toBe(true)
    expect(r.interactive).toBe(true)
    expect(r.loose).toBe(true)
    expect(r.scan).toBe(true)
  })

  it('accepts -I and -S as aliases', () => {
    const r = ok(parseInstallArgs(['-I', '-S']))
    expect(r.interactive).toBe(true)
    expect(r.scan).toBe(true)
  })

  it('mixes flags and positionals in any order', () => {
    const r = ok(parseInstallArgs(['axios', '--scan', 'lodash', '--allow=bcrypt']))
    expect(r.packages).toEqual(['axios', 'lodash'])
    expect(r.scan).toBe(true)
    expect(r.allow).toEqual(['bcrypt'])
  })

  it('ignores unknown flags', () => {
    const r = ok(parseInstallArgs(['--definitely-not-a-flag']))
    expect(r.packages).toEqual([])
  })
})
