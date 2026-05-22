/**
 * Profile-generator tests for the macOS strict sandbox.
 *
 * These tests pin the structural rules of `buildStrictProfile` so
 * future edits to the TinyScheme block can't silently regress a
 * security-critical denial. A `console.log()` of the profile during
 * a session is fine; deleting a `(deny network*)` line should fail
 * the test.
 */
import { describe, expect, it, vi } from 'vitest'

// Force the os module to look like macOS so buildStrictProfile and
// its homedir consumer behave identically across CI runners.
vi.mock('os', async () => {
  const actual = await vi.importActual<typeof import('os')>('os')
  return {
    ...actual,
    platform: () => 'darwin',
    homedir: () => '/Users/test-user',
    default: { ...actual, platform: () => 'darwin', homedir: () => '/Users/test-user' },
  }
})

import { buildStrictProfile, LOOSE_PROFILE } from './macos'

describe('buildStrictProfile — invariants', () => {
  const profile = buildStrictProfile('/tmp/test-pkg-path')

  it('starts with deny-default', () => {
    expect(profile).toMatch(/\(deny default\)/)
  })

  it('denies every network capability', () => {
    expect(profile).toMatch(/\(deny network-outbound\)/)
    expect(profile).toMatch(/\(deny network-inbound\)/)
    expect(profile).toMatch(/\(deny network-bind\)/)
    expect(profile).toMatch(/\(deny network\*\)/)
  })

  it('denies the DNS-related mach services (regression: phone-home SIGABRT)', () => {
    // Removing any of these would re-open the DNS leak path that
    // let the phone-home script intermittently bypass the network
    // denies. Pinned explicitly so the regression can't slip back.
    expect(profile).toContain('"com.apple.dnssd-uds"')
    expect(profile).toContain('"com.apple.mDNSResponder"')
    expect(profile).toContain('"com.apple.networkd"')
  })

  it('denies the sensitive home-directory paths', () => {
    expect(profile).toContain('/Users/test-user/.ssh')
    expect(profile).toContain('/Users/test-user/.aws')
    expect(profile).toContain('/Users/test-user/.gnupg')
    expect(profile).toContain('/Users/test-user/.npmrc')
    expect(profile).toContain('/Users/test-user/.bash_history')
    expect(profile).toContain('/Users/test-user/.zsh_history')
  })

  it('embeds the package path into both the exec-allow and read-allow lists', () => {
    expect(profile).toContain('"/tmp/test-pkg-path"')
  })

  it('allows the basic shell + node binaries', () => {
    expect(profile).toContain('"/bin/sh"')
    expect(profile).toContain('"/bin/bash"')
    expect(profile).toContain('"/usr/bin/node"')
  })

  it('escapes embedded double-quotes in the package path', () => {
    const sneaky = buildStrictProfile('/tmp/has"quote')
    // The escaped form (\") should appear; an unescaped " inside the
    // literal would have closed the TinyScheme string early and
    // produced a syntactically invalid profile.
    expect(sneaky).toContain('\\"')
    // Sanity-check that the profile still terminates the network-deny block.
    expect(sneaky).toMatch(/\(deny network\*\)/)
  })
})

describe('LOOSE_PROFILE', () => {
  it('allows everything by default but still denies network', () => {
    expect(LOOSE_PROFILE).toMatch(/\(allow default\)/)
    expect(LOOSE_PROFILE).toMatch(/\(deny network-outbound\)/)
    expect(LOOSE_PROFILE).toMatch(/\(deny network\*\)/)
  })

  it('does not contain a deny-default rule (would invert the policy)', () => {
    expect(LOOSE_PROFILE).not.toMatch(/\(deny default\)/)
  })
})
