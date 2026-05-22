/**
 * The standard analysis pipeline. Steps run in this order — the order
 * is meaningful because install/index.ts reports findings in the same
 * sequence (preserving the released CLI output contract).
 *
 *   1. typosquats          (scan only — scoped/edit-distance check)
 *   2. lockfile audit      (scan only — registry/integrity/freshness)
 *   3. reputation summary  (scan only — heuristic 0–100 per package)
 *   4. static analysis     (always — risk score per install script)
 *   5. behavioral diff     (scan only — compare against prior cache)
 *   6. threat intel        (always — community signal lookup)
 *   7. maintainer change   (scan only — npm publisher diff)
 *
 * Steps that need the script list (4–7) only ever produce empty
 * results if there are no scripts, so callers can rely on receiving
 * a Finding entry whenever the step is enabled.
 */
import { analyzeAll } from '../analysis/analyzer'
import { diffScripts, significantDiffs } from '../analysis/diffing'
import { auditLockfile } from '../analysis/lockfile'
import { auditNativeAddons } from '../analysis/native'
import { runNpmAudit } from '../analysis/npm-audit'
import { scoreReputationFromNodeModules } from '../analysis/reputation'
import { auditSymlinks } from '../analysis/symlinks'
import { checkAllTyposquats } from '../analysis/typosquat'
import { loadTyposquatIgnores } from '../config/allowlist'
import { checkMaintainerChanges } from '../network/maintainer'
import { checkThreatIntel } from '../network/threatintel'
import type { Step } from './types'

const scanOnly = (opts: { scan: boolean }) => opts.scan

export const typosquatStep: Step<{ kind: 'typosquats'; results: ReturnType<typeof checkAllTyposquats> }> = {
  name: 'typosquats',
  enabled: scanOnly,
  run: (ctx) => {
    const ignores = loadTyposquatIgnores()
    const results = checkAllTyposquats(ctx.allPackageNames)
      .filter((r) => !ignores.has(r.suspect))
    return { kind: 'typosquats', results }
  },
}

export const lockfileStep: Step<{ kind: 'lockfile'; result: ReturnType<typeof auditLockfile> }> = {
  name: 'lockfile',
  enabled: scanOnly,
  run: (ctx) => ({ kind: 'lockfile', result: auditLockfile(ctx.cwd) }),
}

export const reputationStep: Step<{ kind: 'reputation'; summary: ReturnType<typeof scoreReputationFromNodeModules> }> = {
  name: 'reputation',
  enabled: scanOnly,
  run: (ctx) => ({ kind: 'reputation', summary: scoreReputationFromNodeModules(ctx.nodeModulesPath) }),
}

export const npmAuditStep: Step<{ kind: 'npm-audit'; result: ReturnType<typeof runNpmAudit> }> = {
  name: 'npm-audit',
  enabled: scanOnly,
  run: (ctx) => ({ kind: 'npm-audit', result: runNpmAudit(ctx.cwd) }),
}

// Symlink audit runs on EVERY install, not just --scan. The cost is
// low (walk node_modules, readlink each link) and the attack pattern
// (symlink-escape to /etc/passwd / ~/.ssh / etc) is real and pre-
// install — there's no benefit to deferring detection to --scan.
export const symlinkStep: Step<{ kind: 'symlinks'; result: ReturnType<typeof auditSymlinks> }> = {
  name: 'symlinks',
  enabled: () => true,
  run: (ctx) => ({ kind: 'symlinks', result: auditSymlinks(ctx.nodeModulesPath) }),
}

// Native-addon byte scan runs on every install — install-time
// sandbox can't see inside compiled .node files, and the cost of
// a buffer-scan over the (usually few) addons is small. Surfaces
// suspicious imported-symbol names; doesn't block (heuristic).
export const nativeStep: Step<{ kind: 'native'; result: ReturnType<typeof auditNativeAddons> }> = {
  name: 'native',
  enabled: () => true,
  run: (ctx) => ({ kind: 'native', result: auditNativeAddons(ctx.nodeModulesPath) }),
}

export const analysisStep: Step<{ kind: 'analysis'; results: ReturnType<typeof analyzeAll> }> = {
  name: 'analysis',
  enabled: () => true,
  run: (ctx) => ({ kind: 'analysis', results: analyzeAll(ctx.scripts) }),
}

export const diffStep: Step<{ kind: 'diffs'; results: ReturnType<typeof significantDiffs> }> = {
  name: 'behavior-diff',
  enabled: scanOnly,
  run: (ctx) => ({ kind: 'diffs', results: significantDiffs(diffScripts(ctx.scripts)) }),
}

export const threatIntelStep: Step<{ kind: 'threat-intel'; results: Awaited<ReturnType<typeof checkThreatIntel>> }> = {
  name: 'threat-intel',
  enabled: () => true,
  async run(ctx) {
    const pairs = ctx.scripts.map((s) => ({ name: s.name, version: s.version }))
    return { kind: 'threat-intel', results: await checkThreatIntel(pairs) }
  },
}

export const maintainerStep: Step<{ kind: 'maintainers'; results: Awaited<ReturnType<typeof checkMaintainerChanges>> }> = {
  name: 'maintainers',
  enabled: scanOnly,
  async run(ctx) {
    const pairs = ctx.scripts.map((s) => ({ name: s.name, version: s.version }))
    return { kind: 'maintainers', results: await checkMaintainerChanges(pairs) }
  },
}

/**
 * Steps that depend only on the package list, not on install scripts.
 * Run these BEFORE the early-return "no scripts found" branch.
 */
export const PRE_SCRIPT_STEPS: readonly Step[] = [
  symlinkStep,        // always — escape symlinks are an install-time-only check
  nativeStep,         // always — .node files are a sandbox blind spot
  typosquatStep,
  lockfileStep,
  reputationStep,
  npmAuditStep,
]

/**
 * Steps that consume the install-script list. Run these AFTER the
 * early-return check so we don't waste a registry round-trip on
 * projects without install scripts.
 */
export const POST_SCRIPT_STEPS: readonly Step[] = [
  analysisStep,
  diffStep,
  threatIntelStep,
  maintainerStep,
]
