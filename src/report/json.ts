/**
 * JSON-mode reporter — every visual emit is a no-op. The orchestrator
 * is responsible for accumulating findings and emitting a single
 * `JSON.stringify(...)` payload at the end of the run. This keeps
 * stdout free of stray chatter when downstream tooling pipes through
 * `jq` or feeds the output into CI.
 *
 * `interactivePrompt` throws — callers must guard with `opts.json`
 * before reaching it; if it ever fires we want a loud error, not a
 * silent return that hangs an install.
 */
import type { Reporter } from './reporter'

export function createJsonReporter(): Reporter {
  return {
    banner() {},
    dryRunBanner() {},
    backendInfo() {},
    allowlistInfo() {},
    auditInfo() {},
    step() {},
    info() {},
    success() {},
    warn() {},
    error() {},
    blank() {},
    allowed() {},
    blocked() {},
    skipped() {},
    dryRunItem() {},
    typosquatHeader() {},
    typosquatResult() {},
    lockfileHeader() {},
    lockfileResult() {},
    reputationHeader() {},
    reputationResult() {},
    npmAuditHeader() {},
    npmAuditResult() {},
    symlinkHeader() {},
    symlinkResult() {},
    analysisHeader() {},
    analysisResult() {},
    diffHeader() {},
    diffResult() {},
    threatIntelHeader() {},
    threatIntelResult() {},
    maintainerHeader() {},
    maintainerResult() {},
    summary() {},
    interactivePrompt() {
      throw new Error('interactivePrompt called in JSON mode — caller forgot to gate on opts.json')
    },
  }
}
