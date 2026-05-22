import type { AnalysisContext, Finding, FindingKind, FindingOf, Step } from './types'

/**
 * Run every enabled step against the context, in declaration order.
 * Findings come back tagged so the caller can dispatch via `byKind`.
 */
export async function runPipeline(
  steps: readonly Step[],
  ctx: AnalysisContext,
): Promise<Finding[]> {
  const findings: Finding[] = []
  for (const step of steps) {
    if (!step.enabled(ctx.opts)) continue
    findings.push(await step.run(ctx))
  }
  return findings
}

/**
 * Convenience accessor for the orchestrator: returns the (single)
 * finding of a given kind, or undefined if that step did not run.
 *
 * Each finding kind is produced by at most one step, so picking by
 * kind is unambiguous. If you ever need fan-out, switch this to find-
 * all and filter at the caller.
 */
export function byKind<K extends FindingKind>(
  findings: readonly Finding[],
  kind: K,
): FindingOf<K> | undefined {
  return findings.find((f): f is FindingOf<K> => f.kind === kind)
}
