/**
 * argv parser for `safenpm install`. Kept hand-rolled because the CLI
 * has fewer than a dozen flags and pulling in commander/yargs would
 * blow up the zero-prod-dep promise. Tests live in args.test.ts.
 *
 * The parser is intentionally lenient about ordering ("safenpm i pkg
 * --allow x" and "safenpm i --allow x pkg" both work). Unknown flags
 * are ignored; bare positionals are treated as package names.
 */
import { validatePackageName } from '../packages/names'
import type { InstallOptions } from '../types'

export interface ParseError {
  readonly kind: 'parse-error'
  readonly message: string
}

export type ParseResult = InstallOptions | ParseError

export function parseInstallArgs(args: readonly string[]): ParseResult {
  const packages: string[] = []
  const allow: string[] = []
  let dryRun = false
  let noReport = false
  let json = false
  let interactive = false
  let loose = false
  let scan = false

  let i = 0
  while (i < args.length) {
    const arg = args[i]!

    switch (true) {
      case arg === '--dry-run' || arg === '-n':
        dryRun = true; break

      case arg === '--allow': {
        i++
        const value = args[i] ?? ''
        const err = consumeAllowValue(value, allow)
        if (err) return err
        break
      }

      case arg.startsWith('--allow='): {
        const err = consumeAllowValue(arg.slice('--allow='.length), allow)
        if (err) return err
        break
      }

      case arg === '--no-report':       noReport    = true; break
      case arg === '--json':            json        = true; break
      case arg === '--interactive' || arg === '-I':
        interactive = true; break
      case arg === '--loose':           loose       = true; break
      case arg === '--scan' || arg === '-S':
        scan        = true; break

      default:
        if (!arg.startsWith('-')) packages.push(arg)
        break
    }
    i++
  }

  return { packages, dryRun, allow, noReport, json, interactive, loose, scan }
}

function consumeAllowValue(value: string, into: string[]): ParseError | null {
  for (const name of value.split(',')) {
    const trimmed = name.trim()
    if (!trimmed) continue
    const err = validatePackageName(trimmed)
    if (err) return { kind: 'parse-error', message: `invalid --allow value: ${err}` }
    into.push(trimmed)
  }
  return null
}

export function isParseError(result: ParseResult): result is ParseError {
  return (result as ParseError).kind === 'parse-error'
}
