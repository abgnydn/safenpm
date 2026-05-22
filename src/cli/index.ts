#!/usr/bin/env node
/**
 * safenpm CLI entry point. Parses the leading command, dispatches to
 * a per-command module, and translates the returned exit code into a
 * `process.exit()` call. Each command owns its own argv parsing —
 * keeping dispatch trivial here means new commands are one file in
 * `commands/` + one entry in this map.
 */
import { HELP_TEXT, VERSION_STRING } from './help'

type CommandModule = { run: (args: readonly string[]) => Promise<number> }

const COMMANDS: Record<string, () => Promise<CommandModule>> = {
  install:  () => import('./commands/install'),
  i:        () => import('./commands/install'),
  scan:     () => import('./commands/scan'),
  doctor:   () => import('./commands/doctor'),
  fix:      () => import('./commands/fix'),
  diff:     () => import('./commands/diff'),
  audit:    () => import('./commands/audit'),
  trace:    () => import('./commands/trace'),
  run:      () => import('./commands/run'),
}

async function main(): Promise<number> {
  const [, , command, ...rawArgs] = process.argv

  if (command === '--version' || command === '-v') {
    console.log(VERSION_STRING)
    return 0
  }
  if (command === '--help' || command === '-h' || command === undefined) {
    console.log(HELP_TEXT)
    return 0
  }

  const loader = COMMANDS[command]
  if (!loader) {
    console.error(`  unknown command: ${command}`)
    console.error('  run safenpm --help for usage')
    return 1
  }

  const mod = await loader()
  return mod.run(rawArgs)
}

main()
  .then((code) => process.exit(code))
  .catch((err: unknown) => {
    const message = err instanceof Error ? err.message : String(err)
    console.error('  error:', message)
    process.exit(1)
  })
