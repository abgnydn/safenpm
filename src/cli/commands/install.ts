import { install } from '../../install'
import { getReporter } from '../../report'
import { isParseError, parseInstallArgs } from '../args'

export async function run(args: readonly string[]): Promise<number> {
  const parsed = parseInstallArgs(args)
  if (isParseError(parsed)) {
    getReporter({ json: false }).error(parsed.message)
    return 1
  }
  await install(parsed)
  return 0
}
