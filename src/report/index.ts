/**
 * Public surface of the report module.
 * Internals (`human.ts`, `json.ts`) are implementation-private — every
 * external caller should go through `getReporter()` and the
 * `Reporter` interface.
 */
export type { Reporter } from './reporter'
export { getReporter } from './reporter'
export { createHumanReporter } from './human'
export { createJsonReporter } from './json'
