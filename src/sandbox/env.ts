/**
 * Sensitive credential-bearing env vars stripped from every sandboxed
 * child process. Any tool that wants to exfiltrate via env must first
 * be on the allowlist — at which point it isn't sandboxed at all.
 *
 * Two filters layered together:
 *  - `STRIPPED_ENV_KEYS` is the explicit list of well-known names that
 *    don't fit a tidy pattern (`AWS_SECRET_ACCESS_KEY`,
 *    `GOOGLE_APPLICATION_CREDENTIALS`, …).
 *  - `STRIPPED_ENV_PATTERNS` is a regex layer that catches the
 *    organisation-specific credential-y names that the explicit list
 *    won't have (`COMPANY_API_KEY`, `INTERNAL_DEPLOY_TOKEN`, anything
 *    ending in `_TOKEN` / `_SECRET` / `_KEY` / `_PASSWORD` / `_PWD`).
 *
 * Tracked separately from the sandbox profiles because all backends
 * (mac, linux, windows, wsl, even unsandboxed) apply the same redaction.
 */
export const STRIPPED_ENV_KEYS: readonly string[] = [
  'npm_config_authtoken',
  'NPM_TOKEN',
  'GITHUB_TOKEN',
  'GH_TOKEN',
  'GITLAB_TOKEN',
  'AWS_SECRET_ACCESS_KEY',
  'AWS_ACCESS_KEY_ID',
  'AWS_SESSION_TOKEN',
  'AZURE_CLIENT_SECRET',
  'GOOGLE_APPLICATION_CREDENTIALS',
] as const

/**
 * Any env var name matching one of these is stripped. Suffix-based so
 * we don't have to chase every org's naming convention. The patterns
 * are case-insensitive — `MY_API_KEY`, `my_api_key`, `MyApiKey` all
 * match. The explicit `node:` and `npm_config_` prefixes are
 * deliberately *not* stripped via the regex; only the explicit list
 * covers `npm_config_authtoken`.
 */
export const STRIPPED_ENV_PATTERNS: readonly RegExp[] = [
  /_TOKEN$/i,
  /_SECRET$/i,
  /_KEY$/i,
  /_PASSWORD$/i,
  /_PWD$/i,
  /_CREDENTIALS?$/i,
  /^TOKEN$/i,
  /^SECRET$/i,
  /^API[_-]?KEY$/i,
  /SESSION[_-]?TOKEN$/i,
]

/**
 * Suffix-shape names that look credential-bearing but are ubiquitous
 * harmless config (`SSH_AUTH_SOCK`, `KEYCHAIN_NAME`, etc.). Listed
 * here so the regex layer doesn't false-positive and break native
 * compilations that look at these for legitimate reasons.
 */
const ENV_KEEP_LIST: ReadonlySet<string> = new Set([
  'SSH_AUTH_SOCK',
  'XDG_CONFIG_HOME',
  'XDG_DATA_HOME',
  'XDG_CACHE_HOME',
  'XDG_RUNTIME_DIR',
])

export function shouldStrip(key: string): boolean {
  if (ENV_KEEP_LIST.has(key)) return false
  if ((STRIPPED_ENV_KEYS as readonly string[]).includes(key)) return true
  return STRIPPED_ENV_PATTERNS.some((p) => p.test(key))
}

export function cleanEnv(source: NodeJS.ProcessEnv = process.env): Record<string, string | undefined> {
  const env = { ...source }
  for (const key of Object.keys(env)) {
    if (shouldStrip(key)) env[key] = undefined
  }
  return env
}
