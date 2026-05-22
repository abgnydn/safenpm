/**
 * Sensitive credential-bearing env vars stripped from every sandboxed
 * child process. Any tool that wants to exfiltrate via env must first
 * be on the allowlist — at which point it isn't sandboxed at all.
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

export function cleanEnv(source: NodeJS.ProcessEnv = process.env): Record<string, string | undefined> {
  const env = { ...source }
  for (const key of STRIPPED_ENV_KEYS) {
    env[key] = undefined
  }
  return env
}
