import { describe, expect, it } from 'vitest'
import { STRIPPED_ENV_KEYS, cleanEnv, shouldStrip } from './env'

describe('STRIPPED_ENV_KEYS', () => {
  it('contains the documented credential-bearing keys', () => {
    // Matches the README's threat-model section.
    expect(new Set(STRIPPED_ENV_KEYS)).toEqual(new Set([
      'npm_config_authtoken',
      'NPM_TOKEN', 'GITHUB_TOKEN', 'GH_TOKEN', 'GITLAB_TOKEN',
      'AWS_SECRET_ACCESS_KEY', 'AWS_ACCESS_KEY_ID', 'AWS_SESSION_TOKEN',
      'AZURE_CLIENT_SECRET', 'GOOGLE_APPLICATION_CREDENTIALS',
    ]))
  })
})

describe('cleanEnv', () => {
  it('undefines every stripped key', () => {
    const env = cleanEnv({
      GITHUB_TOKEN: 'leak',
      NPM_TOKEN: 'leak',
      AWS_SECRET_ACCESS_KEY: 'leak',
      KEEP: 'ok',
    })
    expect(env.GITHUB_TOKEN).toBeUndefined()
    expect(env.NPM_TOKEN).toBeUndefined()
    expect(env.AWS_SECRET_ACCESS_KEY).toBeUndefined()
    expect(env.KEEP).toBe('ok')
  })

  it('does not mutate the source env', () => {
    const source = { GITHUB_TOKEN: 'leak', PATH: '/bin' }
    cleanEnv(source)
    expect(source.GITHUB_TOKEN).toBe('leak')
  })

  it('strips even when the source has additional unrelated keys', () => {
    const env = cleanEnv({ HOME: '/tmp', NPM_TOKEN: 'x' })
    expect(env.HOME).toBe('/tmp')
    expect(env.NPM_TOKEN).toBeUndefined()
  })

  it('strips regex-matched custom credential names not in the explicit list', () => {
    const env = cleanEnv({
      COMPANY_API_KEY: 'leak',
      INTERNAL_DEPLOY_TOKEN: 'leak',
      MY_DB_PASSWORD: 'leak',
      USER_SESSION_TOKEN: 'leak',
      VAULT_SECRET: 'leak',
      DB_PWD: 'leak',
      GCP_CREDENTIALS: 'leak',
      HOME: '/tmp',
    })
    expect(env.COMPANY_API_KEY).toBeUndefined()
    expect(env.INTERNAL_DEPLOY_TOKEN).toBeUndefined()
    expect(env.MY_DB_PASSWORD).toBeUndefined()
    expect(env.USER_SESSION_TOKEN).toBeUndefined()
    expect(env.VAULT_SECRET).toBeUndefined()
    expect(env.DB_PWD).toBeUndefined()
    expect(env.GCP_CREDENTIALS).toBeUndefined()
    expect(env.HOME).toBe('/tmp')
  })

  it('strips bare TOKEN / SECRET / API_KEY (whole-name match)', () => {
    const env = cleanEnv({ TOKEN: 'x', SECRET: 'y', API_KEY: 'z', PATH: '/bin' })
    expect(env.TOKEN).toBeUndefined()
    expect(env.SECRET).toBeUndefined()
    expect(env.API_KEY).toBeUndefined()
    expect(env.PATH).toBe('/bin')
  })

  it('keeps well-known XDG_* and SSH_AUTH_SOCK to avoid breaking native compiles', () => {
    const env = cleanEnv({
      SSH_AUTH_SOCK: '/tmp/sock',
      XDG_CONFIG_HOME: '/home/u/.config',
      XDG_DATA_HOME: '/home/u/.local/share',
    })
    expect(env.SSH_AUTH_SOCK).toBe('/tmp/sock')
    expect(env.XDG_CONFIG_HOME).toBe('/home/u/.config')
    expect(env.XDG_DATA_HOME).toBe('/home/u/.local/share')
  })
})

describe('shouldStrip', () => {
  it('returns true for explicit list entries', () => {
    expect(shouldStrip('AWS_SECRET_ACCESS_KEY')).toBe(true)
    expect(shouldStrip('GITHUB_TOKEN')).toBe(true)
  })

  it('returns true for regex-matched custom names', () => {
    expect(shouldStrip('SOME_API_KEY')).toBe(true)
    expect(shouldStrip('UPSTASH_REDIS_REST_TOKEN')).toBe(true)
    expect(shouldStrip('FOO_PASSWORD')).toBe(true)
    expect(shouldStrip('BAR_SECRET')).toBe(true)
  })

  it('returns false for ordinary env vars', () => {
    expect(shouldStrip('HOME')).toBe(false)
    expect(shouldStrip('PATH')).toBe(false)
    expect(shouldStrip('LANG')).toBe(false)
  })

  it('returns false for the XDG/SSH_AUTH keep-list even when name matches a pattern', () => {
    expect(shouldStrip('SSH_AUTH_SOCK')).toBe(false)
  })
})
