import { describe, expect, it } from 'vitest'
import { STRIPPED_ENV_KEYS, cleanEnv } from './env'

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
})
