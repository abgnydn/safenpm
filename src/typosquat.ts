/**
 * Typosquat detection — catches packages with names suspiciously
 * close to popular npm packages. Uses Levenshtein distance + common
 * attack patterns (swapped chars, missing chars, scope confusion).
 */

// Critical packages that get stricter typosquat detection thresholds.
// These are extremely high-value targets for supply-chain attacks.
const CRITICAL_PACKAGES = new Set([
  'react', 'lodash', 'express', 'axios', 'next', 'vue', 'angular',
  'webpack', 'typescript', 'eslint', 'jest', 'electron', 'prisma',
  'jsonwebtoken', 'bcrypt', 'passport', 'mongoose', 'sequelize',
  'graphql', 'fastify', 'esbuild', 'vite',
])

// Top npm packages by weekly downloads — curated watchlist
const POPULAR_PACKAGES = [
  'lodash', 'react', 'express', 'axios', 'chalk', 'commander',
  'debug', 'dotenv', 'moment', 'uuid', 'webpack', 'typescript',
  'eslint', 'prettier', 'jest', 'mocha', 'chai', 'underscore',
  'async', 'bluebird', 'request', 'glob', 'minimist', 'yargs',
  'inquirer', 'ora', 'semver', 'mkdirp', 'rimraf', 'fs-extra',
  'colors', 'cheerio', 'puppeteer', 'mongoose', 'sequelize',
  'pg', 'mysql2', 'redis', 'jsonwebtoken', 'bcrypt', 'cors',
  'body-parser', 'cookie-parser', 'helmet', 'morgan', 'passport',
  'nodemailer', 'socket.io', 'ws', 'sharp', 'jimp', 'node-fetch',
  'cross-env', 'concurrently', 'nodemon', 'pm2', 'next', 'nuxt',
  'vue', 'angular', 'svelte', 'esbuild', 'vite', 'rollup',
  'babel-core', 'core-js', 'regenerator-runtime', 'tslib',
  'rxjs', 'graphql', 'apollo-server', 'fastify', 'koa',
  'electron', 'prisma', 'tailwindcss', 'postcss', 'autoprefixer',
]

export interface TyposquatResult {
  suspect: string
  target: string
  distance: number
  technique: string
  confidence: 'high' | 'medium' | 'low'
}

/**
 * Levenshtein distance between two strings
 */
function levenshtein(a: string, b: string): number {
  const m = a.length
  const n = b.length
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0))

  for (let i = 0; i <= m; i++) dp[i][0] = i
  for (let j = 0; j <= n; j++) dp[0][j] = j

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (a[i - 1] === b[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1]
      } else {
        dp[i][j] = 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1])
      }
    }
  }
  return dp[m][n]
}

/**
 * Check if a char swap (transposition) turns suspect into target
 */
function isTransposition(suspect: string, target: string): boolean {
  if (suspect.length !== target.length) return false
  let diffs = 0
  const diffPositions: number[] = []
  for (let i = 0; i < suspect.length; i++) {
    if (suspect[i] !== target[i]) {
      diffs++
      diffPositions.push(i)
    }
  }
  if (diffs !== 2) return false
  const [a, b] = diffPositions
  return suspect[a] === target[b] && suspect[b] === target[a]
}

/**
 * Common substitution patterns attackers use
 */
function hasCommonSubstitution(suspect: string, target: string): boolean {
  const subs: [string, string][] = [
    ['0', 'o'], ['1', 'l'], ['1', 'i'], ['rn', 'm'],
    ['vv', 'w'], ['-', ''], ['_', '-'], ['.', '-'],
  ]

  for (const [from, to] of subs) {
    if (suspect.replace(from, to) === target) return true
    if (target.replace(from, to) === suspect) return true
  }
  return false
}

/**
 * Detect scope confusion: @evil/lodash targeting lodash
 */
function stripScope(name: string): string {
  return name.startsWith('@') ? name.split('/')[1] || name : name
}

export function checkTyposquat(packageName: string): TyposquatResult | null {
  const stripped = stripScope(packageName)

  for (const target of POPULAR_PACKAGES) {
    // exact match is obviously fine
    if (packageName === target || stripped === target) {
      // scope confusion: @evil/lodash targeting lodash
      if (packageName !== target && stripped === target) {
        return {
          suspect: packageName,
          target,
          distance: 0,
          technique: 'scope-confusion',
          confidence: 'high',
        }
      }
      continue
    }

    const dist = levenshtein(stripped, target)

    // Transposition: axois → axios
    if (isTransposition(stripped, target)) {
      return {
        suspect: packageName,
        target,
        distance: dist,
        technique: 'char-swap',
        confidence: 'high',
      }
    }

    // Common substitutions: co1ors → colors
    if (hasCommonSubstitution(stripped, target)) {
      return {
        suspect: packageName,
        target,
        distance: dist,
        technique: 'substitution',
        confidence: 'high',
      }
    }

    // Edit distance 1: very suspicious, especially for critical packages
    if (dist === 1 && stripped.length >= 3) {
      // Critical packages always get 'high' confidence at distance 1
      const isCritical = CRITICAL_PACKAGES.has(target)
      return {
        suspect: packageName,
        target,
        distance: 1,
        technique: 'edit-distance-1',
        confidence: (isCritical || stripped.length <= 6) ? 'high' : 'medium',
      }
    }

    // Edit distance 2: suspicious for longer names, medium for critical packages
    if (dist === 2 && stripped.length >= 6) {
      const isCritical = CRITICAL_PACKAGES.has(target)
      return {
        suspect: packageName,
        target,
        distance: 2,
        technique: 'edit-distance-2',
        confidence: isCritical ? 'medium' : 'low',
      }
    }

    // Prefix/suffix attacks: lodash-utils, lodashx
    if (stripped.length > target.length && stripped.includes(target) && stripped.length - target.length <= 4) {
      const isCritical = CRITICAL_PACKAGES.has(target)
      return {
        suspect: packageName,
        target,
        distance: dist,
        technique: 'name-extension',
        confidence: isCritical ? 'medium' : 'low',
      }
    }
  }

  return null
}

export function checkAllTyposquats(names: string[]): TyposquatResult[] {
  const results: TyposquatResult[] = []
  for (const name of names) {
    const r = checkTyposquat(name)
    if (r) results.push(r)
  }
  return results
}
