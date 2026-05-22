/**
 * Upstash Redis client for Cloudflare Pages Functions.
 *
 * The REST transport works natively in the CF Workers runtime — no Node
 * built-ins required. Credentials come from Pages environment bindings
 * rather than process.env.
 *
 * To provision these in a deployed environment:
 *   wrangler pages secret put UPSTASH_REDIS_REST_URL   --project-name=safenpm
 *   wrangler pages secret put UPSTASH_REDIS_REST_TOKEN --project-name=safenpm
 *   wrangler pages secret put ADMIN_SECRET             --project-name=safenpm
 */
import { Redis } from '@upstash/redis/cloudflare'

export interface Env {
  UPSTASH_REDIS_REST_URL?: string
  UPSTASH_REDIS_REST_TOKEN?: string
  ADMIN_SECRET?: string
}

export function getRedis(env: Env): Redis | null {
  if (!env.UPSTASH_REDIS_REST_URL || !env.UPSTASH_REDIS_REST_TOKEN) return null
  return new Redis({
    url: env.UPSTASH_REDIS_REST_URL,
    token: env.UPSTASH_REDIS_REST_TOKEN,
  })
}

// Keys — identical to the legacy api/_lib/redis.ts so existing data
// migrates cleanly.
export const SIGNALS_KEY = 'safenpm:signals'
export const STATS_KEY = 'safenpm:stats'
export const FLAGGED_KEY = 'safenpm:flagged'
export const RECENT_KEY = 'safenpm:recent'
export const CATEGORIES_KEY = 'safenpm:categories'

// Shared CORS headers — every function echoes these.
export const CORS_HEADERS: Record<string, string> = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
}

export function json(body: unknown, init?: ResponseInit): Response {
  return new Response(JSON.stringify(body), {
    status: init?.status ?? 200,
    headers: {
      'Content-Type': 'application/json',
      ...CORS_HEADERS,
      ...(init?.headers as Record<string, string> | undefined),
    },
  })
}

export const preflight: PagesFunction = async () =>
  new Response(null, { status: 204, headers: CORS_HEADERS })
