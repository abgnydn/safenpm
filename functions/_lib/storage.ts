/**
 * KV-backed storage facade for the safenpm Pages Functions.
 *
 * Replaces the original Upstash Redis client. The handlers use a small
 * subset of Redis primitives (strings + counters + a hash + a list + a
 * sorted set + a set); this module models each on top of Cloudflare
 * Workers KV's `get`/`put`/`delete`/`list` surface so we can eliminate
 * the third-party Upstash dependency and keep everything inside the
 * Pages project's own auth boundary.
 *
 * Consistency notes — KV is eventually consistent across regions
 * (read-your-write is per-region). For threat-intel:
 *
 *   • `incr()`, `listPush()`, `sortedIncrBy()`, `setAdd()` all
 *     read-modify-write a single key. Concurrent writes can lose at
 *     most one update. For a rate-limit counter at the safenpm volume
 *     that means an attacker MIGHT fire 21 reports in a 20/hr window
 *     instead of 20. We accept that drift.
 *
 *   • The hash backing FLAGGED_KEY uses one KV key per field
 *     (`flagged:<pkg>@<ver>`), so concurrent writes to different
 *     packages don't conflict. Concurrent writes to the SAME
 *     package version still race; on contention the loser's update
 *     is lost. Same trade-off as above.
 *
 *   • `hashGetAll()` is implemented as `kv.list({ prefix })` + N gets.
 *     Above ~1000 entries this gets slow and we hit list pagination.
 *     We currently use it only in stats.ts for the dashboard summary;
 *     the result is cached by Cloudflare for 30s so the cost is
 *     amortised.
 */

import type { KVNamespace } from '@cloudflare/workers-types'

// ── Env binding ────────────────────────────────────────────────────────

export interface Env {
  SAFENPM_KV?: KVNamespace
  ADMIN_SECRET?: string
}

export function getStorage(env: Env): Storage | null {
  return env.SAFENPM_KV ? new KvStorage(env.SAFENPM_KV) : null
}

// ── Public surface ─────────────────────────────────────────────────────

export interface Storage {
  // String primitives
  getString(key: string): Promise<string | null>
  setString(key: string, value: string, opts?: { ttlSec?: number }): Promise<void>
  del(key: string): Promise<void>

  // Counter with TTL (used by the rate-limit key)
  incrWithTtl(key: string, ttlSec: number): Promise<number>

  // Hash modelled as `<prefix>:<field>`
  hashGet(prefix: string, field: string): Promise<string | null>
  hashSet(prefix: string, field: string, value: string): Promise<void>
  hashDel(prefix: string, field: string): Promise<void>
  hashGetAll(prefix: string): Promise<Record<string, string>>
  hashLen(prefix: string): Promise<number>
  hashIncrBy(prefix: string, field: string, delta: number): Promise<number>
  hashClear(prefix: string): Promise<void>

  // List modelled as JSON `string[]` under one key
  listPush(key: string, value: string): Promise<void>
  listRange(key: string, start: number, end: number): Promise<string[]>
  listTrim(key: string, start: number, end: number): Promise<void>

  // Sorted set modelled as JSON `Record<member, score>` under one key
  sortedIncrBy(key: string, delta: number, member: string): Promise<number>
  sortedRange(key: string, opts: { rev: boolean }): Promise<Array<[string, number]>>
  sortedClear(key: string): Promise<void>

  // Set modelled as JSON `string[]` (dedup) with optional TTL
  setAdd(key: string, member: string, opts?: { ttlSec?: number }): Promise<boolean>
}

// ── Implementation ─────────────────────────────────────────────────────

class KvStorage implements Storage {
  constructor(private readonly kv: KVNamespace) {}

  async getString(key: string): Promise<string | null> {
    return this.kv.get(key)
  }
  async setString(key: string, value: string, opts?: { ttlSec?: number }): Promise<void> {
    await this.kv.put(key, value, opts?.ttlSec ? { expirationTtl: opts.ttlSec } : undefined)
  }
  async del(key: string): Promise<void> {
    await this.kv.delete(key)
  }

  async incrWithTtl(key: string, ttlSec: number): Promise<number> {
    const raw = await this.kv.get(key)
    const current = raw === null ? 0 : Number(raw) || 0
    const next = current + 1
    await this.kv.put(key, String(next), { expirationTtl: ttlSec })
    return next
  }

  // ── Hash ──
  // Layout: each field becomes its own KV key `<prefix>:<field>`. This
  // gives us O(1) get/set per field and avoids the read-modify-write
  // cost of a one-blob model, at the cost of `hashGetAll` doing a
  // list+N-gets walk. The walk is fine for our two callers (stats +
  // intel batch); FLAGGED_KEY is the hottest hash and we never
  // iterate it on the install path.

  async hashGet(prefix: string, field: string): Promise<string | null> {
    return this.kv.get(`${prefix}:${field}`)
  }
  async hashSet(prefix: string, field: string, value: string): Promise<void> {
    await this.kv.put(`${prefix}:${field}`, value)
  }
  async hashDel(prefix: string, field: string): Promise<void> {
    await this.kv.delete(`${prefix}:${field}`)
  }
  async hashGetAll(prefix: string): Promise<Record<string, string>> {
    const out: Record<string, string> = {}
    let cursor: string | undefined
    do {
      const list = await this.kv.list({ prefix: `${prefix}:`, cursor })
      const keys = list.keys.map((k) => k.name)
      const values = await Promise.all(keys.map((k) => this.kv.get(k)))
      for (let i = 0; i < keys.length; i++) {
        const field = keys[i]!.slice(prefix.length + 1)
        const v = values[i]
        if (v !== null) out[field] = v
      }
      cursor = list.list_complete ? undefined : list.cursor
    } while (cursor)
    return out
  }
  async hashLen(prefix: string): Promise<number> {
    let count = 0
    let cursor: string | undefined
    do {
      const list = await this.kv.list({ prefix: `${prefix}:`, cursor })
      count += list.keys.length
      cursor = list.list_complete ? undefined : list.cursor
    } while (cursor)
    return count
  }
  async hashIncrBy(prefix: string, field: string, delta: number): Promise<number> {
    const key = `${prefix}:${field}`
    const raw = await this.kv.get(key)
    const current = raw === null ? 0 : Number(raw) || 0
    const next = current + delta
    await this.kv.put(key, String(next))
    return next
  }
  async hashClear(prefix: string): Promise<void> {
    let cursor: string | undefined
    do {
      const list = await this.kv.list({ prefix: `${prefix}:`, cursor })
      await Promise.all(list.keys.map((k) => this.kv.delete(k.name)))
      cursor = list.list_complete ? undefined : list.cursor
    } while (cursor)
  }

  // ── List (one-blob JSON model) ──
  // Read-modify-write on a single key. RECENT_KEY is capped at 100
  // entries via ltrim, so the blob stays small and the RMW race is
  // bounded to "we sometimes drop one signal from the recent feed".

  async listPush(key: string, value: string): Promise<void> {
    const arr = await this.readList(key)
    arr.unshift(value) // lpush semantics: newest first
    await this.kv.put(key, JSON.stringify(arr))
  }
  async listRange(key: string, start: number, end: number): Promise<string[]> {
    const arr = await this.readList(key)
    // Redis lrange is inclusive on both ends; negative indices count from the tail.
    const len = arr.length
    const lo = start < 0 ? Math.max(0, len + start) : Math.min(start, len)
    const hi = end < 0 ? Math.max(-1, len + end) : Math.min(end, len - 1)
    return arr.slice(lo, hi + 1)
  }
  async listTrim(key: string, start: number, end: number): Promise<void> {
    const trimmed = await this.listRange(key, start, end)
    await this.kv.put(key, JSON.stringify(trimmed))
  }
  private async readList(key: string): Promise<string[]> {
    const raw = await this.kv.get(key)
    if (!raw) return []
    try {
      const parsed = JSON.parse(raw)
      return Array.isArray(parsed) ? parsed.filter((x): x is string => typeof x === 'string') : []
    } catch {
      return []
    }
  }

  // ── Sorted set (one-blob JSON model) ──
  // CATEGORIES_KEY has at most one entry per reason string (~12 fixed
  // reasons in the validator's VALID_REASONS set), so the blob is
  // tiny and RMW is fine.

  async sortedIncrBy(key: string, delta: number, member: string): Promise<number> {
    const obj = await this.readSorted(key)
    obj[member] = (obj[member] ?? 0) + delta
    await this.kv.put(key, JSON.stringify(obj))
    return obj[member]
  }
  async sortedRange(key: string, opts: { rev: boolean }): Promise<Array<[string, number]>> {
    const obj = await this.readSorted(key)
    const entries: Array<[string, number]> = Object.entries(obj)
    entries.sort((a, b) => (opts.rev ? b[1] - a[1] : a[1] - b[1]))
    return entries
  }
  async sortedClear(key: string): Promise<void> {
    await this.kv.delete(key)
  }
  private async readSorted(key: string): Promise<Record<string, number>> {
    const raw = await this.kv.get(key)
    if (!raw) return {}
    try {
      const parsed = JSON.parse(raw)
      if (!parsed || typeof parsed !== 'object') return {}
      const out: Record<string, number> = {}
      for (const [k, v] of Object.entries(parsed)) {
        if (typeof v === 'number') out[k] = v
      }
      return out
    } catch {
      return {}
    }
  }

  // ── Set (one-blob JSON dedup) ──
  // Used by the reporters-per-(pkg@ver) set. With a 90-day TTL and a
  // sane Sybil-resistance threshold the set rarely exceeds the
  // protected-threshold size (≤15 entries), so the blob stays small.

  async setAdd(key: string, member: string, opts?: { ttlSec?: number }): Promise<boolean> {
    const raw = await this.kv.get(key)
    let arr: string[] = []
    if (raw) {
      try {
        const parsed = JSON.parse(raw)
        if (Array.isArray(parsed)) arr = parsed.filter((x): x is string => typeof x === 'string')
      } catch { /* fall through to empty */ }
    }
    if (arr.includes(member)) {
      // Member already present — refresh TTL but report "not new".
      await this.kv.put(key, JSON.stringify(arr), opts?.ttlSec ? { expirationTtl: opts.ttlSec } : undefined)
      return false
    }
    arr.push(member)
    await this.kv.put(key, JSON.stringify(arr), opts?.ttlSec ? { expirationTtl: opts.ttlSec } : undefined)
    return true
  }
}

// ── Key constants — moved from the old redis.ts ────────────────────────

// Hash: pkg@version -> FlaggedEntry JSON
export const FLAGGED_PREFIX = 'safenpm:flagged'
// Hash: counter name -> Number
export const STATS_PREFIX = 'safenpm:stats'
// List: most recent signals (capped at 100)
export const RECENT_KEY = 'safenpm:recent'
// Sorted set: reason -> count
export const CATEGORIES_KEY = 'safenpm:categories'
// String prefix: per-machineId rate-limit counter (+ TTL)
export const RATE_LIMIT_PREFIX = 'safenpm:ratelimit'
// String prefix: per-(machineId, pkg@ver) 24h dedup marker (+ TTL)
export const DEDUP_PREFIX = 'safenpm:dedup'
// Set prefix: per-(pkg@ver) reporters (Sybil-resistant distinct counter)
export const REPORTERS_PREFIX = 'safenpm:reporters'

// ── HTTP helpers — unchanged from redis.ts ─────────────────────────────

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
