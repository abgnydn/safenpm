/**
 * Unit tests for the KV-backed storage facade. Uses an in-memory mock
 * of Cloudflare's KVNamespace so we exercise the Redis-shape adapter
 * without needing a real Workers runtime.
 */
import { beforeEach, describe, expect, it } from 'vitest'
import { getStorage, type Env, type Storage } from './storage'

// Minimal in-memory mock of the KVNamespace surface our facade uses.
// We model TTL as { value, expiresAt } and let calls beyond expiry
// return null, matching KV's behaviour.
class MockKV {
  private store = new Map<string, { value: string; expiresAt: number | null }>()

  async get(key: string): Promise<string | null> {
    const entry = this.store.get(key)
    if (!entry) return null
    if (entry.expiresAt !== null && Date.now() > entry.expiresAt) {
      this.store.delete(key)
      return null
    }
    return entry.value
  }
  async put(key: string, value: string, opts?: { expirationTtl?: number }): Promise<void> {
    const expiresAt = opts?.expirationTtl ? Date.now() + opts.expirationTtl * 1000 : null
    this.store.set(key, { value, expiresAt })
  }
  async delete(key: string): Promise<void> {
    this.store.delete(key)
  }
  async list(opts: { prefix?: string; cursor?: string }): Promise<{
    keys: Array<{ name: string }>; list_complete: boolean; cursor?: string
  }> {
    const prefix = opts.prefix ?? ''
    const keys = [...this.store.keys()]
      .filter((k) => k.startsWith(prefix))
      .map((name) => ({ name }))
    return { keys, list_complete: true }
  }
}

let storage: Storage
beforeEach(() => {
  const env: Env = { SAFENPM_KV: new MockKV() as any }
  storage = getStorage(env)!
})

describe('strings + TTL', () => {
  it('round-trips a string', async () => {
    await storage.setString('k', 'v')
    expect(await storage.getString('k')).toBe('v')
  })

  it('returns null for missing keys', async () => {
    expect(await storage.getString('missing')).toBeNull()
  })

  it('respects TTL — entry disappears after expiry', async () => {
    await storage.setString('k', 'v', { ttlSec: -1 }) // already expired
    expect(await storage.getString('k')).toBeNull()
  })

  it('del removes a key', async () => {
    await storage.setString('k', 'v')
    await storage.del('k')
    expect(await storage.getString('k')).toBeNull()
  })
})

describe('incrWithTtl', () => {
  it('starts at 1 for a fresh key', async () => {
    expect(await storage.incrWithTtl('rate', 60)).toBe(1)
  })

  it('increments on repeat calls', async () => {
    await storage.incrWithTtl('rate', 60)
    await storage.incrWithTtl('rate', 60)
    expect(await storage.incrWithTtl('rate', 60)).toBe(3)
  })

  it('resets to 0 after TTL expiry', async () => {
    await storage.incrWithTtl('rate', -1) // immediate expiry
    expect(await storage.incrWithTtl('rate', 60)).toBe(1)
  })
})

describe('hash (modelled as prefix:field)', () => {
  it('hashGet returns null for missing fields', async () => {
    expect(await storage.hashGet('h', 'missing')).toBeNull()
  })

  it('hashSet + hashGet round-trip per-field', async () => {
    await storage.hashSet('h', 'a', 'A')
    await storage.hashSet('h', 'b', 'B')
    expect(await storage.hashGet('h', 'a')).toBe('A')
    expect(await storage.hashGet('h', 'b')).toBe('B')
  })

  it('hashGetAll returns every field under the prefix', async () => {
    await storage.hashSet('h', 'a', 'A')
    await storage.hashSet('h', 'b', 'B')
    expect(await storage.hashGetAll('h')).toEqual({ a: 'A', b: 'B' })
  })

  it('hashGetAll does NOT leak fields from neighbouring prefixes', async () => {
    await storage.hashSet('h1', 'a', '1A')
    await storage.hashSet('h2', 'a', '2A')
    expect(await storage.hashGetAll('h1')).toEqual({ a: '1A' })
  })

  it('hashLen counts only fields under the prefix', async () => {
    await storage.hashSet('h', 'a', 'A')
    await storage.hashSet('h', 'b', 'B')
    await storage.hashSet('other', 'x', 'X')
    expect(await storage.hashLen('h')).toBe(2)
  })

  it('hashIncrBy starts at delta for a fresh field', async () => {
    expect(await storage.hashIncrBy('counters', 'x', 3)).toBe(3)
    expect(await storage.hashIncrBy('counters', 'x', 4)).toBe(7)
  })

  it('hashDel removes a single field', async () => {
    await storage.hashSet('h', 'a', 'A')
    await storage.hashDel('h', 'a')
    expect(await storage.hashGet('h', 'a')).toBeNull()
  })

  it('hashClear removes every field under the prefix', async () => {
    await storage.hashSet('h', 'a', 'A')
    await storage.hashSet('h', 'b', 'B')
    await storage.hashClear('h')
    expect(await storage.hashLen('h')).toBe(0)
  })
})

describe('list (modelled as JSON array, lpush semantics)', () => {
  it('returns [] for a missing list', async () => {
    expect(await storage.listRange('l', 0, -1)).toEqual([])
  })

  it('listPush prepends (newest first)', async () => {
    await storage.listPush('l', 'a')
    await storage.listPush('l', 'b')
    await storage.listPush('l', 'c')
    expect(await storage.listRange('l', 0, -1)).toEqual(['c', 'b', 'a'])
  })

  it('listRange handles inclusive end + negative indices', async () => {
    await storage.listPush('l', 'a')
    await storage.listPush('l', 'b')
    await storage.listPush('l', 'c')
    expect(await storage.listRange('l', 0, 1)).toEqual(['c', 'b'])
    expect(await storage.listRange('l', -2, -1)).toEqual(['b', 'a'])
  })

  it('listTrim caps the list at the kept range', async () => {
    for (const v of ['a', 'b', 'c', 'd']) await storage.listPush('l', v)
    await storage.listTrim('l', 0, 1) // keep newest two
    expect(await storage.listRange('l', 0, -1)).toEqual(['d', 'c'])
  })
})

describe('sorted set (member → score)', () => {
  it('sortedIncrBy starts at delta', async () => {
    expect(await storage.sortedIncrBy('z', 1, 'foo')).toBe(1)
    expect(await storage.sortedIncrBy('z', 4, 'foo')).toBe(5)
  })

  it('sortedRange { rev: true } returns descending by score', async () => {
    await storage.sortedIncrBy('z', 3, 'a')
    await storage.sortedIncrBy('z', 7, 'b')
    await storage.sortedIncrBy('z', 1, 'c')
    expect(await storage.sortedRange('z', { rev: true })).toEqual([
      ['b', 7], ['a', 3], ['c', 1],
    ])
  })

  it('sortedRange { rev: false } returns ascending by score', async () => {
    await storage.sortedIncrBy('z', 3, 'a')
    await storage.sortedIncrBy('z', 7, 'b')
    expect(await storage.sortedRange('z', { rev: false })).toEqual([
      ['a', 3], ['b', 7],
    ])
  })

  it('sortedClear empties the set', async () => {
    await storage.sortedIncrBy('z', 1, 'a')
    await storage.sortedClear('z')
    expect(await storage.sortedRange('z', { rev: true })).toEqual([])
  })
})

describe('set (Sybil-resistant dedup)', () => {
  it('first add returns true (new)', async () => {
    expect(await storage.setAdd('s', 'm1')).toBe(true)
  })

  it('repeat add of the same member returns false', async () => {
    await storage.setAdd('s', 'm1')
    expect(await storage.setAdd('s', 'm1')).toBe(false)
  })

  it('distinct members each return true', async () => {
    expect(await storage.setAdd('s', 'm1')).toBe(true)
    expect(await storage.setAdd('s', 'm2')).toBe(true)
    expect(await storage.setAdd('s', 'm3')).toBe(true)
  })

  it('TTL: re-adding refreshes expiry', async () => {
    await storage.setAdd('s', 'm1', { ttlSec: 60 })
    await storage.setAdd('s', 'm1', { ttlSec: 60 }) // refresh
    // We don't assert exact TTL here — KV mock doesn't expose it — but
    // we do assert idempotency: count stays at 1.
    expect(await storage.setAdd('s', 'm1')).toBe(false)
  })
})

describe('getStorage', () => {
  it('returns null when SAFENPM_KV is not bound', () => {
    expect(getStorage({})).toBeNull()
  })

  it('returns a Storage when SAFENPM_KV is bound', () => {
    expect(getStorage({ SAFENPM_KV: new MockKV() as any })).not.toBeNull()
  })
})
