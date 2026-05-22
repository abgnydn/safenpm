/**
 * POST /api/v1/admin
 *
 * Manual bearer-token-authenticated operations on the threat intel
 * store. Only used by operators via curl — not wired into any client.
 *
 *   { "action": "flush" }                       → wipe everything
 *   { "action": "remove", "package": "x@1.0" }  → unflag one package
 *
 * KV-backed (Cloudflare-native); the previous Upstash Redis backing
 * was retired in the 0.1 refactor.
 */
import {
  getStorage,
  FLAGGED_PREFIX,
  STATS_PREFIX,
  RECENT_KEY,
  CATEGORIES_KEY,
  json,
  preflight,
  type Env,
} from '../../_lib/storage'

export const onRequestOptions = preflight

export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
  const secret = env.ADMIN_SECRET
  if (!secret) return json({ error: 'admin not configured' }, { status: 500 })

  const auth = request.headers.get('authorization')
  if (auth !== `Bearer ${secret}`) {
    return json({ error: 'unauthorized' }, { status: 401 })
  }

  const storage = getStorage(env)
  if (!storage) return json({ error: 'storage not configured' }, { status: 500 })

  let body: { action?: string; package?: string }
  try {
    body = await request.json() as { action?: string; package?: string }
  } catch {
    return json({ error: 'invalid JSON' }, { status: 400 })
  }

  const action = body?.action
  if (action === 'flush') {
    await Promise.all([
      storage.hashClear(FLAGGED_PREFIX),
      storage.hashClear(STATS_PREFIX),
      storage.del(RECENT_KEY),
      storage.sortedClear(CATEGORIES_KEY),
    ])
    return json({ flushed: true })
  }

  if (action === 'remove' && typeof body?.package === 'string') {
    const pkg = body.package
    await storage.hashDel(FLAGGED_PREFIX, pkg)
    const count = await storage.hashLen(FLAGGED_PREFIX)
    await storage.hashSet(STATS_PREFIX, 'totalPackages', String(count))
    return json({ removed: pkg })
  }

  return json({ error: 'unknown action', valid: ['flush', 'remove'] }, { status: 400 })
}
