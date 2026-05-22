/**
 * POST /api/v1/admin
 *
 * Manual bearer-token-authenticated operations on the threat intel store.
 * Only used by operators via curl — not wired into any client.
 *
 *   { "action": "flush" }                       → wipe everything
 *   { "action": "remove", "package": "x@1.0" }  → unflag one package
 *
 * Port of api/v1/admin.ts.
 */
import {
  getRedis,
  FLAGGED_KEY,
  STATS_KEY,
  RECENT_KEY,
  CATEGORIES_KEY,
  json,
  preflight,
  type Env,
} from '../../_lib/redis'

export const onRequestOptions = preflight

export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
  const secret = env.ADMIN_SECRET
  if (!secret) return json({ error: 'admin not configured' }, { status: 500 })

  const auth = request.headers.get('authorization')
  if (auth !== `Bearer ${secret}`) {
    return json({ error: 'unauthorized' }, { status: 401 })
  }

  const redis = getRedis(env)
  if (!redis) return json({ error: 'redis not configured' }, { status: 500 })

  let body: any
  try {
    body = await request.json()
  } catch {
    return json({ error: 'invalid JSON' }, { status: 400 })
  }

  const action = body?.action
  if (action === 'flush') {
    await Promise.all([
      redis.del(FLAGGED_KEY),
      redis.del(STATS_KEY),
      redis.del(RECENT_KEY),
      redis.del(CATEGORIES_KEY),
    ])
    return json({ flushed: true })
  }

  if (action === 'remove' && typeof body?.package === 'string') {
    const pkg = body.package
    await redis.hdel(FLAGGED_KEY, pkg)
    const count = await redis.hlen(FLAGGED_KEY)
    await redis.hset(STATS_KEY, { totalPackages: count })
    return json({ removed: pkg })
  }

  return json({ error: 'unknown action', valid: ['flush', 'remove'] }, { status: 400 })
}
