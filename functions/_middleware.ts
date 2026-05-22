/**
 * Pages-wide middleware. Runs on every request — static asset, page,
 * or API Function — before the normal handler.
 *
 * Only job today: canonicalise `www.safenpm.dev` → `safenpm.dev`.
 * `_redirects` can't cross hostnames, the wrangler OAuth scopes don't
 * include the zone-level Rules API, and removing the www custom
 * domain from the Pages project (the other dashboard-only path)
 * would just turn www into a 1014 error. A 301 middleware is the
 * least-surgery solution and ships inside the same deploy.
 */
export const onRequest: PagesFunction = async ({ request, next }) => {
  const url = new URL(request.url)
  if (url.hostname === 'www.safenpm.dev') {
    url.hostname = 'safenpm.dev'
    return Response.redirect(url.toString(), 301)
  }
  return next()
}
