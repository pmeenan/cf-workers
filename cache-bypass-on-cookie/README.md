# Bypass Cache on Cookie
Example of how to bypass cache based on request cookies or URL path. The specific cookies and URL paths can be modified as needed at the top of the script.

There is no explicit way to bypass the cache when "Cache Everything" is enabled and an explicit Edge TTL is configured (yet anyway) so the worker modifies the request URL to make it unique so it will not match the current cache and will go all the way through to the origin. It does require that the origin just ignore unknown query parameters but most do so it should work for most deployments.

As-configured it is set up for a default WordPress deployment with the default WordPress cookies configured for bypass as well as the /wp-admin/ path.

The worker currently bypasses ALL requests, not just HTML requests. It can be modified to only inspect HTML requests or pretty much any other arbitrary rules for when to bypass the cache.

The worker does not actively manage the cache (extending cache times, purging, etc) = it strictly bypasses any existing caches when the configured rules are matched.