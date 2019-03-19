# Cloudflare Workers
Collection of Cloudflare Worker scripts, generally focused on performance optimizations.

* [streaming-optimizations](streaming-optimizations) - Combined set of scripts to operate on streaming responses. This is a subset of the optimizations that doesn't include any workers that need the full HTML response to work.
* [optimization-pack](optimization-pack) - Collection of all optimizations in a single worker. This operates on blocking responses and processes the full HTML with no streaming which can cause pages that rely on early flushing to perform slower (rare but worth being aware of).
* [cache-bypass-on-cookie](cache-bypass-on-cookie) - Bypass an upstream cache (including the Cloudflare cache) for requests with specific cookies or in specific URL paths.
