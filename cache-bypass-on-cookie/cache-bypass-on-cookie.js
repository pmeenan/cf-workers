// Cookie prefixes that cause a request to bypass the cache when present.
const BYPASS_COOKIE_PREFIXES = [
  "wp-",
  "wordpress",
  "comment_",
  "woocommerce_"
];

// URL paths to bypass the cache (each pattern is a regex)
const BYPASS_URL_PATTERNS = [
  /\/wp-admin\/.*/
];

 /**
 * Main worker entry point.
 */
addEventListener("fetch", event => {
  //event.passThroughOnException();
  const request = event.request;
  if (bypassCache(request)) {
    event.respondWith(handleRequest(request));
  }
});

/**
 * Do all of the work to bypass the cache
 * @param {Request} request - Original request
 */
async function handleRequest(request) {
    // Clone the request so we can add a no-cache, no-store Cache-Control request header.
    let init = {
      method: request.method,
      headers: [...request.headers],
      redirect: "manual",
      body: request.body,
      cf: { cacheTtl: 0 }
    };

    // Use a unique URL (query params) to make SURE the cache is busted for this request
    let uniqueUrl = await generateUniqueUrl(request);
    let newRequest = new Request(uniqueUrl, init);
    newRequest.headers.set('Cache-Control', 'no-cache, no-store');

    // For debugging, clone the response and add some debug headers
    let response = await fetch(newRequest);
    let newResponse = new Response(response.body, response);
    newResponse.headers.set('X-Bypass-Cache', 'Bypassed');
    return newResponse;
}

/**
 * Determine if the given request needs to bypass the cache.
 * @param {Request} request - inbound request.
 * @returns {bool} true if the cache should be bypassed
 */
function bypassCache(request) {
  let needsBypass = false;

  // Bypass the cache for all requests to a URL that matches any of the URL path bypass patterns
  const url = new URL(request.url);
  const path = url.pathname + url.search;
  if (BYPASS_URL_PATTERNS.length) {
    for (let pattern of BYPASS_URL_PATTERNS) {
      if (path.match(pattern)) {
        needsBypass = true;
        break;
      }
    }
  }

  // Bypass the cache if the request contains a cookie that starts with one of the pre-configured prefixes
  if (!needsBypass) {
    const cookieHeader = request.headers.get('cookie');
    if (cookieHeader && cookieHeader.length && BYPASS_COOKIE_PREFIXES.length) {
      const cookies = cookieHeader.split(';');
      for (let cookie of cookies) {
        // See if the cookie starts with any of the logged-in user prefixes
        for (let prefix of BYPASS_COOKIE_PREFIXES) {
          if (cookie.trim().startsWith(prefix)) {
            needsBypass = true;
            break;
          }
        }
        if (needsBypass) {
          break;
        }
      }
    }
  }

  return needsBypass;
}

/**
 * Generate a unique URL so it will never match in the cache.
 * This is a bit of a hack since there is no way to explicitly bypass the Cloudflare cache (yet)
 * and requires that the origin will ignore unknown query parameters.
 * @param {Request} request - Original request
 */
async function generateUniqueUrl(request) {
  let url = request.url;
  let timeInMs = Date.now();
  let hashString = '';
  for (let header of request.headers) {
    hashString += header[0] + ': ' + header[1] + '\n';
  }
  const encoder = new TextEncoder();
  const digest = await crypto.subtle.digest('SHA-512', encoder.encode(hashString));
  const base64digest = btoa(String.fromCharCode(...new Uint8Array(digest)));
  const unique = encodeURIComponent(base64digest) + '.' + timeInMs;
  if (url.indexOf('?') >= 0) {
    url += '&';
  } else {
    url += '?';
  }
  url += 'cf_cache_bust=' + unique;
  return url;
}