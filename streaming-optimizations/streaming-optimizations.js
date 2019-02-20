// Enabled optimization features
ENABLE_PROXY_THIRD_PARTY = true;
ENABLE_GOOGLE_FONTS = true;
ENABLE_EDGE_CACHE = true;

// API settings if KV isn't being used for EDGE_CACHE (otherwise the EDGE_CACHE variable needs to be bound to a KV namespace for this worker)
const CLOUDFLARE_API = {
  email: "", // From https://dash.cloudflare.com/profile
  key: "",   // Global API Key from https://dash.cloudflare.com/profile
  zone: ""   // "Zone ID" from the API section of the dashboard overview page https://dash.cloudflare.com/
};

/******************************************************************************
 *  Main control flow
 *****************************************************************************/

 /**
 * Main worker entry point. Looks for font requests that are being proxied and
 * requests for HTML content. All major browsers explicitly send an accept: text/html
 * for navigational requests and the fallback is to just pass the request through
 * unmodified (safe).
 */
addEventListener("fetch", event => {
  // Fail-safe in case of an unhandled exception
  event.passThroughOnException();
  const url = new URL(event.request.url);
  if (event.request.method === 'GET' && isProxyRequest(url)) {
    // Pass the requests through to the origin server
    // (through the underlying request cache and filtering headers).
    event.respondWith(proxyRequest('https:/' + url.pathname + url.search, csp.request));
  } else {
    event.respondWith(processRequest(event.request, event));
  }
});

/******************************************************************************
 *  Application logic
 *****************************************************************************/

 // Third-party script URL prefixes to proxy and cache-extend
const SCRIPT_URLS = [
  // Hosted libraries (usually CDN's for open source).
  '/ajax.aspnetcdn.com/',
  '/ajax.cloudflare.com/',
  '/ajax.googleapis.com/',
  '/cdn.jsdelivr.net/',
  '/cdnjs.com/',
  '/cdnjs.cloudflare.com/',
  '/code.jquery.com/',
  '/maxcdn.bootstrapcdn.com/',
  '/netdna.bootstrapcdn.com/',
  '/oss.maxcdn.com/',
  '/stackpath.bootstrapcdn.com/',
  '/use.fontawesome.com/',

  // Popular scripts (can be site-specific)
  '/a.optmnstr.com/app/js/',
  '/apis.google.com/js/',
  '/bat.bing.com/',
  '/cdn.onesignal.com/sdks/',
  '/cdn.optimizely.com/',
  '/cdn.polyfill.io/',
  '/cdn.shopify.com/s/',
  '/css3-mediaqueries-js.googlecode.com/svn/',
  '/d2wy8f7a9ursnm.cloudfront.net/',
  '/html5shim.googlecode.com/svn/',
  '/html5shiv.googlecode.com/svn/',
  '/maps.google.com/maps/api/js',
  '/maps.googleapis.com/maps/api/js',
  '/pagead2.googlesyndication.com/pagead/js/',
  '/platform.twitter.com/widgets.js',
  '/platform-api.sharethis.com/js/',
  '/s7.addthis.com/js/',
  '/stats.wp.com/',
  '/ws.sharethis.com/button/',
  '/www.google.com/recaptcha/api.js',
  '/www.google-analytics.com/analytics.js',
  '/www.googletagmanager.com/gtag/js',
  '/www.googletagmanager.com/gtm.js',
  '/www.googletagservices.com/tag/js/gpt.js'
];

// Third-party stylesheet URL prefixes to proxy and cache-extend
const STYLESHEET_URLS = [
  // Hosted libraries (usually CDN's for open source).
  '/ajax.aspnetcdn.com/',
  '/ajax.cloudflare.com/',
  '/ajax.googleapis.com/',
  '/cdn.jsdelivr.net/',
  '/cdnjs.com/',
  '/cdnjs.cloudflare.com/',
  '/code.jquery.com/',
  '/fonts.googleapis.com/',
  '/maxcdn.bootstrapcdn.com/',
  '/netdna.bootstrapcdn.com/',
  '/oss.maxcdn.com/',
  '/stackpath.bootstrapcdn.com/',
  '/use.fontawesome.com/'
];

/**
 * Process chunks of HTML as they stream through
 * 
 * @param {*} content - Text chunk from the streaming HTML (or accumulated head)
 * @param {*} request - Original request object for downstream use.
 * @param {*} event - Worker event object
 * @param {bool} cspRules - Content-Security-Policy rules
*/
async function modifyHtmlChunk(content, request, event, cspRules) {

  // Call out to the individual optimizations
  if (ENABLE_GOOGLE_FONTS)
    content = await optimizeGoogleFonts(content, request, event, cspRules);
  if (ENABLE_PROXY_THIRD_PARTY)
    content = await proxyScripts(content, request, cspRules);

  return content;
}

 /**
 * See if the requested resource is a proxy request to an overwritten origin
 * (something that starts with a prefix in one of our lists).
 * 
 * @param {*} url - Requested URL
 * @param {*} request - Original Request
 * @returns {*} - true if the URL matches one of the proxy paths
 */
function isProxyRequest(url) {
  let needsProxy = false;
  if (ENABLE_GOOGLE_FONTS && url.pathname.startsWith('/fonts.gstatic.com/')) {
    needsProxy = true;
  } else if (ENABLE_PROXY_THIRD_PARTY) {
    const path = url.pathname + url.search;
    for (let prefix of SCRIPT_URLS) {
      if (path.startsWith(prefix)) {
        needsProxy = true;
        break;
      }
    }
    if (!needsProxy) {
      for (let prefix of STYLESHEET_URLS) {
        if (path.startsWith(prefix)) {
          needsProxy = true;
          break;
        }
      }
    }
  }
  return needsProxy;
}

/**
 * Handle all non-proxied requests. Send HTML or CSS on for further processing
 * and pass everything else through unmodified.
 * @param {*} request - Original request
 * @param {*} event - Original worker event
 */
async function processRequest(request, event) {
  let response = null;
  if (isEdgeCacheEnabled(request)) {
    response = await edgeCacheFetch(request, event);
  } else {
    response = await fetch(request);
  }
  if (response && response.status === 200) {
    const contentType = response.headers.get("content-type");
    if ((ENABLE_GOOGLE_FONTS || ENABLE_PROXY_THIRD_PARTY) && contentType && contentType.indexOf("text/html") !== -1) {
      return await processHtmlResponse(response, event.request, event);
    } else if (ENABLE_GOOGLE_FONTS && contentType && contentType.indexOf("text/css") !== -1) {
      return await processStylesheetResponse(response, event.request, event);
    }
  }

  return response;
}

/******************************************************************************
 *  HTML Edge Cache
 *****************************************************************************/

 /**
  * See if the edge cache is enabled and should be used
  * @param {Request} request - Original request
  * @returns {bool} true if edge caching is enabled
  */
 function isEdgeCacheEnabled(request) {
  let enabled = ENABLE_EDGE_CACHE;

  // Disable if there is a cache in front of us
  if (request.headers.get('x-HTML-Edge-Cache') !== null) {
    return false;
  }

  // Disable if KV isn't enabled or if the API key isn't configured
  if (typeof EDGE_CACHE !== 'undefined') {
    return enabled;
  }
  if (CLOUDFLARE_API.email.length && CLOUDFLARE_API.key.length && CLOUDFLARE_API.zone.length) {
    return enabled;
  }

  return false;
}

/**
 * Fetch from the edge cache if available. If not, fetch from the origin and cache if requested.
 * @param {Request} originalRequest - Original request
 * @param {Event} event - original event
 */
async function edgeCacheFetch(originalRequest, event) {
  let {response, cacheVer, status, bypassCache} = await getEdgeCachedResponse(originalRequest);

  if (response === null) {
    // Clone the request, add the edge-cache header and send it through.
    let request = new Request(originalRequest);
    request.headers.set('x-HTML-Edge-Cache', 'supports=cache|purgeall|bypass-cookies');
    response = await fetch(request);

    if (response) {
      const options = getEdgeCacheResponseOptions(response);
      if (options.purge) {
        await purgeEdgeCache(cacheVer, event);
        status += ', Purged';
      }
      if (options.cache && !bypassCache) {
        status += await cacheEdgeResponse(cacheVer, originalRequest, response, event);
      }
    }
  }

  const accept = originalRequest.headers.get('Accept');
  if (response && status !== null && originalRequest.method === 'GET' && response.status === 200 && accept && accept.indexOf('text/html') >= 0) {
    response = new Response(response.body, response);
    response.headers.set('x-HTML-Edge-Cache-Status', status);
    if (cacheVer !== null) {
      response.headers.set('x-HTML-Edge-Cache-Version', cacheVer.toString());
    }
  }

  return response;
}

const CACHE_HEADERS = ['Cache-Control', 'Expires', 'Pragma'];

/**
 * Check for cached HTML GET requests.
 * 
 * @param {Request} request - Original request
 */
async function getEdgeCachedResponse(request) {
  let response = null;
  let cacheVer = null;
  let bypassCache = false;
  let status = 'Miss';

  // Only check for HTML GET requests (saves on reading from KV unnecessarily)
  // and not when there are cache-control headers on the request (refresh)
  const accept = request.headers.get('Accept');
  const cacheControl = request.headers.get('Cache-Control');
  let noCache = false;
  if (cacheControl && cacheControl.indexOf('no-cache') !== -1) {
    noCache = true;
    status = 'Bypass for Reload';
  }
  if (!noCache && request.method === 'GET' && accept && accept.indexOf('text/html') >= 0) {
    // Build the versioned URL for checking the cache
    cacheVer = await GetCurrentEdgeCacheVersion(cacheVer);
    const cacheKeyRequest = GenerateEdgeCacheRequest(request, cacheVer);

    // See if there is a request match in the cache
    try {
      let cache = caches.default;
      let cachedResponse = await cache.match(cacheKeyRequest);
      if (cachedResponse) {
        // Copy Response object so that we can edit headers.
        cachedResponse = new Response(cachedResponse.body, cachedResponse);

        // Check to see if the response needs to be skipped for a login cookie.
        const options = getEdgeCacheResponseOptions(cachedResponse);
        const cookieHeader = request.headers.get('cookie');
        if (cookieHeader && cookieHeader.length && options.bypassCookies.length) {
          const cookies = cookieHeader.split(';');
          for (let cookie of cookies) {
            // See if the cookie starts with any of the logged-in user prefixes
            for (let prefix of options.bypassCookies) {
              if (cookie.trim().startsWith(prefix)) {
                bypassCache = true;
                break;
              }
            }
            if (bypassCache) {
              break;
            }
          }
        }
      
        // Copy the original cache headers back and clean up any control headers
        if (bypassCache) {
          status = 'Bypass Cookie';
        } else {
          status = 'Hit';
          response = cachedResponse;
          response.headers.delete('x-HTML-Edge-Cache');
          response.headers.delete('Cache-Control');
          for (header of CACHE_HEADERS) {
            let value = response.headers.get('x-HTML-Edge-Cache-' + header);
            if (value) {
              response.headers.delete('x-HTML-Edge-Cache-' + header);
              response.headers.set(header, value);
            }
          }
        }
      } else {
        status = 'Miss';
      }
    } catch (err) {
      // Send the exception back in the response header for debugging
      status = "Cache Read Exception: " + err.message;
    }
  }

  return {response, cacheVer, status, bypassCache};
}

/**
 * Asynchronously purge the HTML cache.
 * @param {Int} cacheVer - Current cache version (if retrieved)
 * @param {Event} event - Original event
 */
async function purgeEdgeCache(cacheVer, event) {
  if (typeof EDGE_CACHE !== 'undefined') {
    // Purge the KV cache by bumping the version number
    cacheVer = await GetCurrentEdgeCacheVersion(cacheVer);
    cacheVer++;
    event.waitUntil(EDGE_CACHE.put('html_cache_version', cacheVer.toString()));
  } else {
    // Purge everything using the API
    const url = "https://api.cloudflare.com/client/v4/zones/" + CLOUDFLARE_API.zone + "/purge_cache";
    event.waitUntil(fetch(url,{
      method: 'POST',
      headers: {'X-Auth-Email': CLOUDFLARE_API.email,
                'X-Auth-Key': CLOUDFLARE_API.key,
                'Content-Type': 'application/json'},
      body: JSON.stringify({purge_everything: true})
    }));
  }
}

/**
 * Cache the returned content (but only if it was a successful GET request)
 * 
 * @param {Int} cacheVer - Current cache version (if already retrieved)
 * @param {Request} request - Original Request
 * @param {Response} originalResponse - Response to (maybe) cache
 * @param {Event} event - Original event
 * @returns {bool} true if the response was cached
 */
async function cacheEdgeResponse(cacheVer, request, originalResponse, event) {
  let status = "";
  const accept = request.headers.get('Accept');
  if (request.method === 'GET' && originalResponse.status === 200 && accept && accept.indexOf('text/html') >= 0) {
    cacheVer = await GetCurrentEdgeCacheVersion(cacheVer);
    const cacheKeyRequest = GenerateEdgeCacheRequest(request, cacheVer);

    try {
      // Move the cache headers out of the way so the response can actually be cached.
      // First clone the response so there is a parallel body stream and then
      // create a new response object based on the clone that we can edit.
      let cache = caches.default;
      let clonedResponse = originalResponse.clone();
      let response = new Response(clonedResponse.body, clonedResponse);
      for (header of CACHE_HEADERS) {
        let value = response.headers.get(header);
        if (value) {
          response.headers.delete(header);
          response.headers.set('x-HTML-Edge-Cache-' + header, value);
        }
      }
      response.headers.delete('Set-Cookie');
      response.headers.set('Cache-Control', 'public; max-age=315360000');
      event.waitUntil(cache.put(cacheKeyRequest, response));
      status = ", Cached";
    } catch (err) {
      // Send the exception back in the response header for debugging
      status = ", Cache Write Exception: " + err.message;
    }
  }
  return status;
}

/**
 * Parse the commands from the x-HTML-Edge-Cache response header.
 * @param {Response} response - HTTP response from the origin.
 * @returns {*} Parsed commands
 */
function getEdgeCacheResponseOptions(response) {
  let options = {
    purge: false,
    cache: false,
    bypassCookies: []
  };

  let header = response.headers.get('x-HTML-Edge-Cache');
  if (header) {
    let commands = header.split(',');
    for (let command of commands) {
      if (command.trim() === 'purgeall') {
        options.purge = true;
      } else if (command.trim() === 'cache') {
        options.cache = true;
      } else if (command.trim().startsWith('bypass-cookies')) {
        let separator = command.indexOf('=');
        if (separator >= 0) {
          let cookies = command.substr(separator + 1).split('|');
          for (let cookie of cookies) {
            cookie = cookie.trim();
            if (cookie.length) {
              options.bypassCookies.push(cookie);
            }
          }
        }
      }
    }
  }

  return options;
}

/**
 * Retrieve the current cache version from KV
 * @param {Int} cacheVer - Current cache version value if set.
 * @returns {Int} The current cache version.
 */
async function GetCurrentEdgeCacheVersion(cacheVer) {
  if (cacheVer === null) {
    if (typeof EDGE_CACHE !== 'undefined') {
      cacheVer = await EDGE_CACHE.get('html_cache_version');
      if (cacheVer === null) {
        // Uninitialized - first time through, initialize KV with a value
        // Blocking but should only happen immediately after worker activation.
        cacheVer = 0;
        await EDGE_CACHE.put('html_cache_version', cacheVer.toString());
      } else {
        cacheVer = parseInt(cacheVer);
      }
    } else {
      cacheVer = -1;
    }
  }
  return cacheVer;
}

/**
 * Generate the versioned Request object to use for cache operations.
 * @param {Request} request - Base request
 * @param {Int} cacheVer - Current Cache version (must be set)
 * @returns {Request} Versioned request object
 */
function GenerateEdgeCacheRequest(request, cacheVer) {
  let cacheUrl = request.url;
  if (cacheUrl.indexOf('?') >= 0) {
    cacheUrl += '&';
  } else {
    cacheUrl += '?';
  }
  cacheUrl += 'cf_edge_cache_ver=' + cacheVer;
  return new Request(cacheUrl);
}

/******************************************************************************
 *  Proxy static 3rd-party scripts and stylesheets
 *****************************************************************************/

 /**
 * Change proxy well-known 3rd-party scripts through our origin
 * @param {*} content - Text chunk from the streaming HTML
 * @param {*} request - Original request object for downstream use.
 * @param {*} cspRules - Content-Security-Policy rules
 */
async function proxyScripts(content, request, cspRules) {
  // Regex patterns for matching script tags
  const SCRIPT_PRE = '<\\s*script[^>]+src\\s*=\\s*[\'"]\\s*((https?:)?/';
  const CSS_PRE = '<\\s*link[^>]+href\\s*=\\s*[\'"]\\s*((https?:)?/';
  const PATTERN_POST = '[^\'" ]+)\\s*["\'][^>]*>';

  // build the list of url patterns we are going to look for.
  let patterns = [];
  if (!('script' in cspRules) || cspRules['script'].indexOf("'self'") >= 0) {
    for (let scriptUrl of SCRIPT_URLS) {
      let regex = new RegExp(SCRIPT_PRE + scriptUrl + PATTERN_POST, 'gi');
      patterns.push(regex);
    }
  }
  if (!('style' in cspRules) || cspRules['style'].indexOf("'self'") >= 0) {
    for (let stylesheetUrl of STYLESHEET_URLS) {
      let regex = new RegExp(CSS_PRE + stylesheetUrl + PATTERN_POST, 'gi');
      patterns.push(regex);
    }
  }

  // Rewrite the script and stylesheet URLs
  const stylesheetRegex = new RegExp('rel\\s*=\\s*[\'"]\\s*stylesheet\\s*[\'"]', 'gi');
  const pageUrl = new URL(request.url);
  for (let pattern of patterns) {
    let match = pattern.exec(content);
    while (match !== null) {
      // Make sure any link tags are stylesheets
      let ok = true;
      if (pattern.source.indexOf('link') >= 0) {
        stylesheetRegex.lastIndex = 0;
        ok = stylesheetRegex.test(match[0]);
      }
      if (ok) {
        const originalUrl = match[1];
        let fetchUrl = originalUrl;
        if (fetchUrl.startsWith('//')) {
          fetchUrl = pageUrl.protocol + fetchUrl;
        }
        const proxyUrl = await hashContent(originalUrl, fetchUrl, request);
        if (proxyUrl !== null) {
          content = content.split(originalUrl).join(proxyUrl);
          pattern.lastIndex -= originalUrl.length - proxyUrl.length;
        }
      }
      match = pattern.exec(content);
    }
  }

  return content;
}

/**
 * Rewrite the URLs in the stylesheet to proxy through the same origin
 * @param {String} url - URL for the CSS
 * @param {String} content - Original CSS
 * @returns {String} The rewritten CSS
 */
function rewriteStylesheetUrls(url, content) {
  const patterns = [
    '@import\\s*[\'"]\\s*((https?:)?\\/[^\'" ;]*)\\s*[\'"]',
    '@import\\s*((https?:)?\\/[^\\s\'"\(]*)\\s*;',
    'url\\s*\\(\\s*[\'"]?\\s*((https?:)?\\/[^\'" ]*)\\s*[\'"]?\\s*\\)'
  ];
  const cssUrl = new URL(url);
  for (let pattern of patterns) {
    let regex = new RegExp(pattern, 'gi');
    let match = regex.exec(content);
    while (match !== null) {
      const originalUrl = match[1];
      let proxyUrl = null;
      // only operate on absolute urls
      if (originalUrl.startsWith('//')) {
        proxyUrl = originalUrl.substr(1);
      } else if (originalUrl.startsWith('/')) {
        proxyUrl = '/' + cssUrl.hostname + originalUrl;
      } else if (originalUrl.indexOf(cssUrl.hostname) === -1) {
        let offset = originalUrl.indexOf('://');
        if (offset >= 0) {
          proxyUrl = originalUrl.substr(offset + 2);
        }
      }
      if (proxyUrl !== null) {
        content = content.split(originalUrl).join(proxyUrl);
        regex.lastIndex -= originalUrl.length - proxyUrl.length;
      }
      match = regex.exec(content);
    }
  }
  return content;
}

/**
 * Generate the proxy URL given the content hash and base URL
 * @param {*} originalUrl - Original URL
 * @param {*} hash - Hash of content
 * @returns {*} - URL with content hash appended
 */
function constructProxyUrl(originalUrl, hash) {
  let proxyUrl = null;
  let pathStart = originalUrl.indexOf('//');
  if (pathStart >= 0) {
    proxyUrl = originalUrl.substring(pathStart + 1);
    if (hash !== null) {
      if (proxyUrl.indexOf('?') >= 0) {
        proxyUrl += '&';
      } else {
        proxyUrl += '?';
      }
      proxyUrl += 'cf_hash=' + hash;
    }
  }
  return proxyUrl;
}

/**
 * Fetch the original content and return a hash of the result (for detecting changes).
 * Use a local cache because some scripts use cache-control: private to prevent
 * proxies from caching.
 * 
 * @param {*} originalUrl - Unmodified URL
 * @param {*} url - URL for the third-party request
 * @param {*} request - Original request for the page HTML so the user-agent can be passed through 
 * @param {*} event - Worker event object.
 */
async function hashContent(originalUrl, url, request) {
  let proxyUrl = constructProxyUrl(originalUrl, null);
  let hash = null;
  const userAgent = request.headers.get('user-agent');
  const clientAddr = request.headers.get('cf-connecting-ip');
  const hashCacheKey = new Request(url + "cf-hash-key");
  let cache = null;

  let foundInCache = false;
  // Try pulling it from the cache API (wrap it in case it's not implemented)
  try {
    cache = caches.default;
    let response = await cache.match(hashCacheKey);
    if (response) {
      hash = await response.text();
      proxyUrl = constructProxyUrl(originalUrl, hash);
      foundInCache = true;
    }
  } catch(e) {
    // Ignore the exception
  }

  if (!foundInCache) {
    try {
      let headers = {'Referer': request.url,
                     'User-Agent': userAgent};
      if (clientAddr) {
        headers['X-Forwarded-For'] = clientAddr;
      }
      const response = await fetch(url, {headers: headers});
      let content = await response.arrayBuffer();
      if (content) {
        const hashBuffer = await crypto.subtle.digest('SHA-1', content);
        hash = hex(hashBuffer);
        proxyUrl = constructProxyUrl(originalUrl, hash);

        // Add the hash to the local cache
        try {
          if (cache) {
            let ttl = 60;
            const cacheControl = response.headers.get('cache-control');
            const maxAgeRegex = /max-age\s*=\s*(\d+)/i;
            const match = maxAgeRegex.exec(cacheControl);
            if (match) {
              ttl = parseInt(match[1], 10);
            }
            const hashCacheResponse = new Response(hash, {ttl: ttl});
            cache.put(hashCacheKey, hashCacheResponse);
          }
        } catch(e) {
          // Ignore the exception
        }
      }
    } catch(e) {
      // Ignore the exception
    }
  }

  return proxyUrl;
}

/**
 * Convert a buffer into a hex string (for hashes).
 * From: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest
 * @param {*} buffer - Binary buffer
 * @returns {*} - Hex string of the binary buffer
 */
function hex(buffer) {
  var hexCodes = [];
  var view = new DataView(buffer);
  for (var i = 0; i < view.byteLength; i += 4) {
    var value = view.getUint32(i);
    var stringValue = value.toString(16);
    var padding = '00000000';
    var paddedValue = (padding + stringValue).slice(-padding.length);
    hexCodes.push(paddedValue);
  }
  return hexCodes.join("");
}

/******************************************************************************
 *  Optimizing Google Fonts
 *****************************************************************************/

 /**
 * Identify any <link> tags that pull ing Google font css and inline the css file.
 * 
 * @param {*} content - Text chunk from the streaming HTML (or accumulated head)
 * @param {*} request - Original request object for downstream use.
 * @param {*} event - Worker event object
 * @param {*} cspRules - Content-Security-Policy rules
*/
async function optimizeGoogleFonts(content, request, event, cspRules) {
  if (!('style' in cspRules) || cspRules['style'].indexOf("'self'") >= 0) {
    // Fully tokenizing and parsing the HTML is expensive.  This regex is much faster and should be reasonably safe.
    // It looks for Stylesheet links for the Google fonts css and extracts the URL as match #1.  It shouldn't match
    // in-text content because the < > brackets would be escaped in the HTML.  There is some potential risk of
    // matching it in an inline script (unlikely but possible).
    const fontCSSRegex = /<link\s+[^>]*href\s*=\s*['"]((https?:)?\/\/fonts.googleapis.com\/css[^'"]+)[^>]*>/mgi;
    let match = fontCSSRegex.exec(content);
    while (match !== null) {
      const matchString = match[0];
      if (matchString.indexOf('stylesheet') >= 0) {
        if (!('style' in cspRules)) {
          const fontCSS = await fetchGoogleFontsCSS(match[1], request, event);
          if (fontCSS.length) {
            // See if there is a media type on the link tag
            let mediaStr = '';
            const mediaMatch = matchString.match(/media\s*=\s*['"][^'"]*['"]/mig);
            if (mediaMatch) {
              mediaStr = ' ' + mediaMatch[0];
            }
            // Replace the actual css
            let cssString = "<style" + mediaStr + ">\n";
            cssString += fontCSS;
            cssString += "\n</style>\n";
            content = content.split(matchString).join(cssString);
            fontCSSRegex.lastIndex -= matchString.length - cssString.length;
          }
        } else {
          // Rewrite the URL to proxy it through the origin
          let originalUrl = match[1];
          let startPos = originalUrl.indexOf('/fonts.googleapis.com');
          let newUrl = originalUrl.substr(startPos);
          let newString = matchString.split(originalUrl).join(newUrl);
          content = content.split(matchString).join(newString);
          fontCSSRegex.lastIndex -= matchString.length - newString.length;
        }
        match = fontCSSRegex.exec(content);
      }
    }
  }

  return content;
}

/**
 * Handle the processing of stylesheets (that might have a @import)
 * 
 * @param {*} response - The stylesheet response
 * @param {*} request - The original request
 * @param {*} event - The original worker event
 */
async function processStylesheetResponse(response, request, event) {
  let body = response.body;
  try {
    body = await response.text();
    const fontCSSRegex = /@import\s*(url\s*)?[\('"\s]+((https?:)?\/\/fonts.googleapis.com\/css[^'"\)]+)[\s'"\)]+\s*;/mgi;
    let match = fontCSSRegex.exec(body);
    while (match !== null) {
      const matchString = match[0];
      const fontCSS = await fetchGoogleFontsCSS(match[2], request, event);
      if (fontCSS.length) {
        body = body.split(matchString).join(fontCSS);
        fontCSSRegex.lastIndex -= matchString.length - fontCSS.length;
      }
      match = fontCSSRegex.exec(body);
    }
  } catch (e) {
    // Ignore the exception, the original body will be passed through.
  }

  // Return a cloned response with the (possibly modified) body.
  // We can't just return the original response since we already
  // consumed the body.
  const newResponse = new Response(body, response);

  return newResponse;
}

/**
 * Fetch the font css from Google using the same browser user-agent string to make sure the
 * correct CSS is returned and rewrite the font URLs to proxy them through the worker (on
 * the same origin to avoid a new connection).
 * 
 * @param {*} url - URL for the Google font css.
 * @param {*} request - Original request for the page HTML so the user-agent can be passed through 
 * and the origin can be used for rewriting the font paths.
 * @param {*} event - Worker event object
 */
async function fetchGoogleFontsCSS(url, request, event) {
  let fontCSS = "";
  if (url.startsWith('/'))
    url = 'https:' + url;
  const userAgent = request.headers.get('user-agent');
  const clientAddr = request.headers.get('cf-connecting-ip');
  const browser = getCacheKey(userAgent);
  const cacheKey = browser ? url + '&' + browser : url;
  const cacheKeyRequest = new Request(cacheKey);
  let cache = null;

  let foundInCache = false;
  // Try pulling it from the cache API (wrap it in case it's not implemented)
  try {
    cache = caches.default;
    let response = await cache.match(cacheKeyRequest);
    if (response) {
      fontCSS = await response.text();
      foundInCache = true;
    }
  } catch(e) {
    // Ignore the exception
  }

  if (!foundInCache) {
    let headers = {'Referer': request.url};
    if (browser) {
      headers['User-Agent'] = userAgent;
    } else {
      headers['User-Agent'] = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0)";
    }
    if (clientAddr) {
      headers['X-Forwarded-For'] = clientAddr;
    }

    try {
      const response = await fetch(url, {headers: headers});
      if (response && response.status === 200) {
        fontCSS = await response.text();

        // Rewrite all of the font URLs to come through the worker
        fontCSS = fontCSS.replace(/(https?:)?\/\/fonts\.gstatic\.com\//mgi, '/fonts.gstatic.com/');

        // Add the css info to the font cache
        try {
          if (cache) {
            const cacheResponse = new Response(fontCSS, {ttl: 86400});
            event.waitUntil(cache.put(cacheKeyRequest, cacheResponse));
          }
        } catch(e) {
          // Ignore the exception
        }
      }
    } catch(e) {
      // Ignore the exception
    }
  }

  return fontCSS;
}

/**
 * Identify the common browsers (and versions) for using browser-specific css.
 * Others will use a common fallback css fetched without a user agent string (ttf).
 * 
 * @param {*} userAgent - Browser user agent string
 * @returns {*} A browser-version-specific string like Chrome61
 */
function getCacheKey(userAgent) {
  let os = '';
  const osRegex = /^[^(]*\(\s*(\w+)/mgi;
  let match = osRegex.exec(userAgent);
  if (match) {
    os = match[1];
  }

  let mobile = '';
  if (userAgent.match(/Mobile/mgi)) {
    mobile = 'Mobile';
  }

  // Detect Edge first since it includes Chrome and Safari
  const edgeRegex = /\s+Edge\/(\d+)/mgi;
  match = edgeRegex.exec(userAgent);
  if (match) {
    return 'Edge' + match[1] + os + mobile;
  }

  // Detect Chrome next (and browsers using the Chrome UA/engine)
  const chromeRegex = /\s+Chrome\/(\d+)/mgi;
  match = chromeRegex.exec(userAgent);
  if (match) {
    return 'Chrome' + match[1] + os + mobile;
  }

  // Detect Safari and Webview next
  const webkitRegex = /\s+AppleWebKit\/(\d+)/mgi;
  match = webkitRegex.exec(userAgent.match);
  if (match) {
    return 'WebKit' + match[1] + os + mobile;
  }

  // Detect Firefox
  const firefoxRegex = /\s+Firefox\/(\d+)/mgi;
  match = firefoxRegex.exec(userAgent);
  if (match) {
    return 'Firefox' + match[1] + os + mobile;
  }
  
  return null;
}

/******************************************************************************
 *  Support routines and general streaming parse plumbing.
 *****************************************************************************/

// Workers can only decode utf-8 so keep a list of character encodings that can be decoded.
const VALID_CHARSETS = ['utf-8', 'utf8', 'iso-8859-1', 'us-ascii'];

/**
 * Generate a new request based on the original. Filter the request
 * headers to prevent leaking user data (cookies, etc) and filter
 * the response headers to prevent the origin setting policy on
 * our origin.
 * 
 * @param {*} url The URL to proxy
 * @param {*} request The original request (to copy parameters from)
 */
async function proxyRequest(url, request) {
  let init = {
    method: request.method,
    headers: {}
  };
  // see if it is a cache-extended hashed URL
  let extendCache = false;
  const hashOffset = url.indexOf('cf_hash=');
  if (hashOffset >= 2) {
    url = url.substring(0, hashOffset - 1);
    extendCache = true;
  }

  // Only pass through a subset of headers
  const proxyHeaders = ["Accept",
                        "Accept-Encoding",
                        "Accept-Language",
                        "Referer",
                        "User-Agent"];
  for (let name of proxyHeaders) {
    let value = request.headers.get(name);
    if (value) {
      init.headers[name] = value;
    }
  }
  // Add an X-Forwarded-For with the client IP
  const clientAddr = request.headers.get('cf-connecting-ip');
  if (clientAddr) {
    init.headers['X-Forwarded-For'] = clientAddr;
  }

  const response = await fetch(url, init);
  if (response) {
    const responseHeaders = ["Content-Type",
                             "Cache-Control",
                             "Expires",
                             "Accept-Ranges",
                             "Date",
                             "Last-Modified",
                             "ETag"];
    // Only include a strict subset of response headers
    let responseInit = {status: response.status,
                        statusText: response.statusText,
                        headers: {}};
    for (let name of responseHeaders) {
      let value = response.headers.get(name);
      if (value) {
        responseInit.headers[name] = value;
      }
    }
    if (response.status === 200 && extendCache) {
      responseInit.headers['Cache-Control'] = 'private; max-age=315360000';
    }
    // Add a little bit of protection to the proxied content type
    responseInit.headers['X-Content-Type-Options'] = "nosniff";

    // Rewrite URLs in stylesheets
    let body = response.body;
    const contentType = response.headers.get("content-type");
    if (contentType && contentType.indexOf("text/css") !== -1) {
      try {
        let content = await response.text();
        body = rewriteStylesheetUrls(url, content);
      } catch (e) {
        // ignore the exception
      }
    }

    const newResponse = new Response(body, responseInit);
    return newResponse;
  }

  return response;
}

/**
 * Handle all of the processing for a (likely) HTML request.
 * - Pass through the request to the origin and inspect the response.
 * - If the response is HTML set up a streaming transform and pass it on to modifyHtmlStream for processing
 * 
 * Extra care needs to be taken to make sure the character encoding from the original
 * HTML is extracted and converted to utf-8 and that the downstream response is identified
 * as utf-8.
 * 
 * @param {*} response The original response
 * @param {*} request The original request
 * @param {*} event worker event object
 */
async function processHtmlResponse(response, request, event) {
  // Workers can only decode utf-8. If it is anything else, pass the
  // response through unmodified
  const contentType = response.headers.get("content-type");
  const charsetRegex = /charset\s*=\s*([^\s;]+)/mgi;
  const match = charsetRegex.exec(contentType);
  if (match !== null) {
    let charset = match[1].toLowerCase();
    if (!VALID_CHARSETS.includes(charset)) {
      return response;
    }
  }
  // See if the stylesheet should be embedded or proxied.
  // CSP blocks embedded CSS by default so fall back to proxying
  // the stylesheet through the origin.
  //
  // Note: only 'self' and 'unsafe-inline' CSP rules for style-src
  // are recognized. If explicit URLs are used instead then the
  // HTML will not be modified.
  let cspRules = {};
  let csp = response.headers.get("Content-Security-Policy");
  if (csp) {
    // Get the style policy that will be applied to the document
    let cspRule = null;
    const styleRegex = /style-src[^;]*/gmi;
    let match = styleRegex.exec(csp);
    if (match !== null) {
      cspRule = match[0];
    } else {
      const defaultRegex = /default-src[^;]*/gmi;
      match = defaultRegex.exec(csp);
      if (match !== null) {
        cspRule = match[0];
      }
    }
    if (cspRule !== null) {
      if (cspRule.indexOf("'unsafe-inline'") >= 0) {
        // Do nothing. This is the same as not using CSP for styles.
      } else if (cspRule.indexOf("'self'") >= 0) {
        cspRules['style'] = cspRule;
      } else {
        cspRules['style'] = cspRule;
      }
    }
    const scriptRegex = /script-src[^;]*/gmi;
    match = scriptRegex.exec(csp);
    if (match !== null) {
      cspRule = match[0];
    } else {
      const defaultRegex = /default-src[^;]*/gmi;
      match = defaultRegex.exec(csp);
      if (match !== null) {
        cspRule = match[0];
      }
    }
    if (cspRule !== null) {
      if (cspRule.indexOf("'unsafe-inline'") >= 0) {
        // Do nothing. This is the same as not using CSP for scripts.
      } else if (cspRule.indexOf("'self'") >= 0) {
        cspRules['script'] = cspRule;
      } else {
        cspRules['script'] = cspRule;
      }
    }
  }
  
  // Create an identity TransformStream (a.k.a. a pipe).
  // The readable side will become our new response body.
  const { readable, writable } = new TransformStream();

  // Create a cloned response with our modified stream
  const newResponse = new Response(readable, response);

  // Start the async processing of the response stream
  modifyHtmlStream(response.body, writable, request, event, cspRules);

  // Return the in-process response so it can be streamed.
  return newResponse;
}

/**
 * Check to see if the HTML chunk includes a meta tag for an unsupported charset
 * @param {*} chunk - Chunk of HTML to scan
 * @returns {bool} - true if the HTML chunk includes a meta tag for an unsupported charset
 */
function chunkContainsInvalidCharset(chunk) {
  let invalid = false;

  // meta charset
  const charsetRegex = /<\s*meta[^>]+charset\s*=\s*['"]([^'"]*)['"][^>]*>/mgi;
  const charsetMatch = charsetRegex.exec(chunk);
  if (charsetMatch) {
    const docCharset = charsetMatch[1].toLowerCase();
    if (!VALID_CHARSETS.includes(docCharset)) {
      invalid = true;
    }
  }
  // content-type
  const contentTypeRegex = /<\s*meta[^>]+http-equiv\s*=\s*['"]\s*content-type[^>]*>/mgi;
  const contentTypeMatch = contentTypeRegex.exec(chunk);
  if (contentTypeMatch) {
    const metaTag = contentTypeMatch[0];
    const metaRegex = /charset\s*=\s*([^\s"]*)/mgi;
    const metaMatch = metaRegex.exec(metaTag);
    if (metaMatch) {
      const charset = metaMatch[1].toLowerCase();
      if (!VALID_CHARSETS.includes(charset)) {
        invalid = true;
      }
    }
  }
  return invalid;
}

/**
 * Process the streaming HTML response from the origin server.
 * - Scan the first response chunk for a charset meta tag (and bail if it isn't a supported charset)
 * - Pass the gathered head and each subsequent chunk to modifyHtmlChunk() for actual processing of the text.
 * 
 * @param {*} readable - Input stream (from the origin).
 * @param {*} writable - Output stream (to the browser).
 * @param {*} request - Original request object for downstream use.
 * @param {*} event - Worker event object
 * @param {bool} cspRules - Content-Security-Policy rules
 */
async function modifyHtmlStream(readable, writable, request, event, cspRules) {
  const reader = readable.getReader();
  const writer = writable.getWriter();
  const encoder = new TextEncoder();
  let decoder = new TextDecoder("utf-8", {fatal: true});

  let firstChunk = true;
  let unsupportedCharset = false;

  let partial = '';
  let content = '';

  try {
    for(;;) {
      const { done, value } = await reader.read();
      if (done) {
        if (partial.length) {
          partial = await modifyHtmlChunk(partial, request, event, cspRules);
          await writer.write(encoder.encode(partial));
          partial = '';
        }
        break;
      }

      let chunk = null;
      if (unsupportedCharset) {
        // Pass the data straight through
        await writer.write(value);
        continue;
      } else {
        try {
          chunk = decoder.decode(value, {stream:true});
        } catch (e) {
          // Decoding failed, switch to passthrough
          unsupportedCharset = true;
          if (partial.length) {
            await writer.write(encoder.encode(partial));
            partial = '';
          }
          await writer.write(value);
          continue;
        }
      }

      try {
        // Look inside of the first chunk for a HTML charset or content-type meta tag.
        if (firstChunk) {
          firstChunk = false;
          if (chunkContainsInvalidCharset(chunk)) {
            // switch to passthrough
            unsupportedCharset = true;
            if (partial.length) {
              await writer.write(encoder.encode(partial));
              partial = '';
            }
            await writer.write(value);
            continue;
          }
        }

        // TODO: Optimize this so we aren't continuously adding strings together
        content = partial + chunk;
        partial = '';

        // See if there is an unclosed tag at the end (and if so, carve it out
        // to complete when the remainder comes in).
        // This is FAR from perfect and has a lot of false positives but no false
        // negatives and is very fast.
        const tagPos = content.lastIndexOf('<');
        if (tagPos >= 0) {
          const tagClose = content.indexOf('>', tagPos);
          if (tagClose === -1) {
            partial = content.slice(tagPos);
            content = content.slice(0, tagPos);
          }
        }

        if (content.length) {
          content = await modifyHtmlChunk(content, request, event, cspRules);
        }
      } catch (e) {
        // Ignore the exception
      }
      if (content.length) {
        await writer.write(encoder.encode(content));
        content = '';
      }
    }
  } catch(e) {
    // Ignore the exception
  }

  try {
    await writer.close();
  } catch(e) {
    // Ignore the exception
  }
}
