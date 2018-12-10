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
  const bypass = url.searchParams.get('cf-worker') === 'bypass';
  if (!bypass) {
    if (event.request.method === 'GET' && isProxyRequest(url)) {
      // Pass the requests through to the origin server
      // (through the underlying request cache and filtering headers).
      event.respondWith(proxyRequest('https:/' + url.pathname + url.search,
                                     event.request));
    } else if (event.request.method === 'GET' &&
               url.pathname.startsWith('/fonts.googleapis.com/')) {
      // Proxy the Google fonts stylesheet for pages using CSP
      // (Separate because it rewrites the font URLs).
      event.respondWith(proxyStylesheet('https:/' + url.pathname + url.search,
                                        event.request));
    } else {
      event.respondWith(processRequest(event.request, event));
    }
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

  // Popular scripts (can be site-specific)
  '/a.optmnstr.com/app/js/',
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

/**
 * Process chunks of HTML as they stream through
 * 
 * @param {*} content - Text chunk from the streaming HTML (or accumulated head)
 * @param {*} request - Original request object for downstream use.
 * @param {*} event - Worker event object
 * @param {bool} cspRules - Content-Security-Policy rules
*/
async function modifyHtmlResponse(content, request, event, cspRules) {

  // Call out to the individual optimizations
  content = await optimizeGoogleFonts(content, request, event, cspRules);
  content = await proxyScripts(content, request);

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
  if (url.pathname.startsWith('/fonts.gstatic.com/')) {
    needsProxy = true;
  } else {
    const path = url.pathname + url.search;
    for (let prefix of SCRIPT_URLS) {
      if (path.startsWith(prefix)) {
        needsProxy = true;
        break;
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
  const response = await fetch(request);
  if (response && response.status === 200) {
    const contentType = response.headers.get("content-type");
    if (contentType && contentType.indexOf("text/html") !== -1) {
      return await processHtmlResponse(response, event.request, event);
    } else if (contentType && contentType.indexOf("text/css") !== -1) {
      return await processStylesheetResponse(response, event.request, event);
    }
  }

  return response;
}

/******************************************************************************
 *  Proxy static 3rd-party scripts
 *****************************************************************************/

 /**
 * Change proxy well-known 3rd-party scripts through our origin
 * @param {*} content - Text chunk from the streaming HTML
 * @param {*} request - Original request object for downstream use.
 */
async function proxyScripts(content, request) {
  // Regex patterns for matching script tags
  const SCRIPT_PRE = '<\\s*script[^>]+src\\s*=\\s*[\'"]\\s*((https?:)?/';
  const PATTERN_POST = '[^\'" ]+)\\s*["\'][^>]*>';

  // build the list of url patterns we are going to look for.
  let patterns = [];
  for (let scriptUrl of SCRIPT_URLS) {
    let regex = new RegExp(SCRIPT_PRE + scriptUrl + PATTERN_POST, 'gi');
    patterns.push(regex);
  }

  // Rewrite the script URLs
  const pageUrl = new URL(request.url);
  for (let pattern of patterns) {
    let match = pattern.exec(content);
    while (match !== null) {
      console.log(match[0]);
      const originalUrl = match[1];
      let fetchUrl = originalUrl;
      if (fetchUrl.startsWith('//')) {
        fetchUrl = pageUrl.protocol + fetchUrl;
      }
      const proxyUrl = await hashContent(originalUrl, fetchUrl, request);
      if (proxyUrl !== null) {
        content = content.split(originalUrl).join(proxyUrl);
      }
      match = pattern.exec(content);
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
    if (proxyUrl.indexOf('?') >= 0) {
      proxyUrl += '&';
    } else {
      proxyUrl += '?';
    }
    proxyUrl += 'cf_hash=' + hash;
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
  let proxyUrl = null;
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
 * @param {bool} cspRules - Content-Security-Policy rules
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
          }
        } else {
          // Rewrite the URL to proxy it through the origin
          let originalUrl = match[1];
          let startPos = originalUrl.indexOf('/fonts.googleapis.com');
          let newUrl = originalUrl.substr(startPos);
          let newString = matchString.split(originalUrl).join(newUrl);
          content = content.split(matchString).join(newString);
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
 * Handle a proxied stylesheet request.
 * 
 * @param {*} url The URL to proxy
 * @param {*} request The original request (to copy parameters from)
 */
async function proxyStylesheet(url, request) {
  let css = await fetchGoogleFontsCSS(url, request)
  if (css) {
    const responseInit = {headers: {
      "Content-Type": "text/css; charset=utf-8",
      "Cache-Control": "private, max-age=86400, stale-while-revalidate=604800"
    }};
    const newResponse = new Response(css, responseInit);
    return newResponse;
  } else {
    // Do a straight-through proxy as fallback
    return proxyRequest(url, request);
  }
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
async function fetchGoogleFontsCSS(url, request) {
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
      fontCSS = response.text();
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

    const newResponse = new Response(response.body, responseInit);
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
      let match = defaultRegex.exec(csp);
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
  }

  let contentArray = await response.arrayBuffer();
  let content = null;
  try {
    let decoder = new TextDecoder("utf-8", {fatal: true});
    content = decoder.decode(contentArray);
    console.log(content);
    content = await modifyHtmlResponse(content, request, event, cspRules);
  } catch (e) {
    // Ignore the exception
  }

  if (content !== null) {
    // Send back the modified response
    const newResponse = new Response(content, response);
    return newResponse;
  }

  // Pass the original response unmodified (decode error)
  const newResponse = new Response(contentArray, response);
  return newResponse;
}
