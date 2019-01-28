/**
 * Main worker entry point.
 */
addEventListener("fetch", event => {
  // Fail-safe in case of an unhandled exception
  console.log(event.request.url);
  event.passThroughOnException();
  event.respondWith(processRequest(event.request, event));
});

/**
 * Handle all non-proxied requests. Send HTML or CSS on for further processing
 * and pass everything else through unmodified.
 * @param {*} request - Original request
 * @param {*} event - Original worker event
 */
async function processRequest(request, event) {
  // Proxy the request
  let init = {
    method: request.method,
    headers: [...request.headers]
  };
  const clientAddr = request.headers.get('cf-connecting-ip');
  if (clientAddr) {
    init.headers['X-Forwarded-For'] = clientAddr;
  }
  const url = new URL(request.url);
  let proxyOrigin = url.origin;
  const proxyUrl = 'https:/' + url.pathname + url.search;
  let originalDomain = url.pathname.substr(1);
  const domainEnd = originalDomain.indexOf('/');
  if (domainEnd >= 0)
    originalDomain = originalDomain.substr(0, domainEnd);
  const response = await fetch(proxyUrl, init);
  if (response) {
    // Process test responses
    const contentType = response.headers.get("content-type");
    if (contentType && contentType.indexOf("text/") !== -1) {
      let content = await response.text();

      // Do the content-specific modification
      content = rewriteProxyUrls(content, originalDomain, proxyOrigin);

      // Create a cloned response with our modified body
      let init = {
        method: request.method,
        headers: [...response.headers]
      };
      const newResponse = new Response(content, init);

      // Return the in-process response so it can be streamed.
      return newResponse;
    }
  }

  return response;
}

function rewriteProxyUrls(content, originalDomain, proxyOrigin) {
  const hrefRegex = /href\s*=\s*['"]\s*((https?:)?\/?\/[^\s'"]+)\s*['"]/mig;
  const srcRegex = /src\s*=\s*['"]\s*((https?:)?\/?\/[^\s'"]+)\s*['"]/mig;
  const cssUrlRegex = /url\s*[\('"]*\s*((https?:)?\/?\/[^\s'"]+)\s*[\)'"]*/mig;
  const importRegex = /@import\s*(url\s*)?[\('"\s]*((https?:\/)?\/[^'"\)]+)[\s'"\)]*\s*;/mig;
  content = rewriteUrls(content, originalDomain, proxyOrigin, hrefRegex, 1);
  content = rewriteUrls(content, originalDomain, proxyOrigin, srcRegex, 1);
  content = rewriteUrls(content, originalDomain, proxyOrigin, cssUrlRegex, 1);
  content = rewriteUrls(content, originalDomain, proxyOrigin, importRegex, 2);
  return content;
}

function rewriteUrls(content, originalDomain, proxyOrigin, regex, group) {
  let match = regex.exec(content);
  while (match !== null) {
    const url = match[group];
    if (url && !url.startsWith(proxyOrigin)) {
      let newUrl =null;
      if (url.startsWith("//")) {
        newUrl = proxyOrigin + url.substr(1);
      } else if (url.startsWith("/") && !url.startsWith("/" + originalDomain)) {
        newUrl = proxyOrigin + '/' + originalDomain + url;
      } else {
        let offset = url.indexOf('//');
        if (offset >= 0) {
          newUrl = proxyOrigin + url.substr(offset + 1);
        }
      }
      if (newUrl !== null) {
        let matchStr = match[0];
        let newStr = matchStr.split(url).join(newUrl);
        console.log("Replacing: " + matchStr);
        console.log("     With: " + newStr);
        content = content.split(matchStr).join(newStr);
      }
    }
    match = regex.exec(content);
  }
  return content;
}