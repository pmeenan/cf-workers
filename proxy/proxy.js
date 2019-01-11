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
  const proxyUrl = 'https:/' + url.pathname + url.search;
  let originalDomain = url.pathname.substr(1);
  const domainEnd = originalDomain.indexOf('/');
  if (domainEnd >= 0)
    originalDomain = originalDomain.substr(0, domainEnd - 1);
  const response = await fetch(proxyUrl, init);
  if (response) {
    // Process test responses
    const contentType = response.headers.get("content-type");
    if (contentType && contentType.indexOf("text/") !== -1) {
      let content = await response.text();

      // Do the content-specific modification
      content = rewriteProxyUrls(content, originalDomain);

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

function rewriteProxyUrls(content, originalDomain) {
  const hrefRegex = /href\s*=\s*['"]\s*((https?:)?\/?\/[^\s'"]+)\s*['"]/mig;
  const srcRegex = /src\s*=\s*['"]\s*((https?:)?\/?\/[^\s'"]+)\s*['"]/mig;
  const cssUrlRegex = /url\s*[\('"]*\s*((https?:)?\/?\/[^\s'"]+)\s*[\)'"]*/mig;
  const importRegex = /@import\s*(url\s*)?[\('"\s]*((https?:\/)?\/[^'"\)]+)[\s'"\)]*\s*;/mig;
  content = rewriteUrls(content, originalDomain, hrefRegex, 1);
  content = rewriteUrls(content, originalDomain, srcRegex, 1);
  content = rewriteUrls(content, originalDomain, cssUrlRegex, 1);
  content = rewriteUrls(content, originalDomain, importRegex, 2);
  return content;
}

function rewriteUrls(content, originalDomain, regex, group) {
  let match = regex.exec(content);
  while (match !== null) {
    const url = match[group];
    if (url) {
      let newUrl =null;
      if (url.startsWith("//")) {
        newUrl = url.substr(1);
      } else if (url.startsWith("/")) {
        newUrl = '/' + originalDomain + url.substr(1);
      } else {
        let offset = url.indexOf('//');
        if (offset >= 0) {
          newUrl = url.substr(offset + 1);
        }
      }
      if (newUrl !== null) {
        let matchStr = match[0];
        let newStr = matchStr.split(url).join(newUrl);
        content = content.split(matchStr).join(newStr);
      }
    }
    match = regex.exec(content);
  }
  return content;
}