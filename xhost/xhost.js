/**
 * Handle all requests. Proxy requests with an x-host header and return 403
 * for everything else
 */
addEventListener("fetch", event => {
  const host = request.headers.get('x-host');
  if (host) {
    const url = new URL(request.url);
    const requestedHost = url.hostname;
    const originUrl = url.protocol + '//' + host + url.pathname + url.search;
    event.respondWith(processRequest(request, event, requestedHost, originUrl));
  } else {
    const response = new Response('x-Host headers missing', {status: 403});
    event.respondWith(response);
  }
});

/**
 * Business logic for the actual request handling.
 * @param {Request} request - Original incoming request
 * @param {Event} event - Original worker event (in case we need to tell it to wait on an async operation)
 * @param {String} requestedHost = Hostname from the inbound request (in case there is business logic tied to the host that requests were proxied through)
 * @param {String} originUrl - Original URL requested by the web page (with the x-Host hostname used in place of the requested hostname)
 */
async function processRequest(request, event, requestedHost, originUrl) {
  // Proxy the request using the host from the x-Host header
  let init = {
    method: request.method,
    redirect: "manual",
    headers: [...request.headers]
  };
  const clientAddr = request.headers.get('cf-connecting-ip');
  if (clientAddr) {
    init.headers['X-Forwarded-For'] = clientAddr;
  }
  const response = await fetch(originUrl, init);
  return response;
}
