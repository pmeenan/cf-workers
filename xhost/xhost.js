/**
 * Handle all requests. Proxy requests with an x-host header and return 403
 * for everything else
 */
addEventListener("fetch", event => {
  const host = event.request.headers.get('x-host');
  if (host) {
    const url = new URL(event.request.url);
    const originUrl = url.protocol + '//' + host + url.pathname + url.search;
    let init = {
      method: event.request.method,
      redirect: "manual",
      headers: [...event.request.headers]
    };
    event.respondWith(fetch(originUrl, init));
  } else {
    const response = new Response('x-Host headers missing', {status: 403});
    event.respondWith(response);
  }
});
