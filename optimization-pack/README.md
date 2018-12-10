# Web Performance Optimization Pack

Combined set of workers to optimize performance. Currently a combined set of:

* [Fast Google Fonts](https://github.com/cloudflare/worker-examples/tree/master/examples/fast-google-fonts) - Inlines the browser-specific font CSS and re-hosts the font files through the page origin (saving round trips). Blog post with more details [here](https://blog.cloudflare.com/fast-google-fonts-with-cloudflare-workers/).
* [Third-party Scripts](https://github.com/cloudflare/worker-examples/tree/master/examples/third-party-scripts) - Cache-extends and rehosts static third-party scripts from well-known providers (things like Ajax library CDN's, static analytics code, A/B testing code, etc).

This operates on blocking responses and processes the full HTML with no streaming which can cause pages that rely on early flushing to perform slower (rare but worth being aware of).

Caution, this has not been tested extensively in a production environment so there may still be some edge cases that are not handled.