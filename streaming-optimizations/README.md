#Streaming Optimizations

Combined set of streaming workers to optimize performance. Currently a combined set of:
* [Fast Google Fonts](https://github.com/cloudflare/worker-examples/tree/master/examples/fast-google-fonts) - Inlines the browser-specific font CSS and re-hosts the font files through the page origin (saving round trips). Blog post with more details [here](https://blog.cloudflare.com/fast-google-fonts-with-cloudflare-workers/).
* [Third-party Scripts](https://github.com/cloudflare/worker-examples/tree/master/examples/third-party-scripts) - Cache-extends and rehosts static third-party scripts from well-known providers (things like Ajax library CDN's, static analytics code, A/B testing code, etc).

Caution, this has not been tested extensively in a production environment so there may still be some edge cases that are not handled.