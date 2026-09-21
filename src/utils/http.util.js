/**
 * HTTP fetch helper that manually follows redirects (rather than letting
 * axios follow them internally) so we can capture an accurate redirect
 * chain for evidence - axios/follow-redirects doesn't reliably expose the
 * hop-by-hop chain it followed internally.
 */

const axios = require('axios');

/**
 * Fetches `url`, following up to `maxRedirects` redirects one hop at a time.
 * @returns {{ response: object, finalUrl: string, statusCode: number, redirectChain: Array<{url:string, status:number}> }}
 */
async function fetchWithRedirectChain(url, options = {}) {
  const { timeout = 15000, maxRedirects = 5, headers } = options;
  const redirectChain = [];
  let currentUrl = url;
  let response;

  for (let hop = 0; hop <= maxRedirects; hop++) {
    response = await axios.get(currentUrl, {
      timeout,
      headers,
      maxRedirects: 0,
      validateStatus: () => true
    });

    const isRedirect = response.status >= 300 && response.status < 400 && response.headers.location;
    if (isRedirect && hop < maxRedirects) {
      redirectChain.push({ url: currentUrl, status: response.status });
      currentUrl = new URL(response.headers.location, currentUrl).href;
      continue;
    }
    break;
  }

  return {
    response,
    finalUrl: currentUrl,
    statusCode: response.status,
    redirectChain
  };
}

module.exports = { fetchWithRedirectChain };
