/**
 * HTTP fetch helper that manually follows redirects (rather than letting
 * axios follow them internally) so we can capture an accurate redirect
 * chain for evidence - axios/follow-redirects doesn't reliably expose the
 * hop-by-hop chain it followed internally.
 *
 * Also the single choke point for treating fetched sites as untrusted input:
 * every hop is SSRF-checked (both by resolved IP and by literal-IP URL - see
 * ssrf-guard.util.js) before it's requested, response size is capped, and a
 * fixed number of redirects is enforced. This module never executes any
 * content it fetches - it only reads response headers/body as data.
 */

const axios = require('axios');
const { createSafeAgents, assertUrlIsSafe } = require('./ssrf-guard.util');

const DEFAULT_TIMEOUT_MS = 15000;
const DEFAULT_MAX_REDIRECTS = 5;
const MAX_RESPONSE_BYTES = 5 * 1024 * 1024; // 5MB - plenty for HTML/headers, bounds memory use
const USER_AGENT = 'SiteSentinel-Scanner/1.0 (+https://sitesentinel.tech; automated security scan)';

/**
 * Classifies a failed fetch into a stable, human-readable category. Used so
 * "we couldn't check this site" is always reported as such (never silently
 * treated as "safe") and so the specific cause (DNS/timeout/refused/TLS/
 * SSRF/etc) is visible instead of a generic "engine error".
 */
function classifyFetchError(error) {
  const code = error && error.code;
  const message = (error && error.message) || String(error);

  if (code === 'ERR_SSRF_BLOCKED') {
    return { type: 'ssrf-blocked', label: 'Blocked (restricted destination)', detail: message };
  }
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') {
    return { type: 'dns-failure', label: 'DNS resolution failed', detail: message };
  }
  if (code === 'ECONNREFUSED') {
    return { type: 'connection-refused', label: 'Connection refused', detail: message };
  }
  if (code === 'ECONNRESET') {
    return { type: 'connection-reset', label: 'Connection reset', detail: message };
  }
  if (code === 'ETIMEDOUT' || code === 'ECONNABORTED' || /timeout/i.test(message)) {
    return { type: 'timeout', label: 'Connection timed out', detail: message };
  }
  if (typeof code === 'string' && code.startsWith('ERR_TLS')) {
    return { type: 'tls-failure', label: 'TLS/SSL handshake failed', detail: message };
  }
  if (code === 'CERT_HAS_EXPIRED' || code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' || code === 'DEPTH_ZERO_SELF_SIGNED_CERT') {
    return { type: 'tls-failure', label: 'TLS certificate error', detail: message };
  }
  if (error && error.isAxiosError && error.response === undefined && /Network Error/i.test(message)) {
    return { type: 'network-error', label: 'Network error', detail: message };
  }
  return { type: 'unknown-error', label: 'Request failed', detail: message };
}

/**
 * Fetches `url`, following up to `maxRedirects` redirects one hop at a time.
 * Every hop is validated against SSRF restrictions before it's requested.
 * @returns {{ response: object, finalUrl: string, statusCode: number, redirectChain: Array<{url:string, status:number}> }}
 */
async function fetchWithRedirectChain(url, options = {}) {
  const {
    timeout = DEFAULT_TIMEOUT_MS,
    maxRedirects = DEFAULT_MAX_REDIRECTS,
    headers = {}
  } = options;

  const redirectChain = [];
  let currentUrl = url;
  let response;
  const { httpAgent, httpsAgent } = createSafeAgents();

  for (let hop = 0; hop <= maxRedirects; hop++) {
    assertUrlIsSafe(currentUrl); // throws SsrfBlockedError synchronously if unsafe

    response = await axios.get(currentUrl, {
      timeout,
      headers: { 'User-Agent': USER_AGENT, ...headers },
      maxRedirects: 0,
      validateStatus: () => true,
      maxContentLength: MAX_RESPONSE_BYTES,
      maxBodyLength: MAX_RESPONSE_BYTES,
      httpAgent,
      httpsAgent
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

module.exports = { fetchWithRedirectChain, classifyFetchError, USER_AGENT, MAX_RESPONSE_BYTES };
