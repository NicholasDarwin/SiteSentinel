/**
 * SSRF (Server-Side Request Forgery) Protection
 *
 * The scanner fetches whatever URL a user submits, and follows redirects
 * from arbitrary (untrusted) sites. Without protection, either of those is a
 * classic SSRF vector: a submitted or redirect-chain URL could point at
 * localhost, an internal/private network address, or a cloud metadata
 * endpoint (e.g. 169.254.169.254), tricking the server into making requests
 * on the attacker's behalf.
 *
 * This module blocks connections to those destinations at the DNS-resolution
 * layer (not just by inspecting the URL string), which is what actually
 * closes the gap: a hostname that LOOKS public can still resolve to a
 * private IP (DNS rebinding), so the check has to happen against the
 * resolved address, for every hop of every request - see http.util.js,
 * which wires createSafeAgents() into every redirect hop, not just the
 * first request.
 */

const dns = require('dns');
const net = require('net');
const http = require('http');
const https = require('https');

function isBlockedIpv4(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(p => Number.isNaN(p))) return true;
  const [a, b] = parts;

  if (a === 127) return true; // loopback (127.0.0.0/8)
  if (a === 10) return true; // private (10.0.0.0/8)
  if (a === 172 && b >= 16 && b <= 31) return true; // private (172.16.0.0/12)
  if (a === 192 && b === 168) return true; // private (192.168.0.0/16)
  if (a === 169 && b === 254) return true; // link-local incl. cloud metadata 169.254.169.254 (169.254.0.0/16)
  if (a === 100 && b >= 64 && b <= 127) return true; // carrier-grade NAT (100.64.0.0/10)
  if (a === 0) return true; // "this network" (0.0.0.0/8)
  if (a >= 224) return true; // multicast/reserved/broadcast (224.0.0.0/4 and above)
  return false;
}

function isBlockedIpv6(ip) {
  const lower = ip.toLowerCase();
  if (lower === '::1' || lower === '::') return true; // loopback / unspecified
  if (lower.startsWith('::ffff:')) {
    // IPv4-mapped IPv6 address - unwrap and check the embedded IPv4 address
    const v4 = lower.slice('::ffff:'.length);
    if (net.isIP(v4) === 4) return isBlockedIpv4(v4);
  }
  if (/^fe[89ab][0-9a-f]:/.test(lower)) return true; // link-local (fe80::/10)
  if (/^f[cd][0-9a-f]{2}:/.test(lower)) return true; // unique local (fc00::/7)
  return false;
}

/**
 * True if `ip` is a localhost/private/link-local/cloud-metadata/reserved
 * address that the scanner must never connect to.
 */
function isBlockedIp(ip) {
  if (!ip || typeof ip !== 'string') return true;
  const version = net.isIP(ip);
  if (version === 4) return isBlockedIpv4(ip);
  if (version === 6) return isBlockedIpv6(ip);
  return true; // unparseable - block defensively
}

class SsrfBlockedError extends Error {
  constructor(hostname, address) {
    super(`Refusing to connect to "${hostname}" - it resolves to ${address}, a restricted/private address.`);
    this.name = 'SsrfBlockedError';
    this.code = 'ERR_SSRF_BLOCKED';
    this.hostname = hostname;
    this.address = address;
  }
}

/**
 * A drop-in replacement for Node's dns.lookup that rejects any resolved
 * address in a blocked range. Passed to http.Agent/https.Agent as their
 * `lookup` option, so it governs every connection those agents make -
 * including reconnects for redirect hops when the agent is reused.
 */
function safeDnsLookup(hostname, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }

  // "localhost" resolves to a loopback address on most systems, but some
  // minimal/misconfigured resolvers can behave unexpectedly - block by name
  // directly rather than relying solely on the resolved address.
  if (hostname.toLowerCase() === 'localhost') {
    return callback(new SsrfBlockedError(hostname, '127.0.0.1 (localhost)'));
  }

  dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) return callback(err);
    const list = Array.isArray(addresses) ? addresses : [addresses];
    if (list.length === 0) {
      return callback(new Error(`DNS lookup for "${hostname}" returned no addresses`));
    }

    const blocked = list.find(a => isBlockedIp(a.address));
    if (blocked) {
      return callback(new SsrfBlockedError(hostname, blocked.address));
    }

    if (options && options.all) {
      return callback(null, list, undefined);
    }
    const first = list[0];
    callback(null, first.address, first.family);
  });
}

/**
 * Wraps an Agent's createConnection so a literal-IP target is checked
 * directly, BEFORE Node gets a chance to connect to it. This matters because
 * a custom `lookup` function (safeDnsLookup, passed in below) is only ever
 * invoked by Node when a hostname actually needs to be resolved - when the
 * "hostname" in a URL is already an IP literal (e.g. "http://127.0.0.1/", or
 * a redirect target like "http://169.254.169.254/..."), Node's networking
 * stack skips DNS resolution entirely and connects directly, bypassing a
 * lookup-only guard completely. Patching createConnection closes that gap at
 * the agent level, so these agents are safe to use on their own - callers
 * don't have to separately remember to pre-validate every URL themselves
 * (though http.util.js does that too, for defense in depth and clearer
 * error messages before a connection is even attempted).
 */
function guardAgentConnections(agent) {
  const originalCreateConnection = agent.createConnection.bind(agent);
  agent.createConnection = function (options, callback) {
    const host = options && options.host;
    if (host && net.isIP(host) && isBlockedIp(host)) {
      const err = new SsrfBlockedError(host, host);
      process.nextTick(() => callback(err));
      return;
    }
    return originalCreateConnection(options, callback);
  };
  return agent;
}

/**
 * Creates a matched pair of http/https Agents whose connections are pinned
 * through safeDnsLookup for hostname targets, AND directly checked for
 * literal-IP targets (see guardAgentConnections) - i.e. whatever address
 * they actually connect to has already been validated either way. This
 * closes both the DNS-rebinding gap (checking the URL string alone isn't
 * enough, since a hostname can resolve differently between a naive
 * pre-check and the actual connection) and the IP-literal gap (checking the
 * URL string alone would also miss a target that's already a bare IP).
 */
function createSafeAgents() {
  return {
    httpAgent: guardAgentConnections(new http.Agent({ lookup: safeDnsLookup, keepAlive: false })),
    httpsAgent: guardAgentConnections(new https.Agent({ lookup: safeDnsLookup, keepAlive: false }))
  };
}

/**
 * Resolves `hostname` and rejects if it points at a blocked address. Used as
 * an early, request-independent check (e.g. in the API route, before
 * dispatching any of the 9 parallel checks) so obviously-unsafe targets are
 * rejected immediately with a clear error rather than failing deep inside
 * some check's fetch call.
 */
function assertHostnameIsSafe(hostname) {
  return new Promise((resolve, reject) => {
    safeDnsLookup(hostname, {}, (err) => {
      if (err) return reject(err);
      resolve();
    });
  });
}

/**
 * Validates a full URL before it's fetched. This is deliberately separate
 * from (and used IN ADDITION TO) createSafeAgents()'s DNS-lookup hook: when
 * a URL's host is already a literal IP address (e.g. "http://127.0.0.1/" or
 * a redirect target like "http://169.254.169.254/..."), Node's networking
 * stack does not invoke a custom `lookup` function at all - there's nothing
 * to resolve - so an IP-literal target would otherwise sail straight past
 * the agent-level protection. Call this for every hop of every request
 * (see http.util.js) so a malicious redirect chain can't reach an IP
 * literal either.
 */
function assertUrlIsSafe(urlString) {
  const parsed = new URL(urlString);

  // Also guards against a malicious redirect Location header smuggling a
  // non-http(s) scheme (file://, ftp://, etc) into a later hop.
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new SsrfBlockedError(parsed.hostname || urlString, `disallowed protocol "${parsed.protocol}"`);
  }

  const hostname = parsed.hostname.replace(/^\[|\]$/g, ''); // strip IPv6 URL brackets
  if (net.isIP(hostname) && isBlockedIp(hostname)) {
    throw new SsrfBlockedError(hostname, hostname);
  }
  if (hostname.toLowerCase() === 'localhost') {
    throw new SsrfBlockedError(hostname, '127.0.0.1 (localhost)');
  }
}

module.exports = {
  isBlockedIp,
  safeDnsLookup,
  createSafeAgents,
  assertHostnameIsSafe,
  assertUrlIsSafe,
  SsrfBlockedError
};
