/**
 * Domain Classification Utilities
 *
 * Uses the Public Suffix List (via tldts) to correctly compare domains by
 * their *registrable domain* (a.k.a. eTLD+1) rather than naive substring or
 * suffix checks. This is what makes "i5.walmartimages.com" not equal to
 * "walmartimages-fake.com", and "www.walmart.com" / "corporate.walmart.com"
 * correctly recognized as the same site as "walmart.com".
 */

const tldts = require('tldts');

/**
 * Returns the registrable domain (eTLD+1) for a hostname, e.g.
 * "i5.walmartimages.com" -> "walmartimages.com", "example.co.uk" -> "example.co.uk".
 * Returns null for bare IP addresses or unparseable input.
 */
function getRegistrableDomain(hostname) {
  if (!hostname || typeof hostname !== 'string') return null;
  try {
    return tldts.getDomain(hostname.toLowerCase());
  } catch (e) {
    return null;
  }
}

/**
 * True if `hostname` is the same registrable domain as `rootHostname`, or a
 * subdomain of it (e.g. isSameSite('i5.walmartimages.com', 'walmartimages.com') -> true,
 * isSameSite('www.walmart.com', 'walmart.com') -> true).
 * Falls back to exact hostname match when either side is a bare IP address
 * (which has no registrable domain).
 */
function isSameSite(hostname, rootHostname) {
  if (!hostname || !rootHostname) return false;
  const a = hostname.toLowerCase();
  const b = rootHostname.toLowerCase();
  if (a === b) return true;

  const domainA = getRegistrableDomain(a);
  const domainB = getRegistrableDomain(b);
  if (domainA && domainB) return domainA === domainB;

  // No registrable domain on either side (e.g. IP addresses) - only exact match counts.
  return false;
}

/**
 * True if `hostname` is a strict subdomain of `rootHostname`'s registrable domain
 * (i.e. same site per isSameSite, but not the bare root itself).
 */
function isSubdomainOf(hostname, rootHostname) {
  return isSameSite(hostname, rootHostname) && hostname.toLowerCase() !== rootHostname.toLowerCase();
}

// Well-known CDN / script-hosting domains. Matched by registrable domain, so
// listing "jsdelivr.net" also covers "cdn.jsdelivr.net" automatically.
const KNOWN_CDNS = [
  'googleapis.com', 'gstatic.com', 'google.com', 'googletagmanager.com',
  'cloudflare.com', 'cloudflareinsights.com', 'jsdelivr.net', 'jsdelivr.com',
  'unpkg.com', 'jquery.com', 'bootstrapcdn.com', 'akamaized.net', 'akamai.net',
  'fastly.net', 'fastly.com', 'cloudfront.net', 'azureedge.net',
  'edgekey.net', 'edgesuite.net', 'stackpathcdn.com', 'kxcdn.com', 'polyfill.io'
];

// Well-known third-party vendors commonly embedded on commercial sites
// (payments, fraud detection, analytics, tag managers, support widgets, etc.)
// A script from one of these is a known, identifiable vendor - not an
// "unknown source" - even though it isn't a general-purpose CDN.
const KNOWN_VENDORS = [
  // Analytics / tag management
  'google-analytics.com', 'googletagmanager.com', 'doubleclick.net',
  'hotjar.com', 'segment.com', 'segment.io', 'mixpanel.com', 'amplitude.com',
  'adobedtm.com', 'demdex.net', 'omtrdc.net', 'newrelic.com', 'nr-data.net',
  'bugsnag.com', 'sentry.io', 'datadoghq.com', 'fullstory.com', 'quantummetric.com',
  // Payments / fraud
  'paypal.com', 'paypalobjects.com', 'stripe.com', 'braintreegateway.com',
  'signifyd.com', 'forter.com', 'riskified.com', 'cybersource.com',
  'adyen.com', 'klarna.com', 'affirm.com', 'afterpay.com',
  // Support / chat / marketing widgets
  'zendesk.com', 'intercom.io', 'drift.com', 'livechatinc.com', 'salesforce.com',
  'exponea.com', 'bazaarvoice.com', 'trustpilot.com', 'yotpo.com', 'olapic.com',
  'criteo.com', 'criteo.net', 'facebook.net', 'facebook.com', 'twitter.com',
  'x.com', 'linkedin.com', 'tiktok.com', 'pinterest.com', 'snapchat.com',
  'bing.com', 'clarity.ms', 'microsoft.com'
];

function isKnownCdn(hostname) {
  const domain = getRegistrableDomain(hostname);
  if (!domain) return false;
  return KNOWN_CDNS.includes(domain);
}

function isKnownVendor(hostname) {
  const domain = getRegistrableDomain(hostname);
  if (!domain) return false;
  return KNOWN_VENDORS.includes(domain);
}

// Suffix words used to recognize a brand's own separate asset/CDN domains,
// e.g. "walmartimages.com" for a page on "walmart.com". Deliberately narrow:
// only exact "<brand><suffix>" (optionally hyphenated) matches count.
const BRAND_OWNED_ASSET_SUFFIXES = [
  'images', 'img', 'static', 'assets', 'cdn', 'media', 'content', 'files'
];

/**
 * True if `hostname`'s registrable domain looks like a brand's own separate
 * asset/CDN domain - e.g. "walmartimages.com" for a page on "walmart.com".
 * This is a heuristic, not a guarantee, and is deliberately narrow: it only
 * matches an EXACT "<brand><suffix>" combination from a small whitelist of
 * asset-related words (images/cdn/static/assets/...), never a bare substring
 * match. A bare "contains the brand name anywhere" rule was tried first and
 * rejected - it classified "evil-walmart-login.com" as first-party, which
 * would have suppressed a real phishing signal in a security tool. This
 * narrower version still can't catch domains with no textual relationship to
 * the brand at all (e.g. a dedicated short-link domain like "wal.co") -
 * those stay 'unknown' and rely on the scoring being scaled sensibly rather
 * than on perfect classification (see score-calculator.util.js).
 */
function isLikelyBrandOwned(hostname, pageHostname) {
  const candidateDomain = getRegistrableDomain(hostname);
  const pageDomain = getRegistrableDomain(pageHostname);
  if (!candidateDomain || !pageDomain) return false;

  const brandToken = tldts.getDomainWithoutSuffix(pageDomain);
  if (!brandToken || brandToken.length < 4) return false;

  const candidateToken = tldts.getDomainWithoutSuffix(candidateDomain);
  if (!candidateToken) return false;

  return BRAND_OWNED_ASSET_SUFFIXES.some(suffix =>
    candidateToken === `${brandToken}${suffix}` ||
    candidateToken === `${brandToken}-${suffix}` ||
    candidateToken === `${brandToken}_${suffix}`
  );
}

/**
 * Classify a script/resource hostname relative to the page's own hostname.
 * Returns { tier, reason } where tier is one of: 'first-party', 'known-cdn',
 * 'known-vendor', 'unknown'.
 */
function classifyDomain(hostname, pageHostname) {
  if (!hostname) return { tier: 'unknown', reason: 'No hostname' };

  if (pageHostname && isSameSite(hostname, pageHostname)) {
    return { tier: 'first-party', reason: `Same registrable domain as ${pageHostname}` };
  }
  if (pageHostname && isLikelyBrandOwned(hostname, pageHostname)) {
    return { tier: 'first-party', reason: `Domain name contains the site's brand - likely owned infrastructure (e.g. a separate asset/CDN domain)` };
  }
  const cdnDomain = getRegistrableDomain(hostname);
  if (isKnownCdn(hostname)) {
    return { tier: 'known-cdn', reason: `Recognized CDN (${cdnDomain})` };
  }
  if (isKnownVendor(hostname)) {
    return { tier: 'known-vendor', reason: `Recognized third-party vendor (${cdnDomain})` };
  }
  return { tier: 'unknown', reason: 'Domain not recognized as first-party, a known CDN, or a known vendor' };
}

/**
 * True if `hostname` looks like a real, resolvable hostname - has a
 * registrable domain, is a valid IP address, or is "localhost". Used to
 * reject junk extracted from loosely-matched text (template placeholders,
 * truncated strings, etc) before treating it as a real URL.
 */
function isValidHostname(hostname) {
  if (!hostname || typeof hostname !== 'string') return false;
  const lower = hostname.toLowerCase();
  if (lower === 'localhost') return true;
  try {
    const parsed = tldts.parse(lower);
    if (parsed.isIp) return true;
    return !!parsed.domain;
  } catch (e) {
    return false;
  }
}

module.exports = {
  getRegistrableDomain,
  isValidHostname,
  isSameSite,
  isSubdomainOf,
  isKnownCdn,
  isKnownVendor,
  isLikelyBrandOwned,
  classifyDomain,
  KNOWN_CDNS,
  KNOWN_VENDORS
};
