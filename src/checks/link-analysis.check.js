/**
 * Link Analysis Check
 * Crawls the site's <a> tags, meta-refresh, and inline JS redirects, and
 * checks whether any of them redirect to a suspicious domain.
 *
 * NOTE on "External Link Density": this check only looks at <a href> tags
 * found directly in the initial HTML. external-links.check.js additionally
 * scans onclick handlers, inline <script> bodies (including base64/atob
 * obfuscation), JSON-LD, data-* attributes, form actions, and iframe sources
 * - so its link count will legitimately be larger. Both checks now use the
 * SAME density formula (unique external URLs / count of `p, article, section`
 * elements) so the numbers are comparable; each check's description says
 * explicitly what it counted, rather than presenting two similarly-named but
 * differently-scoped numbers as if they were interchangeable.
 */

const axios = require('axios');
const cheerio = require('cheerio');
const { calculateCategoryScore } = require('../utils/score-calculator.util');
const { isSameSite } = require('../utils/domain.util');
const { attachEvidence, buildLinkEvidence } = require('../utils/evidence.util');

class LinkAnalysisCheck {
  constructor() {
    // Used only to decide which external links are worth probing further (via a HEAD
    // request) for their real redirect destination - this is deliberately broad since
    // a false positive here just means "check this link", not "flag this site".
    // NOTE: previously also included 'out.', 'tracking', and 'redirect' as bare
    // substrings, which matched huge numbers of unrelated legitimate URLs (e.g.
    // "out." matches "checkout.stripe.com", "tracking" matches any analytics script
    // path, "redirect" matches normal OAuth "redirect_uri" params) - removed.
    this.suspiciousRedirectDomains = [
      'bit.ly', 'tinyurl', 'short.link', 'goo.gl',
      'ow.ly', 'adf.ly', 'clickbank', 'amazon-click', '.click', '/go?'
    ];
  }

  async analyze(url) {
    const checks = [];
    const hostname = new URL(url).hostname;

    try {
      const response = await axios.get(url, {
        timeout: 15000,
        validateStatus: () => true,
        maxRedirects: 3
      });

      const $ = cheerio.load(response.data);
      const links = []; // { url, sourceType, sourceDetail }
      const suspiciousLinks = [];
      const redirectLinks = [];

      // Check for meta refresh redirects (common in phishing)
      const metaRefresh = $('meta[http-equiv="refresh"]').attr('content');
      if (metaRefresh) {
        const urlMatch = metaRefresh.match(/url=(.+?)(?:;|$)/i);
        if (urlMatch) {
          const redirectUrl = urlMatch[1].replace(/['"]/g, '').trim();
          if (this.isSuspiciousDomain(redirectUrl)) {
            suspiciousLinks.push({
              source: 'Meta Refresh',
              sourceType: 'meta-tag',
              redirectTo: redirectUrl,
              reason: 'Automatic redirect to suspicious domain'
            });
          }
        }
      }

      // Check for JavaScript redirects
      const scripts = $('script').text().toLowerCase();
      const jsRedirectPatterns = [
        /window\.location\s*=\s*['"]([^'"]+)['"]/gi,
        /window\.location\.href\s*=\s*['"]([^'"]+)['"]/gi,
        /window\.location\.replace\s*\(\s*['"]([^'"]+)['"]\s*\)/gi
      ];

      for (const pattern of jsRedirectPatterns) {
        let match;
        while ((match = pattern.exec(scripts)) !== null) {
          const redirectUrl = match[1];
          if (this.isSuspiciousDomain(redirectUrl)) {
            suspiciousLinks.push({
              source: 'JavaScript Redirect',
              sourceType: 'script-body',
              redirectTo: redirectUrl,
              reason: 'JavaScript redirect to suspicious domain'
            });
          }
        }
      }

      // Extract all links from the page (only real <a href> tags - script-extracted
      // "links" are handled separately and more defensively in
      // external-links.check.js, since naive text-scraping of scripts/JSON tends to
      // pull out malformed fragments rather than real URLs)
      const externalLinks = [];
      $('a[href]').each((i, el) => {
        const href = $(el).attr('href');
        if (href && !href.startsWith('javascript:') && !href.startsWith('mailto:') && !href.startsWith('#')) {
          try {
            // Convert relative URLs to absolute
            const absoluteUrl = new URL(href, url).href;
            const linkHostname = new URL(absoluteUrl).hostname;

            links.push({ url: absoluteUrl, sourceType: 'a-tag', sourceDetail: $(el).text().trim().slice(0, 60) || null });

            // Track external links using registrable-domain comparison, not raw
            // hostname equality - www.example.com / m.example.com / etc are the
            // same site as example.com, not "external".
            if (!isSameSite(linkHostname, hostname)) {
              externalLinks.push(absoluteUrl);
            }
          } catch (e) {
            // Skip invalid URLs
          }
        }
      });

      // Check links for suspicious patterns and redirects
      for (const link of links.slice(0, 20).map(l => l.url)) { // Check first 20 links only
        try {
          // Check if link domain is a different site from the main domain
          const linkHostname = new URL(link).hostname;

          if (!isSameSite(linkHostname, hostname)) {
            // Check for suspicious redirect patterns
            if (this.isRedirectLink(link)) {
              redirectLinks.push(link);

              // Try to detect redirect destination
              try {
                const redirectResponse = await axios.head(link, {
                  timeout: 5000,
                  maxRedirects: 0,
                  validateStatus: () => true
                });

                const location = redirectResponse.headers.location;
                if (location && this.isSuspiciousDomain(location)) {
                  suspiciousLinks.push({
                    source: link,
                    sourceType: 'a-tag',
                    redirectTo: location,
                    reason: 'Redirects to suspicious domain'
                  });
                }
              } catch (e) {
                // If HEAD fails, might still be suspicious. isSuspiciousDomain() only
                // matches high-confidence patterns (specific TLDs, crypto/gambling
                // redirect chains) here, never bare URL shorteners - a shortener we
                // simply couldn't verify isn't evidence of anything on its own.
                if (this.isSuspiciousDomain(link)) {
                  suspiciousLinks.push({
                    source: link,
                    sourceType: 'a-tag',
                    redirectTo: 'Unknown',
                    reason: 'Suspicious redirect pattern'
                  });
                }
              }
            }
          }
        } catch (e) {
          // Skip errors on individual links
        }
      }

      // Generate checks based on findings
      checks.push({
        id: 'external-links-found',
        name: 'External Links Found',
        status: links.length === 0 ? 'info' : 'pass',
        description: `${links.length} total <a> links detected on page (${externalLinks.length} external, by registrable domain)`,
        severity: 'low',
        explanation: 'Links connect pages together. External links point to a different registrable domain (so www./m./subdomains of the same site don\'t count as external).',
        method: 'Extracts every <a href> in the initially fetched HTML, resolves relative URLs, and compares each link\'s registrable domain (Public Suffix List, via tldts) against the page\'s own domain.',
        risk: 'N/A - informational.',
        fix: 'No action needed.',
        confidence: 'high'
      });
      attachEvidence(checks[checks.length - 1], links.slice(0, 20).map(l => buildLinkEvidence({ url: l.url, sourceType: l.sourceType, sourceDetail: l.sourceDetail })));

      checks.push({
        id: 'redirect-links',
        name: 'Redirect Links',
        status: redirectLinks.length > 5 ? 'warn' : redirectLinks.length > 0 ? 'info' : 'pass',
        description: redirectLinks.length > 0
          ? `${redirectLinks.length} redirect/shortened links detected`
          : 'No suspicious redirect links found',
        severity: 'medium',
        explanation: 'URL shorteners and redirects can mask the true destination of links.',
        method: 'Flags links whose URL contains a known shortener domain (bit.ly, tinyurl, etc) or a generic redirect-path pattern - used only to decide which links are worth probing further, not as a verdict on its own.',
        risk: 'A link can be shortened/redirected to hide its real, potentially malicious destination.',
        fix: redirectLinks.length > 0 ? 'Review the linked shortener/redirect URLs below and confirm their destinations are legitimate.' : 'No action needed.',
        confidence: 'medium'
      });
      attachEvidence(checks[checks.length - 1], redirectLinks.map(u => buildLinkEvidence({ url: u, sourceType: 'a-tag' })));

      checks.push({
        id: 'suspicious-external-redirects',
        name: 'Suspicious External Redirects',
        status: suspiciousLinks.length > 3 ? 'fail' : suspiciousLinks.length > 0 ? 'warn' : 'pass',
        description: suspiciousLinks.length > 0
          ? `${suspiciousLinks.length} links redirect to suspicious domains`
          : 'No malicious redirects detected',
        severity: 'critical',
        explanation: 'Links that redirect to known malicious or suspicious domains may indicate phishing or scam activity.',
        method: 'Follows meta-refresh tags, inline JS location redirects, and (for the first 20 links found) HTTP redirects, checking each destination against a list of high-confidence suspicious patterns (specific bad TLDs, crypto/gambling redirect chains, clickbank).',
        risk: 'Links that redirect through or to known-malicious infrastructure may lead users to phishing pages or scams.',
        fix: suspiciousLinks.length > 0 ? 'Review and remove the flagged links below.' : 'No action needed.',
        confidence: 'high'
      });
      attachEvidence(checks[checks.length - 1], suspiciousLinks.map(s => buildLinkEvidence({ url: s.source, sourceType: s.sourceType || 'a-tag', sourceDetail: `${s.reason} → ${s.redirectTo}` })));

      // Calculate external link density using the same formula as
      // external-links.check.js: unique external URLs / count of content elements.
      const contentElements = $('p, article, section').length || 1;
      const uniqueExternalLinks = [...new Set(externalLinks)];
      const externalLinkRatio = uniqueExternalLinks.length / contentElements;

      let densityStatus = 'pass';
      let densityDesc = `${uniqueExternalLinks.length} unique external <a>-tag links / ${contentElements} content blocks = ${externalLinkRatio.toFixed(2)} ratio`;

      if (externalLinkRatio > 2) {
        densityStatus = 'warn';
        densityDesc = `High external link density from <a> tags: ${externalLinkRatio.toFixed(2)} links per content block - may indicate link spam`;
      } else if (externalLinkRatio > 1) {
        densityStatus = 'info';
        densityDesc = `Moderate external link density from <a> tags: ${externalLinkRatio.toFixed(2)} links per content block`;
      } else if (uniqueExternalLinks.length === 0) {
        densityDesc = 'No external <a>-tag links detected';
      }

      checks.push({
        id: 'external-link-density',
        name: 'External Link Density',
        status: densityStatus,
        description: densityDesc,
        severity: 'medium',
        explanation: 'This measures only <a href> links found in the initial HTML. See the "External Link Density" check under External Links for the broader count that also includes scripts, onclick handlers, and other sources.',
        method: 'unique_external_a_tag_links / count(p, article, section elements). Same formula as external-links.check.js, applied to a narrower link source (only <a> tags vs. that check\'s broader script/onclick/JSON-LD/data-attribute scan).',
        risk: 'A high ratio of external links to content may indicate link-spam or a low-quality/affiliate-stuffed page.',
        fix: densityStatus === 'pass' ? 'No action needed.' : 'Review whether all external links are necessary and relevant to the page content.',
        confidence: 'high',
        details: {
          externalLinks: uniqueExternalLinks.length,
          contentElements: contentElements,
          ratio: externalLinkRatio.toFixed(2),
          formula: 'unique_external_a_tag_links / content_elements',
          scope: '<a href> tags only, from the initial HTML'
        }
      });

      const score = calculateCategoryScore(checks);

      return {
        category: 'Link Analysis',
        icon: 'link',
        score: score,
        status: score === null ? 'unavailable' : 'available',
        checks,
        // Matches the 'fail' threshold used for the "Suspicious External Redirects"
        // check above. This flag caps the *entire site's* overall score at 25/100
        // (see analyze.route.js), so it needs multiple corroborating matches rather
        // than a single link - one flagged link (which can itself be a heuristic
        // false positive) is not strong enough evidence to nuke the whole report.
        suspiciousRedirectsDetected: suspiciousLinks.length > 3
      };
    } catch (error) {
      checks.push({
        id: 'link-analysis-error',
        name: 'Link Analysis Error',
        status: 'error',
        description: 'Link analysis unavailable',
        severity: 'medium',
        explanation: `An error occurred: ${error.message}`
      });

      const score = calculateCategoryScore(checks);

      return {
        category: 'Link Analysis',
        icon: 'link',
        score: score,
        status: score === null ? 'unavailable' : 'available',
        checks
      };
    }
  }

  isRedirectLink(url) {
    const urlLower = url.toLowerCase();
    return this.suspiciousRedirectDomains.some(domain => urlLower.includes(domain));
  }

  isSuspiciousDomain(url) {
    const urlLower = url.toLowerCase();

    // High-confidence patterns: safe to flag even when we can't independently verify
    // the destination (e.g. when a HEAD request fails). Restricted to specific
    // known-bad TLDs, brand-impersonation redirect patterns, and crypto/gambling
    // redirect chains.
    // NOTE: previously included bare `/tracking/i` and `/analytics.*redirect/i`,
    // which matched almost any analytics or tracking-pixel URL on the web (extremely
    // common and legitimate) - removed as false-positive generators.
    const highConfidencePatterns = [
      /\.click($|\/)/i,
      /\.download($|\/)/i,
      /clickbank/i,
      // Crypto/gambling redirect patterns
      /whitebit\.com/i,
      /binance.*redirect/i,
      /kraken.*redirect/i,
      /bitget/i,
      /bybit/i,
      /crypto.*casino/i,
      /gambling.*app/i,
      /sports.*betting/i
    ];

    return highConfidencePatterns.some(pattern => pattern.test(urlLower));
  }

  /**
   * Known URL-shortener services. This is a much weaker signal than
   * isSuspiciousDomain() - legitimate businesses routinely use these services for
   * their own promotional/social links, so a shortener alone should never be treated
   * as proof of a malicious redirect, only as a reason to check where it actually goes.
   */
  isKnownShortener(url) {
    const urlLower = url.toLowerCase();
    const shorteners = ['bit.ly', 'tinyurl', 'adf.ly', 'short.link', 'goo.gl', 'ow.ly'];
    return shorteners.some(s => urlLower.includes(s));
  }
}

module.exports = LinkAnalysisCheck;
