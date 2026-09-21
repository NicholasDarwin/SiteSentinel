/**
 * Link Analysis Check
 * Crawls the site for links and checks if they redirect to suspicious domains
 */

const axios = require('axios');
const cheerio = require('cheerio');
const { calculateCategoryScore } = require('../utils/score-calculator.util');

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
      const links = [];
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
              redirectTo: redirectUrl,
              reason: 'JavaScript redirect to suspicious domain'
            });
          }
        }
      }

      // Extract all links from the page
      const externalLinks = [];
      $('a[href]').each((i, el) => {
        const href = $(el).attr('href');
        if (href && !href.startsWith('javascript:') && !href.startsWith('mailto:') && !href.startsWith('#')) {
          try {
            // Convert relative URLs to absolute
            const absoluteUrl = new URL(href, url).href;
            const linkHostname = new URL(absoluteUrl).hostname;
            
            links.push(absoluteUrl);
            
            // Track external links (different domain)
            if (linkHostname !== hostname) {
              externalLinks.push(absoluteUrl);
            }
          } catch (e) {
            // Skip invalid URLs
          }
        }
      });

      // Check links for suspicious patterns and redirects
      for (const link of links.slice(0, 20)) { // Check first 20 links only
        try {
          // Check if link domain is different from main domain
          const linkHostname = new URL(link).hostname;
          
          if (linkHostname !== hostname) {
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
                    redirectTo: location,
                    reason: 'Redirects to suspicious domain'
                  });
                }
              } catch (e) {
                // If HEAD fails, might still be suspicious
                if (this.isSuspiciousDomain(link)) {
                  suspiciousLinks.push({
                    source: link,
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
        name: 'External Links Found',
        status: links.length === 0 ? 'info' : 'pass',
        description: `${links.length} total links detected on page (${externalLinks.length} external)`,
        severity: 'low',
        explanation: 'Links connect pages together. External links point to other websites.'
      });

      checks.push({
        name: 'Redirect Links',
        status: redirectLinks.length > 5 ? 'warn' : redirectLinks.length > 0 ? 'info' : 'pass',
        description: redirectLinks.length > 0 
          ? `${redirectLinks.length} redirect/shortened links detected` 
          : 'No suspicious redirect links found',
        severity: 'medium',
        explanation: 'URL shorteners and redirects can mask the true destination of links.'
      });

      checks.push({
        name: 'Suspicious External Redirects',
        status: suspiciousLinks.length > 3 ? 'fail' : suspiciousLinks.length > 0 ? 'warn' : 'pass',
        description: suspiciousLinks.length > 0
          ? `${suspiciousLinks.length} links redirect to suspicious domains`
          : 'No malicious redirects detected',
        severity: 'critical',
        explanation: 'Links that redirect to known malicious or suspicious domains may indicate phishing or scam activity.'
      });

      // Calculate external link density properly
      // Density = external links / total content elements
      const contentElements = $('p, article, section, div:has(> p)').length || 1;
      const externalLinkRatio = externalLinks.length / contentElements;
      
      // Express as a ratio, not a percentage > 100
      let densityStatus = 'pass';
      let densityDesc = `External link ratio: ${externalLinkRatio.toFixed(2)} links per content block`;
      
      if (externalLinkRatio > 2) {
        densityStatus = 'warn';
        densityDesc = `High external link density: ${externalLinkRatio.toFixed(2)} links per content block - may indicate link spam`;
      } else if (externalLinkRatio > 1) {
        densityStatus = 'info';
        densityDesc = `Moderate external link density: ${externalLinkRatio.toFixed(2)} links per content block`;
      } else if (externalLinks.length === 0) {
        densityDesc = 'No external links detected';
      }
      
      checks.push({
        name: 'External Link Density',
        status: densityStatus,
        description: densityDesc,
        severity: 'medium',
        explanation: 'Link density measures external links relative to content. Formula: external_links / content_elements. A high ratio may indicate affiliate spam or low-quality content.',
        details: {
          externalLinks: externalLinks.length,
          contentElements: contentElements,
          ratio: externalLinkRatio.toFixed(2)
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
