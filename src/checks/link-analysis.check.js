/**
 * Link Analysis Check
 * Crawls the site for links and checks if they redirect to suspicious domains
 */

const axios = require('axios');
const cheerio = require('cheerio');
const { calculateCategoryScore } = require('../utils/score-calculator.util');

class LinkAnalysisCheck {
  constructor() {
    this.suspiciousRedirectDomains = [
      'bit.ly', 'tinyurl', 'short.link', 'goo.gl', 
      'ow.ly', 'adf.ly', 'clickbank', 'amazon-click',
      'click/', '.click', 'redirect', 'out.', '/go?',
      'tracking', 'analytics-redirect'
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
        suspiciousRedirectsDetected: suspiciousLinks.length > 0
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
    
    // Check for known phishing/malware domains
    const suspiciousDomainPatterns = [
      /\.click($|\/)/i,
      /\.download($|\/)/i,
      /bit\.ly/i,
      /tinyurl/i,
      /adf\.ly/i,
      /short\.link/i,
      /goo\.gl/i,
      /ow\.ly/i,
      /clickbank/i,
      /tracking/i,
      /analytics.*redirect/i,
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

    return suspiciousDomainPatterns.some(pattern => pattern.test(urlLower));
  }
}

module.exports = LinkAnalysisCheck;
