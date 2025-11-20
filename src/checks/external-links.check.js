/**
 * External Links Check
 * Lists all external links found on the page
 */

const axios = require('axios');
const cheerio = require('cheerio');
const { calculateCategoryScore } = require('../utils/score-calculator.util');

class ExternalLinksCheck {
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
      const externalLinks = [];

      // Extract all <a> tag links
      $('a[href]').each((i, el) => {
        const href = $(el).attr('href');
        if (href && !href.startsWith('javascript:') && !href.startsWith('mailto:') && !href.startsWith('#')) {
          try {
            const absoluteUrl = new URL(href, url).href;
            const linkHostname = new URL(absoluteUrl).hostname;
            
            if (linkHostname !== hostname) {
              externalLinks.push(absoluteUrl);
            }
          } catch (e) {
            // Skip invalid URLs
          }
        }
      });

      // Extract links from button onclick attributes
      $('button[onclick], input[onclick], div[onclick], span[onclick], a[onclick]').each((i, el) => {
        const onclick = $(el).attr('onclick');
        if (onclick) {
          // Match window.open, location.href, location.assign patterns
          const urlPatterns = [
            /window\.open\s*\(\s*['"]([^'"]+)['"]/gi,
            /location\.href\s*=\s*['"]([^'"]+)['"]/gi,
            /location\.assign\s*\(\s*['"]([^'"]+)['"]/gi,
            /location\s*=\s*['"]([^'"]+)['"]/gi,
            /window\.location\s*=\s*['"]([^'"]+)['"]/gi
          ];

          for (const pattern of urlPatterns) {
            let match;
            while ((match = pattern.exec(onclick)) !== null) {
              try {
                const absoluteUrl = new URL(match[1], url).href;
                const linkHostname = new URL(absoluteUrl).hostname;
                
                if (linkHostname !== hostname) {
                  externalLinks.push(absoluteUrl);
                }
              } catch (e) {
                // Skip invalid URLs
              }
            }
          }
        }
      });

      // Extract links from inline JavaScript in script tags
      const scripts = $('script').toArray();
      for (const script of scripts) {
        const scriptContent = $(script).html() || '';
        
        const urlPatterns = [
          /window\.open\s*\(\s*['"]([^'"]+)['"]/gi,
          /location\.href\s*=\s*['"]([^'"]+)['"]/gi,
          /location\.assign\s*\(\s*['"]([^'"]+)['"]/gi,
          /window\.location\s*=\s*['"]([^'"]+)['"]/gi,
          /window\.location\.replace\s*\(\s*['"]([^'"]+)['"]/gi,
          /['"]https?:\/\/[^'"]+['"]/gi  // Any quoted URLs
        ];

        for (const pattern of urlPatterns) {
          let match;
          while ((match = pattern.exec(scriptContent)) !== null) {
            let extractedUrl = match[1] || match[0].replace(/['"]/g, '');
            
            // Clean up the URL
            extractedUrl = extractedUrl.trim();
            
            if (extractedUrl.startsWith('http://') || extractedUrl.startsWith('https://')) {
              try {
                const absoluteUrl = new URL(extractedUrl).href;
                const linkHostname = new URL(absoluteUrl).hostname;
                
                if (linkHostname !== hostname) {
                  externalLinks.push(absoluteUrl);
                }
              } catch (e) {
                // Skip invalid URLs
              }
            }
          }
        }
      }

      // Extract popup/modal links from data attributes
      $('[data-url], [data-href], [data-link], [data-popup-url]').each((i, el) => {
        const dataAttrs = ['data-url', 'data-href', 'data-link', 'data-popup-url'];
        
        for (const attr of dataAttrs) {
          const dataUrl = $(el).attr(attr);
          if (dataUrl) {
            try {
              const absoluteUrl = new URL(dataUrl, url).href;
              const linkHostname = new URL(absoluteUrl).hostname;
              
              if (linkHostname !== hostname) {
                externalLinks.push(absoluteUrl);
              }
            } catch (e) {
              // Skip invalid URLs
            }
          }
        }
      });

      // Extract form action URLs
      $('form[action]').each((i, el) => {
        const action = $(el).attr('action');
        if (action && !action.startsWith('javascript:') && !action.startsWith('#')) {
          try {
            const absoluteUrl = new URL(action, url).href;
            const linkHostname = new URL(absoluteUrl).hostname;
            
            if (linkHostname !== hostname) {
              externalLinks.push(absoluteUrl);
            }
          } catch (e) {
            // Skip invalid URLs
          }
        }
      });

      // Extract iframe sources
      $('iframe[src]').each((i, el) => {
        const src = $(el).attr('src');
        if (src && !src.startsWith('javascript:') && !src.startsWith('about:')) {
          try {
            const absoluteUrl = new URL(src, url).href;
            const linkHostname = new URL(absoluteUrl).hostname;
            
            if (linkHostname !== hostname) {
              externalLinks.push(absoluteUrl);
            }
          } catch (e) {
            // Skip invalid URLs
          }
        }
      });

      // Remove duplicates
      const uniqueExternalLinks = [...new Set(externalLinks)];

      // Generate checks
      checks.push({
        name: 'External Links Detected',
        status: uniqueExternalLinks.length === 0 ? 'info' : 'pass',
        description: uniqueExternalLinks.length === 0 
          ? 'No external links found on this page'
          : `Found ${uniqueExternalLinks.length} unique external link${uniqueExternalLinks.length !== 1 ? 's' : ''}`,
        severity: 'low'
      });

      // Check link diversity
      const domains = uniqueExternalLinks.map(link => {
        try {
          return new URL(link).hostname;
        } catch {
          return null;
        }
      }).filter(Boolean);
      
      const uniqueDomains = [...new Set(domains)];
      
      checks.push({
        name: 'External Domains',
        status: 'info',
        description: `Links point to ${uniqueDomains.length} unique external domain${uniqueDomains.length !== 1 ? 's' : ''}`,
        severity: 'low'
      });

      return {
        category: 'External Links',
        icon: '🌍',
        score: calculateCategoryScore(checks),
        checks,
        externalLinks: uniqueExternalLinks,
        externalDomains: uniqueDomains
      };
    } catch (error) {
      checks.push({
        name: 'External Links Analysis Error',
        status: 'error',
        description: `Error analyzing external links: ${error.message}`,
        severity: 'medium'
      });

      return {
        category: 'External Links',
        icon: '🌍',
        score: 0,
        checks,
        externalLinks: [],
        externalDomains: []
      };
    }
  }
}

module.exports = ExternalLinksCheck;
