/**
 * External Links Check
 * Lists all external links found on the page using Puppeteer for dynamic content
 */

const axios = require('axios');
const cheerio = require('cheerio');
const { calculateCategoryScore } = require('../utils/score-calculator.util');

class ExternalLinksCheck {
  async analyze(url) {
    const checks = [];
    const hostname = new URL(url).hostname;

    try {
      // Try to use Puppeteer for dynamic link detection if available
      let dynamicLinks = [];
      try {
        const puppeteer = require('puppeteer');
        dynamicLinks = await this.extractDynamicLinks(url, hostname, puppeteer);
      } catch (puppeteerError) {
        // Puppeteer not available, continue with static analysis only
        console.log('Puppeteer not available, using static analysis only');
      }

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

      // Remove duplicates and merge with dynamic links
      const allLinks = [...externalLinks, ...dynamicLinks];
      const uniqueExternalLinks = [...new Set(allLinks)];

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

  async extractDynamicLinks(url, hostname, puppeteer) {
    const dynamicLinks = [];
    let browser = null;

    try {
      browser = await puppeteer.launch({
        headless: true,
        args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
      });

      const page = await browser.newPage();
      
      // Track all network requests for external links
      const requestedUrls = new Set();
      page.on('request', request => {
        const requestUrl = request.url();
        try {
          const requestHostname = new URL(requestUrl).hostname;
          if (requestHostname !== hostname && (requestUrl.startsWith('http://') || requestUrl.startsWith('https://'))) {
            requestedUrls.add(requestUrl);
          }
        } catch (e) {
          // Skip invalid URLs
        }
      });

      await page.goto(url, { 
        waitUntil: 'networkidle2', 
        timeout: 30000 
      });

      // Extract all links from the page after JavaScript execution
      const extractedLinks = await page.evaluate((pageHostname) => {
        const links = [];
        
        // Get all anchor tags
        document.querySelectorAll('a[href]').forEach(el => {
          const href = el.href;
          if (href) {
            try {
              const linkHostname = new URL(href).hostname;
              if (linkHostname !== pageHostname) {
                links.push(href);
              }
            } catch (e) {}
          }
        });

        // Get all elements with onclick
        document.querySelectorAll('[onclick]').forEach(el => {
          const onclick = el.getAttribute('onclick');
          if (onclick) {
            const urlMatches = onclick.match(/['"]https?:\/\/[^'"]+['"]/g);
            if (urlMatches) {
              urlMatches.forEach(match => {
                const url = match.replace(/['"]/g, '');
                try {
                  const linkHostname = new URL(url).hostname;
                  if (linkHostname !== pageHostname) {
                    links.push(url);
                  }
                } catch (e) {}
              });
            }
          }
        });

        // Get form actions
        document.querySelectorAll('form[action]').forEach(el => {
          const action = el.action;
          if (action) {
            try {
              const linkHostname = new URL(action).hostname;
              if (linkHostname !== pageHostname) {
                links.push(action);
              }
            } catch (e) {}
          }
        });

        // Get iframes
        document.querySelectorAll('iframe[src]').forEach(el => {
          const src = el.src;
          if (src) {
            try {
              const linkHostname = new URL(src).hostname;
              if (linkHostname !== pageHostname) {
                links.push(src);
              }
            } catch (e) {}
          }
        });

        return links;
      }, hostname);

      dynamicLinks.push(...extractedLinks);

      // Click on all clickable elements and capture any navigation attempts
      await page.evaluate(() => {
        const clickableSelectors = [
          'button', 'a', '[role="button"]', '[onclick]', 
          'input[type="button"]', 'input[type="submit"]',
          '[data-url]', '[data-href]', '[data-link]'
        ];
        
        clickableSelectors.forEach(selector => {
          document.querySelectorAll(selector).forEach((el, index) => {
            // Only click first 50 of each type to avoid too many interactions
            if (index < 50) {
              try {
                el.click();
              } catch (e) {}
            }
          });
        });
      });

      // Wait a bit for any dynamic content to load
      await page.waitForTimeout(2000);

      // Extract links again after clicking
      const afterClickLinks = await page.evaluate((pageHostname) => {
        const links = [];
        document.querySelectorAll('a[href]').forEach(el => {
          const href = el.href;
          if (href) {
            try {
              const linkHostname = new URL(href).hostname;
              if (linkHostname !== pageHostname) {
                links.push(href);
              }
            } catch (e) {}
          }
        });
        return links;
      }, hostname);

      dynamicLinks.push(...afterClickLinks);

      // Add all network-requested URLs
      dynamicLinks.push(...Array.from(requestedUrls));

      await browser.close();

      return [...new Set(dynamicLinks)]; // Remove duplicates
    } catch (error) {
      if (browser) {
        await browser.close();
      }
      console.error('Dynamic link extraction error:', error.message);
      return dynamicLinks;
    }
  }
}

module.exports = ExternalLinksCheck;
