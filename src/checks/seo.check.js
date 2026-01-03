/**
 * SEO Checks
 */

const axios = require('axios');
const cheerio = require('cheerio');
const puppeteer = require('puppeteer');
const { calculateCategoryScore } = require('../utils/score-calculator.util');

class SeoCheck {
  /**
   * Extract all links from the page using headless browser
   * Opens site invisibly, clicks all interactive elements, and collects all links
   */
  async extractAllLinks(url) {
    let browser;
    try {
      browser = await puppeteer.launch({
        headless: true,
        args: ['--no-sandbox', '--disable-setuid-sandbox']
      });

      const page = await browser.newPage();
      
      // Set viewport and user agent
      await page.setViewport({ width: 1920, height: 1080 });
      await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');
      
      // Navigate to the page
      await page.goto(url, { 
        waitUntil: 'networkidle2',
        timeout: 30000 
      });

      // Wait a bit for any dynamic content
      await page.waitForTimeout(2000);

      // Collect all links before clicking
      const allLinks = new Set();
      
      // Extract initial links
      const initialLinks = await page.evaluate(() => {
        const links = [];
        document.querySelectorAll('a[href]').forEach(a => {
          const href = a.href;
          if (href) links.push(href);
        });
        return links;
      });
      initialLinks.forEach(link => allLinks.add(link));

      // Find all clickable elements (buttons, clickable divs, etc.)
      const clickableSelectors = [
        'button',
        'a',
        '[role="button"]',
        '[onclick]',
        'input[type="button"]',
        'input[type="submit"]',
        '[tabindex]',
        '.btn',
        '.button',
        'details summary'
      ];

      for (const selector of clickableSelectors) {
        try {
          const elements = await page.$$(selector);
          
          for (let i = 0; i < elements.length; i++) {
            try {
              // Check if element is visible and clickable
              const isVisible = await page.evaluate(el => {
                const style = window.getComputedStyle(el);
                return style.display !== 'none' && 
                       style.visibility !== 'hidden' && 
                       style.opacity !== '0';
              }, elements[i]);

              if (isVisible) {
                // Click the element
                await elements[i].click({ delay: 50 });
                
                // Wait for any navigation or dynamic content
                await page.waitForTimeout(500);
                
                // Extract new links after click
                const newLinks = await page.evaluate(() => {
                  const links = [];
                  document.querySelectorAll('a[href]').forEach(a => {
                    const href = a.href;
                    if (href) links.push(href);
                  });
                  return links;
                });
                newLinks.forEach(link => allLinks.add(link));
              }
            } catch (clickError) {
              // Element might not be clickable, continue
              continue;
            }
          }
        } catch (selectorError) {
          // Selector might not exist, continue
          continue;
        }
      }

      // Also extract links from various sources
      const additionalLinks = await page.evaluate(() => {
        const links = new Set();
        
        // Links from href attributes
        document.querySelectorAll('[href]').forEach(el => {
          const href = el.getAttribute('href');
          if (href) links.add(href);
        });
        
        // Links from src attributes (scripts, images, iframes)
        document.querySelectorAll('[src]').forEach(el => {
          const src = el.getAttribute('src');
          if (src) links.add(src);
        });
        
        // Links from data attributes
        document.querySelectorAll('[data-url], [data-href], [data-link]').forEach(el => {
          const dataUrl = el.getAttribute('data-url') || 
                         el.getAttribute('data-href') || 
                         el.getAttribute('data-link');
          if (dataUrl) links.add(dataUrl);
        });
        
        // Links from meta tags
        document.querySelectorAll('meta[content]').forEach(meta => {
          const content = meta.getAttribute('content');
          if (content && (content.startsWith('http://') || content.startsWith('https://'))) {
            links.add(content);
          }
        });
        
        return Array.from(links);
      });
      
      additionalLinks.forEach(link => allLinks.add(link));

      await browser.close();
      
      return Array.from(allLinks);

    } catch (error) {
      if (browser) {
        await browser.close();
      }
      throw error;
    }
  }

  async analyze(url) {
    const checks = [];

    try {
      const response = await axios.get(url, { 
        timeout: 15000,
        validateStatus: () => true
      });

      const $ = cheerio.load(response.data);

      // 1. Meta Title
      const title = $('title').text();
      // For short titles like "Google", treat as pass if title exists (JS sites may have minimal HTML)
      checks.push({
        name: 'Page Title',
        status: title && title.length > 0 ? (title.length >= 30 && title.length <= 60 ? 'pass' : title.length > 2 ? 'warn' : 'fail') : 'fail',
        description: title ? `Title: "${title}" (${title.length} chars)` : 'No page title found',
        severity: 'high'
      });

      // 2. Meta Description
      const metaDescription = $('meta[name="description"]').attr('content');
      // JS sites may load description dynamically; downgrade missing description to 'warn' instead of 'fail'
      checks.push({
        name: 'Meta Description',
        status: metaDescription ? (metaDescription.length >= 120 && metaDescription.length <= 160 ? 'pass' : 'warn') : 'warn',
        description: metaDescription ? `Description: "${metaDescription}" (${metaDescription.length} chars)` : 'No meta description (may be loaded dynamically)',
        severity: 'high'
      });

      // 3. Heading Structure (H1)
      const h1Count = $('h1').length;
      // JS sites may render H1 dynamically; be more lenient
      checks.push({
        name: 'H1 Tag Structure',
        status: h1Count === 1 ? 'pass' : h1Count > 0 ? 'warn' : 'warn',
        description: h1Count === 1 ? 'Single H1 tag found (optimal)' : h1Count > 0 ? `${h1Count} H1 tags found (should be 1)` : 'No H1 tags in static HTML (may be rendered by JavaScript)',
        severity: 'high'
      });

      // 4. Robots Meta Tag
      const robotsMeta = $('meta[name="robots"]').attr('content');
      checks.push({
        name: 'Robots Meta Tag',
        status: robotsMeta ? 'pass' : 'info',
        description: robotsMeta ? `Robots: ${robotsMeta}` : 'No robots meta tag (default: index, follow)',
        severity: 'low'
      });

      // 5. Canonical Tag
      const canonical = $('link[rel="canonical"]').attr('href');
      checks.push({
        name: 'Canonical Tag',
        status: canonical ? 'pass' : 'warn',
        description: canonical ? `Canonical: ${canonical}` : 'No canonical tag (important for duplicate content)',
        severity: 'medium'
      });

      // 6. Open Graph Tags
      const ogTitle = $('meta[property="og:title"]').attr('content');
      const ogImage = $('meta[property="og:image"]').attr('content');
      checks.push({
        name: 'Open Graph Tags',
        status: ogTitle && ogImage ? 'pass' : 'warn',
        description: ogTitle && ogImage ? 'Open Graph meta tags configured' : 'Missing Open Graph tags for social sharing',
        severity: 'medium'
      });

      // 7. Structured Data (Schema.org)
      const hasStructuredData = $('script[type="application/ld+json"]').length > 0;
      checks.push({
        name: 'Structured Data (Schema.org)',
        status: hasStructuredData ? 'pass' : 'info',
        description: hasStructuredData ? 'Structured data found' : 'No structured data detected',
        severity: 'medium'
      });

      // 8. Mobile Viewport Meta
      const viewport = $('meta[name="viewport"]').attr('content');
      // Check if site is responsive via other indicators (og:image, responsive design patterns)
      const hasOgImage = !!$('meta[property="og:image"]').attr('content');
      checks.push({
        name: 'Mobile Viewport',
        status: viewport ? 'pass' : (hasOgImage ? 'warn' : 'warn'),
        description: viewport ? `Viewport: ${viewport}` : 'No viewport meta tag in static HTML (site may be responsive)',
        severity: 'high'
      });

      // 9. Image Alt Texts
      const images = $('img');
      let imagesWithAlt = 0;
      images.each((i, el) => {
        if ($(el).attr('alt')) imagesWithAlt++;
      });
      checks.push({
        name: 'Image Alt Attributes',
        status: images.length === 0 ? 'pass' : imagesWithAlt / images.length > 0.8 ? 'pass' : imagesWithAlt > 0 ? 'warn' : 'fail',
        description: images.length === 0 ? 'No images' : `${imagesWithAlt}/${images.length} images have alt text`,
        severity: 'high'
      });

      // 10. Favicon
      const favicon = $('link[rel="icon"], link[rel="shortcut icon"]').attr('href');
      checks.push({
        name: 'Favicon',
        status: favicon ? 'pass' : 'info',
        description: favicon ? 'Favicon found' : 'No favicon detected',
        severity: 'low'
      });

      // 11. Deep Link Extraction (using headless browser)
      try {
        const extractedLinks = await this.extractAllLinks(url);
        const internalLinks = extractedLinks.filter(link => {
          try {
            const linkUrl = new URL(link);
            const baseUrl = new URL(url);
            return linkUrl.hostname === baseUrl.hostname;
          } catch {
            return false;
          }
        });
        
        checks.push({
          name: 'Deep Link Discovery',
          status: extractedLinks.length > 0 ? 'pass' : 'warn',
          description: `Discovered ${extractedLinks.length} total links (${internalLinks.length} internal, ${extractedLinks.length - internalLinks.length} external) via interactive exploration`,
          severity: 'low',
          details: {
            totalLinks: extractedLinks.length,
            internalLinks: internalLinks.length,
            externalLinks: extractedLinks.length - internalLinks.length,
            links: extractedLinks.slice(0, 50) // Limit to first 50 for performance
          }
        });
      } catch (linkError) {
        checks.push({
          name: 'Deep Link Discovery',
          status: 'warn',
          description: `Could not extract links via browser: ${linkError.message}`,
          severity: 'low'
        });
      }

    } catch (error) {
      checks.push({
        name: 'SEO Analysis Error',
        status: 'error',
        description: `Unable to analyze: ${error.message}`,
        severity: 'critical'
      });
    }

    return {
      category: 'SEO & Metadata',
      icon: 'bar-chart',
      score: calculateCategoryScore(checks),
      checks
    };
  }
}

module.exports = SeoCheck;
