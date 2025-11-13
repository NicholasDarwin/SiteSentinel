/**
 * SEO Checks
 */

const axios = require('axios');
const cheerio = require('cheerio');
const { calculateCategoryScore } = require('../utils/score-calculator.util');

class SeoCheck {
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
      checks.push({
        name: 'Page Title',
        status: title && title.length > 0 ? (title.length >= 30 && title.length <= 60 ? 'pass' : 'warn') : 'fail',
        description: title ? `Title: "${title}" (${title.length} chars)` : 'No page title found',
        severity: 'high'
      });

      // 2. Meta Description
      const metaDescription = $('meta[name="description"]').attr('content');
      checks.push({
        name: 'Meta Description',
        status: metaDescription ? (metaDescription.length >= 120 && metaDescription.length <= 160 ? 'pass' : 'warn') : 'fail',
        description: metaDescription ? `Description: "${metaDescription}" (${metaDescription.length} chars)` : 'No meta description',
        severity: 'high'
      });

      // 3. Heading Structure (H1)
      const h1Count = $('h1').length;
      checks.push({
        name: 'H1 Tag Structure',
        status: h1Count === 1 ? 'pass' : h1Count > 0 ? 'warn' : 'fail',
        description: h1Count === 1 ? 'Single H1 tag found (optimal)' : `${h1Count} H1 tags found (should be 1)`,
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
      checks.push({
        name: 'Mobile Viewport',
        status: viewport ? 'pass' : 'fail',
        description: viewport ? `Viewport: ${viewport}` : 'No viewport meta tag - site not mobile optimized',
        severity: 'critical'
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
      icon: '📊',
      score: calculateCategoryScore(checks),
      checks
    };
  }
}

module.exports = SeoCheck;
