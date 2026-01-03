/**
 * Accessibility Checks (WCAG 2.1)
 */

const axios = require('axios');
const cheerio = require('cheerio');
const { calculateCategoryScore } = require('../utils/score-calculator.util');

class AccessibilityCheck {
  async analyze(url) {
    const checks = [];

    try {
      const response = await axios.get(url, { 
        timeout: 15000,
        validateStatus: () => true
      });

      const $ = cheerio.load(response.data);

      // 1. Language Attribute
      const htmlLang = $('html').attr('lang');
      checks.push({
        name: 'Page Language Declaration',
        status: htmlLang ? 'pass' : 'warn',
        description: htmlLang ? `Language set to: ${htmlLang}` : 'Language attribute not specified',
        severity: 'medium'
      });

      // 2. Image Alt Texts
      const images = $('img');
      let imagesWithAlt = 0;
      images.each((i, el) => {
        if ($(el).attr('alt')) imagesWithAlt++;
      });
      checks.push({
        name: 'Image Alt Text',
        status: images.length === 0 ? 'pass' : imagesWithAlt === images.length ? 'pass' : 'warn',
        description: images.length === 0 ? 'No images' : `${imagesWithAlt}/${images.length} images have alt text`,
        severity: 'medium'
      });

      // 3. Form Labels
      const formInputs = $('input[type!="hidden"]');
      let inputsWithLabel = 0;
      formInputs.each((i, el) => {
        const id = $(el).attr('id');
        const label = $(`label[for="${id}"]`).length > 0;
        if (label) inputsWithLabel++;
      });
      checks.push({
        name: 'Form Input Labels',
        status: formInputs.length === 0 ? 'pass' : inputsWithLabel === formInputs.length ? 'pass' : 'warn',
        description: formInputs.length === 0 ? 'No form inputs' : `${inputsWithLabel}/${formInputs.length} form inputs have labels`,
        severity: 'high'
      });

      // 4. Heading Hierarchy
      const headings = $('h1, h2, h3, h4, h5, h6');
      let validHierarchy = true;
      let lastLevel = 0;
      headings.each((i, el) => {
        const level = parseInt($(el).prop('tagName')[1]);
        if (level > lastLevel + 1) validHierarchy = false;
        lastLevel = level;
      });
      checks.push({
        name: 'Heading Hierarchy (H1-H6)',
        status: headings.length > 0 && validHierarchy ? 'pass' : headings.length > 0 ? 'warn' : 'info',
        description: headings.length > 0 ? `${headings.length} headings found (${validHierarchy ? 'proper hierarchy' : 'hierarchy issues'})` : 'No headings found',
        severity: 'high'
      });

      // 5. Color Contrast (basic check)
      checks.push({
        name: 'Color Contrast Ratio',
        status: 'info',
        description: 'Advanced contrast analysis requires manual review',
        severity: 'high'
      });

      // 6. Focus Visible
      checks.push({
        name: 'Keyboard Navigation',
        status: 'info',
        description: 'Keyboard navigation requires manual testing',
        severity: 'high'
      });

      // 7. ARIA Labels
      const elementsWithAria = $('[aria-label], [aria-labelledby], [role]').length;
      checks.push({
        name: 'ARIA Labels & Roles',
        status: elementsWithAria > 0 ? 'pass' : 'info',
        description: elementsWithAria > 0 ? `${elementsWithAria} elements with ARIA attributes` : 'No ARIA attributes detected',
        severity: 'medium'
      });

      // 8. Skip Links
      const skipLink = $('a[href="#main"], a[href="#content"]').length > 0;
      checks.push({
        name: 'Skip to Main Content Link',
        status: skipLink ? 'pass' : 'warn',
        description: skipLink ? 'Skip link found' : 'No skip link for keyboard users',
        severity: 'medium'
      });

      // 9. Link Text Quality
      const links = $('a');
      let poorLinkText = 0;
      const poorLinkWords = ['click here', 'read more', 'more', 'link', 'here'];
      links.each((i, el) => {
        const text = $(el).text().toLowerCase().trim();
        if (poorLinkWords.includes(text)) poorLinkText++;
      });
      checks.push({
        name: 'Link Text Quality',
        status: links.length === 0 ? 'pass' : poorLinkText === 0 ? 'pass' : poorLinkText / links.length < 0.2 ? 'warn' : 'fail',
        description: links.length === 0 ? 'No links' : `${poorLinkText} out of ${links.length} links have generic text`,
        severity: 'medium'
      });

      // 10. Text Readability
      const bodyText = $('body').text();
      const avgLineLength = bodyText.length / (bodyText.match(/\n/g) || []).length || bodyText.length;
      checks.push({
        name: 'Text Readability',
        status: avgLineLength < 120 ? 'pass' : 'warn',
        description: 'Text readability requires manual review',
        severity: 'medium'
      });

    } catch (error) {
      checks.push({
        name: 'Accessibility Analysis Error',
        status: 'error',
        description: `Unable to analyze: ${error.message}`,
        severity: 'critical'
      });
    }

    return {
      category: 'Accessibility (WCAG 2.1)',
      icon: 'accessibility',
      score: calculateCategoryScore(checks),
      checks
    };
  }
}

module.exports = AccessibilityCheck;
