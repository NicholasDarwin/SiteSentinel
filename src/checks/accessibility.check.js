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
        severity: 'medium',
        explanation: 'The lang attribute helps screen readers pronounce content correctly.'
      });

      // 2. Image Alt Texts
      const images = $('img');
      let imagesWithAlt = 0;
      const imageDetails = [];
      images.each((i, el) => {
        const alt = $(el).attr('alt');
        const src = $(el).attr('src') || 'unknown';
        if (alt !== undefined) {
          imagesWithAlt++;
          imageDetails.push({ src: src.substring(0, 50), method: 'alt attribute' });
        }
      });
      checks.push({
        name: 'Image Alt Text',
        status: images.length === 0 ? 'pass' : imagesWithAlt === images.length ? 'pass' : 'warn',
        description: images.length === 0 ? 'No images found' : `${imagesWithAlt}/${images.length} images have alt text`,
        severity: 'medium',
        explanation: 'Alt text describes images for screen reader users and when images fail to load.'
      });

      // 3. Form Labels - Enhanced with ARIA support (WCAG 2.1 compliant)
      const formInputs = $('input, select, textarea').not('[type="hidden"], [type="submit"], [type="button"], [type="reset"], [type="image"]');
      let inputsWithLabel = 0;
      const labelingDetails = [];
      
      formInputs.each((i, el) => {
        const $el = $(el);
        const id = $el.attr('id');
        const name = $el.attr('name') || $el.attr('type') || 'input';
        let labelMethod = null;
        
        // Check for various WCAG-compliant labeling methods:
        
        // 1. Explicit label via for attribute
        if (id && $(`label[for="${id}"]`).length > 0) {
          labelMethod = 'explicit <label for>';
        }
        
        // 2. aria-label attribute
        else if ($el.attr('aria-label')) {
          labelMethod = 'aria-label';
        }
        
        // 3. aria-labelledby attribute
        else if ($el.attr('aria-labelledby')) {
          const labelledById = $el.attr('aria-labelledby');
          const referencedElement = $(`#${labelledById}`);
          if (referencedElement.length > 0) {
            labelMethod = 'aria-labelledby';
          }
        }
        
        // 4. Implicit label (input wrapped in label)
        else if ($el.closest('label').length > 0 && $el.closest('label').text().trim()) {
          labelMethod = 'implicit label (wrapped)';
        }
        
        // 5. Title attribute (fallback, less accessible)
        else if ($el.attr('title')) {
          labelMethod = 'title attribute (fallback)';
        }
        
        // 6. Placeholder (not a proper label but indicates some context)
        else if ($el.attr('placeholder')) {
          labelMethod = 'placeholder only (not recommended)';
        }
        
        if (labelMethod) {
          inputsWithLabel++;
          labelingDetails.push({ field: name, method: labelMethod });
        } else {
          labelingDetails.push({ field: name, method: 'none' });
        }
      });
      
      const labelStatus = formInputs.length === 0 ? 'pass' : 
                          inputsWithLabel === formInputs.length ? 'pass' : 
                          inputsWithLabel / formInputs.length >= 0.8 ? 'warn' : 'fail';
      
      checks.push({
        name: 'Form Input Labels',
        status: labelStatus,
        description: formInputs.length === 0 
          ? 'No form inputs requiring labels' 
          : `${inputsWithLabel}/${formInputs.length} form inputs have accessible labels`,
        severity: 'high',
        explanation: 'Form inputs must have accessible labels (via <label>, aria-label, aria-labelledby, or implicit wrapping) for screen reader users.',
        details: labelingDetails.length > 0 ? { labelingMethods: labelingDetails.slice(0, 10) } : undefined
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
        severity: 'high',
        explanation: 'Proper heading hierarchy helps screen reader users navigate and understand page structure.'
      });

      // 5. Color Contrast (basic check)
      checks.push({
        name: 'Color Contrast Ratio',
        status: 'info',
        description: 'Advanced contrast analysis requires manual review',
        severity: 'high',
        explanation: 'WCAG requires minimum 4.5:1 contrast ratio for normal text and 3:1 for large text.'
      });

      // 6. Focus Visible
      checks.push({
        name: 'Keyboard Navigation',
        status: 'info',
        description: 'Keyboard navigation requires manual testing',
        severity: 'high',
        explanation: 'All interactive elements must be accessible via keyboard navigation.'
      });

      // 7. ARIA Labels & Roles
      const elementsWithAria = $('[aria-label], [aria-labelledby], [role]').length;
      checks.push({
        name: 'ARIA Labels & Roles',
        status: elementsWithAria > 0 ? 'pass' : 'info',
        description: elementsWithAria > 0 ? `${elementsWithAria} elements with ARIA attributes` : 'No ARIA attributes detected (may not be needed)',
        severity: 'medium',
        explanation: 'ARIA attributes provide additional context for assistive technologies.'
      });

      // 8. Skip Links
      const skipLink = $('a[href="#main"], a[href="#content"], a[href="#main-content"], a.skip-link, a.skip-to-content').length > 0;
      checks.push({
        name: 'Skip to Main Content Link',
        status: skipLink ? 'pass' : 'warn',
        description: skipLink ? 'Skip link found' : 'No skip link for keyboard users',
        severity: 'medium',
        explanation: 'Skip links allow keyboard users to bypass repetitive navigation.'
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
        severity: 'medium',
        explanation: 'Descriptive link text helps users understand where links lead without additional context.'
      });

      // 10. Landmark Regions
      const landmarks = $('[role="main"], [role="navigation"], [role="banner"], [role="contentinfo"], main, nav, header, footer').length;
      checks.push({
        name: 'Landmark Regions',
        status: landmarks > 0 ? 'pass' : 'warn',
        description: landmarks > 0 ? `${landmarks} landmark regions defined` : 'No landmark regions detected',
        severity: 'medium',
        explanation: 'Landmarks help screen reader users navigate between major sections of a page.'
      });

    } catch (error) {
      checks.push({
        name: 'Accessibility Analysis Error',
        status: 'error',
        description: `Unable to analyze: ${error.message}`,
        severity: 'critical',
        explanation: 'An error occurred during accessibility analysis.'
      });
    }

    const score = calculateCategoryScore(checks);
    
    return {
      category: 'Accessibility (WCAG 2.1)',
      icon: 'accessibility',
      score: score,
      status: score === null ? 'unavailable' : 'available',
      checks
    };
  }
}

module.exports = AccessibilityCheck;
