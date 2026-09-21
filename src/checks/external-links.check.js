/**
 * External Links Check
 * Discovers external links from multiple sources on the page (using
 * Puppeteer for dynamic content when available) and scores each one.
 *
 * Link sources are tracked and reported separately:
 *  - "page links": <a href>, onclick handlers, data-* attributes, form
 *    actions, iframe src, and Puppeteer-discovered dynamic links/navigations
 *    - these are things a real browser will actually navigate to.
 *  - "script-extracted links": URLs pulled out of inline <script> bodies via
 *    text/regex scanning (including base64/atob-obfuscated redirects). This
 *    is inherently a best-effort text scrape of JS source, not a structural
 *    parse, so it's kept in its own labeled bucket rather than mixed into the
 *    "real" link count/density/score - it can surface useful redirect
 *    obfuscation, but it can also pick up non-navigable internal
 *    hostnames or JS string fragments, so it's shown for review, not
 *    scored the same way.
 *
 * Every candidate URL (from either bucket) is validated before being kept:
 * common JS string escapes (\uXXXX, \/) are decoded, unresolved template
 * placeholders ({...}) and raw whitespace are rejected, and the resulting
 * hostname must have a real registrable domain or be a valid IP (Public
 * Suffix List, via tldts) - this is what prevents malformed fragments like
 * "kiosco.www.walmart.com.mx,https//..." or "{search_term_string}" from
 * ending up in the results.
 */

const axios = require('axios');
const cheerio = require('cheerio');
const { calculateCategoryScore } = require('../utils/score-calculator.util');
const { isSameSite, isValidHostname } = require('../utils/domain.util');
const { attachEvidence, buildLinkEvidence } = require('../utils/evidence.util');

/** Decodes the handful of JS string escapes most likely to appear in
 * minified/JSON-embedded source when a URL gets pulled out via text
 * scanning rather than a real JS/JSON parser. */
function decodeJsEscapes(str) {
  if (!str) return str;
  try {
    return str
      .replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
      .replace(/\\\//g, '/');
  } catch (e) {
    return str;
  }
}

function looksLikeTemplatePlaceholder(str) {
  return /[{}]/.test(str) || /%7B|%7D/i.test(str);
}

/**
 * Validates and normalizes a URL candidate. Returns the absolute href on
 * success, or null if it isn't a real, well-formed http(s) URL.
 *
 * @param {boolean} requireAbsolute - When true, the candidate MUST already be
 *   a complete absolute URL (its own scheme+host) - it is NOT resolved
 *   against `baseUrl` as a relative path. This matters for text scraped out
 *   of <script> bodies: those candidates are supposed to already be complete
 *   URLs (e.g. matched by a `https?://...` pattern), so if decoding leaves a
 *   malformed/truncated fragment without its own scheme, silently resolving
 *   it as "relative to the page" would produce a nonsense URL like
 *   `https://walmart.com/kiosco.www.walmart.com.mx,https//broken` instead of
 *   correctly rejecting it. Real page-link sources (<a href>, form action,
 *   etc) legitimately use relative URLs, so they pass requireAbsolute=false.
 */
function validateUrlCandidate(candidate, baseUrl, requireAbsolute = false) {
  if (!candidate || typeof candidate !== 'string') return null;
  const decoded = decodeJsEscapes(candidate.trim());
  if (!decoded) return null;
  if (looksLikeTemplatePlaceholder(decoded)) return null;
  if (/\s/.test(decoded)) return null; // real URLs don't contain raw whitespace
  if (requireAbsolute && !/^https?:\/\//i.test(decoded)) return null;
  try {
    const absolute = new URL(decoded, baseUrl);
    if (absolute.protocol !== 'http:' && absolute.protocol !== 'https:') return null;
    if (!isValidHostname(absolute.hostname)) return null;
    return absolute.href;
  } catch (e) {
    return null;
  }
}

class ExternalLinksCheck {
  async analyze(url) {
    const checks = [];
    const hostname = new URL(url).hostname;

    // { url, sourceType, sourceDetail }
    const pageLinkEntries = [];
    const scriptLinkEntries = [];

    const addPageLink = (candidate, sourceType, sourceDetail) => {
      const valid = validateUrlCandidate(candidate, url);
      if (valid) pageLinkEntries.push({ url: valid, sourceType, sourceDetail: sourceDetail || null });
    };
    const addScriptLink = (candidate, sourceType, sourceDetail) => {
      // requireAbsolute=true: script-scraped candidates must already be a complete
      // URL on their own - see validateUrlCandidate's doc comment for why.
      const valid = validateUrlCandidate(candidate, url, true);
      if (valid) scriptLinkEntries.push({ url: valid, sourceType, sourceDetail: sourceDetail || null });
    };

    try {
      // Try to use Puppeteer for dynamic link detection if available
      let dynamicResult = { links: [], redirectLinks: [] };
      try {
        const puppeteer = require('puppeteer');
        dynamicResult = await this.extractDynamicLinks(url, puppeteer);
      } catch (puppeteerError) {
        // Puppeteer not available, continue with static analysis only
      }
      (dynamicResult.links || []).forEach(u => addPageLink(u, 'dynamic-browser'));
      (dynamicResult.redirectLinks || []).forEach(u => addPageLink(u, 'dynamic-redirect', 'Observed navigation/redirect during headless browsing'));

      const response = await axios.get(url, {
        timeout: 15000,
        validateStatus: () => true,
        maxRedirects: 3
      });

      const $ = cheerio.load(response.data);

      // Extract all <a> tag links
      $('a[href]').each((i, el) => {
        const href = $(el).attr('href');
        if (href && !href.startsWith('javascript:') && !href.startsWith('mailto:') && !href.startsWith('#')) {
          addPageLink(href, 'a-tag', $(el).text().trim().slice(0, 60) || null);
        }
      });

      // Extract links from button onclick attributes
      $('button[onclick], input[onclick], div[onclick], span[onclick], a[onclick]').each((i, el) => {
        const onclick = $(el).attr('onclick');
        if (!onclick) return;
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
            addPageLink(match[1], 'onclick', 'onclick handler');
          }
        }
      });

      // Extract links from inline JavaScript in script tags - kept in the separate
      // scriptLinkEntries bucket (see file header comment).
      const scripts = $('script').toArray();
      for (const script of scripts) {
        const scriptContent = $(script).html() || '';

        const urlPatterns = [
          /window\.open\s*\(\s*['"]([^'"]+)['"]/gi,
          /location\.href\s*=\s*['"]([^'"]+)['"]/gi,
          /location\.assign\s*\(\s*['"]([^'"]+)['"]/gi,
          /window\.location\s*=\s*['"]([^'"]+)['"]/gi,
          /window\.location\.replace\s*\(\s*['"]([^'"]+)['"]/gi
        ];
        for (const pattern of urlPatterns) {
          let match;
          while ((match = pattern.exec(scriptContent)) !== null) {
            addScriptLink(match[1], 'script-body', 'location/window.open assignment in <script>');
          }
        }

        // Bare quoted absolute URLs anywhere in the script text
        const quotedUrlPattern = /['"](https?:\/\/[^'"]+)['"]/g;
        let quotedMatch;
        while ((quotedMatch = quotedUrlPattern.exec(scriptContent)) !== null) {
          addScriptLink(quotedMatch[1], 'script-body', 'quoted URL literal in <script>');
        }

        // Base64-encoded strings that decode to a URL
        const base64Regex = /['"]([A-Za-z0-9+/]{40,}={0,2})['"]/g;
        let b64Match;
        while ((b64Match = base64Regex.exec(scriptContent)) !== null) {
          try {
            const decoded = Buffer.from(b64Match[1], 'base64').toString('utf8');
            const decodedUrls = decoded.match(/https?:\/\/[^'"\s]+/g) || [];
            decodedUrls.forEach(u => addScriptLink(u, 'script-base64', 'base64-decoded string in <script>'));
          } catch (e) {
            // ignore malformed base64
          }
        }

        // location assignments using atob() wrappers, e.g. location.href = atob("...")
        const atobPattern = /location\.(?:href|assign|replace)\s*=\s*atob\(['"]([A-Za-z0-9+/]{10,}={0,2})['"]\)/gi;
        let atobMatch;
        while ((atobMatch = atobPattern.exec(scriptContent)) !== null) {
          try {
            const decoded = Buffer.from(atobMatch[1], 'base64').toString('utf8').trim();
            addScriptLink(decoded, 'script-atob', 'atob()-decoded location assignment in <script>');
          } catch (e) {
            // ignore malformed base64
          }
        }
      }

      // Extract popup/modal links from data attributes
      $('[data-url], [data-href], [data-link], [data-popup-url]').each((i, el) => {
        const dataAttrs = ['data-url', 'data-href', 'data-link', 'data-popup-url'];
        for (const attr of dataAttrs) {
          const dataUrl = $(el).attr(attr);
          if (dataUrl) addPageLink(dataUrl, 'data-attribute', attr);
        }
      });

      // Extract form action URLs
      $('form[action]').each((i, el) => {
        const action = $(el).attr('action');
        if (action && !action.startsWith('javascript:') && !action.startsWith('#')) {
          addPageLink(action, 'form-action');
        }
      });

      // Extract iframe sources
      $('iframe[src]').each((i, el) => {
        const src = $(el).attr('src');
        if (src && !src.startsWith('javascript:') && !src.startsWith('about:')) {
          addPageLink(src, 'iframe-src');
        }
      });

      // Filter to external (different registrable domain), dedupe by URL
      const dedupe = (entries) => {
        const seen = new Map();
        for (const entry of entries) {
          try {
            const linkHostname = new URL(entry.url).hostname;
            if (isSameSite(linkHostname, hostname)) continue; // first-party, not "external"
            if (!seen.has(entry.url)) seen.set(entry.url, entry);
          } catch (e) { /* already validated, shouldn't happen */ }
        }
        return [...seen.values()];
      };

      const externalPageLinks = dedupe(pageLinkEntries);
      const externalScriptLinks = dedupe(scriptLinkEntries).filter(e => !externalPageLinks.some(p => p.url === e.url));

      const domains = externalPageLinks.map(e => {
        try { return new URL(e.url).hostname; } catch { return null; }
      }).filter(Boolean);
      const uniqueDomains = [...new Set(domains)];

      // Score each external "page link" (limit to first 50 to avoid timeout).
      // Script-extracted links are shown for review but not individually scored -
      // they're a best-effort text scrape, not confirmed navigable links.
      const SCORE_LIMIT = 50;
      const linksToScore = externalPageLinks.slice(0, SCORE_LIMIT);
      const scoredLinks = await Promise.all(
        linksToScore.map(async (entry) => {
          const score = await this.scoreExternalLink(entry.url);
          return { url: entry.url, sourceType: entry.sourceType, score: score.score, status: score.status, issues: score.issues };
        })
      );

      const remainingLinks = externalPageLinks.slice(SCORE_LIMIT).map(entry => ({
        url: entry.url,
        sourceType: entry.sourceType,
        score: null,
        status: 'Not Scored',
        issues: [],
        notScoredReason: `Evaluation limit reached - only the first ${SCORE_LIMIT} unique external links are individually probed for performance.`
      }));

      // Link count check with clear metrics
      checks.push({
        id: 'external-links-detected',
        name: 'External Links Detected',
        status: externalPageLinks.length === 0 ? 'info' : 'pass',
        description: externalPageLinks.length === 0
          ? 'No external page links found'
          : `Found ${externalPageLinks.length} unique external page link(s) pointing to ${uniqueDomains.length} unique domain(s)${externalScriptLinks.length > 0 ? ` (+ ${externalScriptLinks.length} additional URL-like reference(s) found inside <script> bodies - see "Script-Extracted URL References" below)` : ''}`,
        severity: 'low',
        explanation: 'External links connect your site to other resources on the web. "Page links" come from <a> tags, onclick handlers, data-* attributes, form actions, iframe src, and (if available) headless-browser navigation - things a real browser will actually follow.',
        method: 'Collects candidate URLs from every source listed above, decodes common JS string escapes, rejects unresolved template placeholders and malformed fragments, validates each via URL parsing and a Public-Suffix-List hostname check, then deduplicates and filters to links whose registrable domain differs from the page\'s own.',
        risk: 'N/A - informational.',
        fix: 'No action needed.',
        confidence: 'high',
        details: {
          uniqueUrls: externalPageLinks.length,
          uniqueDomains: uniqueDomains.length,
          scriptExtractedCount: externalScriptLinks.length
        }
      });
      attachEvidence(checks[checks.length - 1], externalPageLinks.slice(0, 20).map(e => buildLinkEvidence(e)));

      if (externalScriptLinks.length > 0) {
        checks.push({
          id: 'script-extracted-url-references',
          name: 'Script-Extracted URL References',
          status: 'info',
          description: `${externalScriptLinks.length} URL-like reference(s) found inside <script> bodies (including base64/atob-decoded strings) - shown separately from real page links`,
          severity: 'low',
          explanation: 'These are pulled out of inline JavaScript by text/pattern scanning, not a full JS parse, so they can include non-navigable internal hostnames or incidental string literals alongside genuine (possibly obfuscated) redirects. Review before treating any of these as confirmed links.',
          method: 'Scans <script> bodies for location/window.open assignments, quoted absolute URLs, base64-encoded strings that decode to a URL, and atob()-wrapped location assignments. Every candidate is still validated (escape-decoded, checked for template placeholders, parsed, and hostname-checked) before being kept.',
          risk: 'Obfuscated (base64/atob) redirect targets in scripts are sometimes used to hide a malicious destination from simple text scanning of the page.',
          fix: 'Review the entries below, particularly any script-base64 / script-atob sourced ones.',
          confidence: 'low',
          confidenceNote: 'This is a best-effort text scrape of JavaScript source, not a structural parse - treat individual entries as leads to review, not confirmed findings.'
        });
        attachEvidence(checks[checks.length - 1], externalScriptLinks.map(e => buildLinkEvidence(e)));
      }

      if ((dynamicResult.redirectLinks || []).length > 0) {
        checks.push({
          id: 'redirect-triggered-external-destinations',
          name: 'Redirect Triggered External Destinations',
          status: 'warn',
          description: `Detected ${dynamicResult.redirectLinks.length} external navigation(s) initiated via scripted redirects / window.location changes`,
          severity: 'medium',
          explanation: 'These links redirect users programmatically rather than via standard anchor tags.',
          method: 'A headless browser instruments window.open, location.assign/replace/href, and history.pushState/replaceState, then records any external navigation triggered while loading the page and interacting with its clickable elements.',
          risk: 'Programmatic redirects can send users to an unexpected destination without an inspectable <a href> to review beforehand.',
          fix: 'Review the destinations below; prefer standard <a href> links where possible so users (and scanners) can see the destination in advance.',
          confidence: 'high'
        });
        attachEvidence(checks[checks.length - 1], (dynamicResult.redirectLinks || []).map(u => buildLinkEvidence({ url: u, sourceType: 'dynamic-redirect' })));
      }

      // External domains check with explanation
      checks.push({
        id: 'external-domains',
        name: 'External Domains',
        status: 'info',
        description: `Page links point to ${uniqueDomains.length} unique external domain${uniqueDomains.length !== 1 ? 's' : ''}`,
        severity: 'low',
        explanation: 'The number of different external websites your page links to (page links only, not script-extracted references).',
        method: 'Counts unique registrable domains among externalPageLinks.',
        risk: 'N/A - informational.',
        fix: 'No action needed.',
        confidence: 'high',
        details: {
          domains: uniqueDomains.slice(0, 20)
        }
      });

      // Calculate link density using the SAME formula as link-analysis.check.js:
      // unique external links / count of `p, article, section` elements. Based on
      // page links only (not script-extracted references), for the same reason
      // those aren't included in the main external link count above.
      const contentElements = $('p, article, section').length || 1;
      const linkDensityRatio = externalPageLinks.length / contentElements;

      let densityStatus = 'pass';
      let densityDesc = `${externalPageLinks.length} unique external page link(s) / ${contentElements} content blocks = ${linkDensityRatio.toFixed(2)} ratio`;

      if (linkDensityRatio > 2) {
        densityStatus = 'warn';
        densityDesc = `High link density: ${linkDensityRatio.toFixed(2)} links per content block - may indicate link spam`;
      } else if (linkDensityRatio > 1) {
        densityStatus = 'info';
        densityDesc = `Moderate link density: ${linkDensityRatio.toFixed(2)} links per content block`;
      }

      checks.push({
        id: 'external-link-density',
        name: 'External Link Density',
        status: densityStatus,
        description: densityDesc,
        severity: 'medium',
        explanation: 'This uses the same formula as the "External Link Density" check under Link Analysis (unique external links / content blocks), but this check\'s link count includes onclick/data-attribute/form/iframe/dynamic-browser sources in addition to <a> tags, so the two numbers can still differ - see each check\'s "method" for exactly what it counted.',
        method: 'unique_external_page_links / count(p, article, section elements).',
        risk: 'A high ratio of external links to content may indicate link-spam or a low-quality/affiliate-stuffed page.',
        fix: densityStatus === 'pass' ? 'No action needed.' : 'Review whether all external links are necessary and relevant to the page content.',
        confidence: 'high',
        details: {
          uniqueExternalUrls: externalPageLinks.length,
          contentElements: contentElements,
          ratio: linkDensityRatio.toFixed(2),
          formula: 'unique_external_page_links / content_elements',
          scope: 'a-tag, onclick, data-attribute, form-action, iframe-src, and dynamic-browser sources (not script-extracted references)'
        }
      });

      // Security check on scored links
      const lowScoreLinks = scoredLinks.filter(l => l.score !== null && l.score < 50);
      if (lowScoreLinks.length > 0) {
        checks.push({
          id: 'potentially-unsafe-external-links',
          name: 'Potentially Unsafe External Links',
          status: lowScoreLinks.length > 3 ? 'fail' : 'warn',
          description: `${lowScoreLinks.length} external link${lowScoreLinks.length !== 1 ? 's have' : ' has'} security concerns`,
          severity: 'high',
          explanation: 'These links may point to suspicious domains, use unsafe protocols, or have other security issues.',
          method: 'Each external page link is scored from a 100-point baseline, deducting for suspicious TLDs, known URL shorteners, direct-IP URLs, excessive subdomains, broken/unreachable destinations, and missing HTTPS. Links scoring below 50 are flagged here.',
          risk: 'Low-scoring links may lead to phishing, malware, or otherwise unreliable destinations.',
          fix: 'Review the flagged links below and remove or replace any that are unnecessary or untrustworthy.',
          confidence: 'medium'
        });
        attachEvidence(checks[checks.length - 1], lowScoreLinks.map(l => buildLinkEvidence({ url: l.url, sourceType: l.sourceType, sourceDetail: `score ${l.score}/100 (${l.issues.join(', ')})` })));
      }

      const allScoredLinks = [...scoredLinks, ...remainingLinks];
      const score = calculateCategoryScore(checks);

      return {
        category: 'External Links',
        icon: 'external-link',
        score: score,
        status: score === null ? 'unavailable' : 'available',
        checks,
        externalLinks: externalPageLinks.map(e => e.url),
        externalDomains: uniqueDomains,
        scoredLinks: allScoredLinks,
        scriptExtractedLinks: externalScriptLinks.map(e => e.url),
        metrics: {
          totalLinksFound: pageLinkEntries.length + scriptLinkEntries.length,
          uniqueUrls: externalPageLinks.length,
          uniqueDomains: uniqueDomains.length,
          linkDensity: linkDensityRatio.toFixed(2)
        }
      };
    } catch (error) {
      checks.push({
        id: 'external-links-analysis-error',
        name: 'External Links Analysis Error',
        status: 'error',
        description: 'External links analysis unavailable',
        severity: 'medium',
        explanation: `An error occurred: ${error.message}`
      });

      const score = calculateCategoryScore(checks);

      return {
        category: 'External Links',
        icon: 'external-link',
        score: score,
        status: score === null ? 'unavailable' : 'available',
        checks,
        externalLinks: [],
        externalDomains: [],
        scoredLinks: []
      };
    }
  }

  async scoreExternalLink(linkUrl) {
    let score = 100;
    const issues = [];
    let status = 'Safe';

    try {
      // Check URL patterns for suspicious characteristics
      const urlLower = linkUrl.toLowerCase();

      // Suspicious TLDs
      const suspiciousTlds = ['.click', '.loan', '.win', '.download', '.bid', '.racing', '.top', '.stream'];
      if (suspiciousTlds.some(tld => urlLower.includes(tld))) {
        score -= 30;
        issues.push('Suspicious TLD');
        status = 'Warning';
      }

      // Redirect/shortener services
      const redirectServices = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'adf.ly', 't.co'];
      if (redirectServices.some(service => urlLower.includes(service))) {
        score -= 20;
        issues.push('URL Shortener');
        status = 'Warning';
      }

      // IP address in URL
      if (/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(linkUrl)) {
        score -= 25;
        issues.push('Direct IP Address');
        status = 'Warning';
      }

      // Long subdomain (common in phishing)
      try {
        const hostname = new URL(linkUrl).hostname;
        const parts = hostname.split('.');
        if (parts.length > 4) {
          score -= 15;
          issues.push('Multiple Subdomains');
        }
      } catch (e) {}

      // Try to check if URL is accessible
      try {
        const response = await axios.head(linkUrl, {
          timeout: 5000,
          maxRedirects: 0,
          validateStatus: () => true
        });

        if (response.status === 404) {
          score -= 40;
          issues.push('Link Not Found (404)');
          status = 'Broken';
        } else if (response.status >= 500) {
          score -= 20;
          issues.push('Server Error');
          status = 'Warning';
        } else if (response.status >= 300 && response.status < 400) {
          score -= 10;
          issues.push('Redirects');
        }

        // Check for HTTPS
        if (!linkUrl.startsWith('https://')) {
          score -= 15;
          issues.push('No HTTPS');
          status = 'Warning';
        }
      } catch (error) {
        // Connection issues
        score -= 30;
        issues.push('Cannot Connect');
        status = 'Unreachable';
      }

      // Determine final status
      if (score < 40) {
        status = 'Unsafe';
      } else if (score < 70) {
        status = 'Warning';
      } else {
        status = 'Safe';
      }

      return {
        score: Math.max(0, Math.min(100, score)),
        status,
        issues
      };
    } catch (error) {
      return {
        score: 50,
        status: 'Unknown',
        issues: ['Analysis Error']
      };
    }
  }

  /**
   * Discovers links dynamically via a headless browser: initial DOM links,
   * links after interacting with clickable elements, and any navigation
   * triggered programmatically (window.open, location changes, redirects).
   * Returns RAW absolute URLs without same-site filtering - the caller
   * classifies/validates them centrally alongside every other source.
   */
  async extractDynamicLinks(url, puppeteer) {
    const dynamicLinks = [];
    const redirectLinks = new Set();
    let browser = null;

    try {
      browser = await puppeteer.launch({
        headless: true,
        args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
      });

      const page = await browser.newPage();

      // Instrument redirect/navigation APIs before any script runs
      await page.evaluateOnNewDocument(() => {
        window.__redirectLog = [];
        function log(u) {
          try { if (u && (u.startsWith('http://') || u.startsWith('https://'))) window.__redirectLog.push(u); } catch(e) {}
        }
        const origOpen = window.open;
        window.open = function(u) { log(u); return origOpen.apply(this, arguments); };
        ['assign','replace'].forEach(fn => {
          const orig = window.location[fn];
          window.location[fn] = function(u) { log(u); return orig.call(window.location, u); };
        });
        const hrefDesc = Object.getOwnPropertyDescriptor(Location.prototype, 'href');
        if (hrefDesc && hrefDesc.set) {
          Object.defineProperty(window.location, 'href', {
            set(u){ log(u); return hrefDesc.set.call(window.location, u); },
            get(){ return hrefDesc.get.call(window.location); }
          });
        }
        const origPush = history.pushState;
        history.pushState = function(state, title, url){ if (url) log(url.toString()); return origPush.apply(history, arguments); };
        const origReplace = history.replaceState;
        history.replaceState = function(state, title, url){ if (url) log(url.toString()); return origReplace.apply(history, arguments); };
      });

      // Track all network requests
      const requestedUrls = new Set();
      page.on('request', request => {
        const requestUrl = request.url();
        if (requestUrl.startsWith('http://') || requestUrl.startsWith('https://')) {
          requestedUrls.add(requestUrl);
        }
      });

      // Capture navigation events (frame navigations)
      page.on('framenavigated', frame => {
        const navUrl = frame.url();
        if (navUrl.startsWith('http://') || navUrl.startsWith('https://')) {
          redirectLinks.add(navUrl);
        }
      });

      // Capture explicit redirect response Location headers
      page.on('response', response => {
        try {
          const status = response.status();
          if (status >= 300 && status < 400) {
            const headers = response.headers();
            const loc = headers['location'];
            if (loc) {
              try {
                const absolute = new URL(loc, response.url()).href;
                redirectLinks.add(absolute);
              } catch (e) { /* ignore malformed Location header */ }
            }
          }
        } catch(e) {}
      });

      await page.goto(url, {
        waitUntil: 'networkidle2',
        timeout: 30000
      });

      // Extract all links from the page after JavaScript execution
      const extractedLinks = await page.evaluate(() => {
        const links = [];
        document.querySelectorAll('a[href]').forEach(el => { if (el.href) links.push(el.href); });
        document.querySelectorAll('[onclick]').forEach(el => {
          const onclick = el.getAttribute('onclick');
          const urlMatches = onclick && onclick.match(/['"]https?:\/\/[^'"]+['"]/g);
          if (urlMatches) urlMatches.forEach(m => links.push(m.replace(/['"]/g, '')));
        });
        document.querySelectorAll('form[action]').forEach(el => { if (el.action) links.push(el.action); });
        document.querySelectorAll('iframe[src]').forEach(el => { if (el.src) links.push(el.src); });
        return links;
      });
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
            if (index < 50) {
              try {
                ['pointerover','mouseover','mouseenter','focus'].forEach(evt => {
                  try { el.dispatchEvent(new Event(evt, { bubbles: true })); } catch(e) {}
                });
                ['pointerdown','mousedown','click','mouseup','pointerup'].forEach(evt => {
                  try { el.dispatchEvent(new Event(evt, { bubbles: true })); } catch(e) {}
                });
                el.click();
              } catch (e) {}
            }
          });
        });
      });

      await page.waitForTimeout(5000);

      const afterClickLinks = await page.evaluate(() => {
        const links = [];
        document.querySelectorAll('a[href]').forEach(el => { if (el.href) links.push(el.href); });
        return links;
      });
      dynamicLinks.push(...afterClickLinks);

      try {
        const apiRedirects = await page.evaluate(() => Array.isArray(window.__redirectLog) ? window.__redirectLog : []);
        apiRedirects.forEach(u => redirectLinks.add(u));
      } catch(e) {}

      dynamicLinks.push(...Array.from(requestedUrls));

      await browser.close();

      return {
        links: [...new Set(dynamicLinks)],
        redirectLinks: [...redirectLinks]
      };
    } catch (error) {
      if (browser) {
        await browser.close();
      }
      return { links: [...new Set(dynamicLinks)], redirectLinks: [...redirectLinks] };
    }
  }
}

module.exports = ExternalLinksCheck;
