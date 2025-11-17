/**
 * Safety & Threats Checks
 */

const axios = require('axios');
const { calculateCategoryScore } = require('../utils/score-calculator.util');

class SafetyCheck {
  async analyze(url) {
    const checks = [];
    const hostname = new URL(url).hostname;

    try {
      const response = await axios.get(url, { 
        timeout: 15000,
        validateStatus: () => true
      });

      // 1. Malware / Phishing Indicators
      // If a Google Safe Browsing API key is provided via env, use it for reliable detection.
      // Otherwise fallback to a local keyword heuristic (prone to false positives).
      const body = response.data ? String(response.data).toLowerCase() : '';
      const urlLower = url.toLowerCase();
      let malwareDetected = false;
      let detectionDetails = null;

      const gsApiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
      if (gsApiKey) {
        try {
          const gsPayload = {
            client: {
              clientId: 'sitesentinel',
              clientVersion: '2.0.0'
            },
            threatInfo: {
              threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
              platformTypes: ['ANY_PLATFORM'],
              threatEntryTypes: ['URL'],
              threatEntries: [ { url } ]
            }
          };

          const gsUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${gsApiKey}`;
          const gsResp = await axios.post(gsUrl, gsPayload, { timeout: 10000 });
          if (gsResp.data && Object.keys(gsResp.data).length > 0) {
            malwareDetected = true;
            detectionDetails = `Google Safe Browsing match: ${JSON.stringify(gsResp.data)}`;
          }
        } catch (err) {
          // If the Safe Browsing call fails, fall back to keyword heuristics below
          detectionDetails = `Safe Browsing check failed: ${err.message}`;
        }
      }

      if (!malwareDetected) {
        // Check for phishing indicators in URL structure and domain reputation
        malwareDetected = this.detectPhishingIndicators(url, hostname);
        
        if (malwareDetected) {
          detectionDetails = `Phishing/scam indicators detected in domain structure or redirect patterns`;
        }
      }

      // Check for suspicious domain patterns and redirect behavior
      if (!malwareDetected) {
        const domainSuspiciousness = this.checkDomainReputation(hostname, url);
        if (domainSuspiciousness.isSuspicious) {
          malwareDetected = true;
          detectionDetails = domainSuspiciousness.reason;
        }
      }

      checks.push({
        name: 'Malware/Phishing Indicators',
        status: malwareDetected ? 'fail' : 'info',
        description: malwareDetected ? detectionDetails : 'Full malware detection requires integration with Google Safe Browsing API',
        severity: 'critical'
      });

      // 2. SSL Certificate Validity
      checks.push({
        name: 'SSL Certificate Status',
        status: url.startsWith('https://') ? 'pass' : 'fail',
        description: url.startsWith('https://') ? 'HTTPS connection established' : 'No HTTPS - unencrypted connection',
        severity: 'critical'
      });

      // 3. Suspicious Content Check
      const hasFormWithoutHttps = response.data?.includes('form') && !url.startsWith('https://');
      checks.push({
        name: 'Form Security',
        status: hasFormWithoutHttps ? 'fail' : 'pass',
        description: hasFormWithoutHttps ? 'Forms detected on non-HTTPS page' : 'Forms properly secured or no forms detected',
        severity: 'critical'
      });

      // 4. Outdated Software Detection
      checks.push({
        name: 'Outdated Software Detection',
        status: 'info',
        description: 'Requires deep framework version analysis',
        severity: 'medium'
      });

      // 5. SQL Injection Indicators
      checks.push({
        name: 'SQL Injection Protection',
        status: 'info',
        description: 'Server-side security requires comprehensive penetration testing',
        severity: 'critical'
      });

      // 6. XSS Protection
      checks.push({
        name: 'XSS (Cross-Site Scripting) Protection',
        status: 'info',
        description: 'CSP headers provide XSS protection (see Security section)',
        severity: 'high'
      });

      // 7. Iframe Restrictions
      const iframes = response.data?.match(/<iframe/gi) || [];
      checks.push({
        name: 'Iframe Usage',
        status: iframes.length > 0 ? 'warn' : 'pass',
        description: iframes.length > 0 ? `${iframes.length} iframes detected - verify they're from trusted sources` : 'No iframes detected',
        severity: 'medium'
      });

      // 8. External Script Safety
      const externalScripts = (response.data?.match(/<script[^>]+src=/gi) || []).length;
      checks.push({
        name: 'External Scripts',
        status: externalScripts > 0 ? 'warn' : 'pass',
        description: externalScripts > 0 ? `${externalScripts} external scripts - verify they're from trusted sources` : 'No external scripts',
        severity: 'high'
      });

      // 9. Rate Limiting / Brute Force Protection
      checks.push({
        name: 'Rate Limiting / Bot Protection',
        status: 'info',
        description: 'Bot protection mechanisms vary by platform',
        severity: 'medium'
      });

      // 10. DNS Hijacking Risk
      checks.push({
        name: 'Domain Registrar Status',
        status: 'info',
        description: 'Domain registration status requires WHOIS lookup',
        severity: 'medium'
      });

    } catch (error) {
      checks.push({
        name: 'Safety Analysis Error',
        status: 'error',
        description: `Unable to analyze: ${error.message}`,
        severity: 'critical'
      });
    }

    // Calculate score and attach malwareDetected flag for the route handler to act on
    let score = calculateCategoryScore(checks);
    const malwareCheck = checks.find(c => c.name === 'Malware/Phishing Indicators');
    const malwareFlag = !!(malwareCheck && (malwareCheck.status === 'fail' || malwareCheck.status === 'error'));
    if (malwareFlag) {
      // category gets 0
      score = 0;
    }

    return {
      category: 'Safety & Threats',
      icon: '⚠️',
      score,
      checks,
      malwareDetected: malwareFlag
    };
  }

  /**
   * Better phishing detection based on domain structure and URL patterns
   * Instead of keyword matching, looks at domain reputation indicators
   */
  detectPhishingIndicators(url, hostname) {
    const urlLower = url.toLowerCase();
    const decodedUrl = decodeURIComponent(urlLower);
    
    // 1. Check for obfuscated/encoded payloads in URL path or query
    // This includes base64, URL-encoded, or other suspicious patterns
    if (/\/[A-Za-z0-9+/]{50,}={0,2}($|\?|\/)/i.test(urlLower) ||  // Long base64 in path
        /\/[A-Za-z0-9+/]{50,}={0,2}($|\?|\/)/i.test(decodedUrl) ||
        /[?&][a-zA-Z0-9_-]+=([A-Za-z0-9+/]{50,}={0,2})($|&|%)/i.test(urlLower) || // Base64 in query
        /[?&][a-zA-Z0-9_-]+=([A-Za-z0-9+/]{50,}={0,2})($|&)/i.test(decodedUrl)) {
      return true;
    }

    // 2. Check for suspicious URL patterns
    const suspiciousPatterns = [
      /^https?:\/\/[a-z0-9]+\.[a-z0-9]+\.click\//i, // Click redirect domains
      /^https?:\/\/[a-z0-9]+\.[a-z0-9]+\.download\//i, // Download redirect domains
      /[?&](click_id|cid|zoneid|landing_id|_pd|mcount|spayout)/i, // Tracking/redirect parameters
      /verify|confirm|update.*password|urgent.*action|claim.*reward|click.*verify/i, // Phishing keywords in URL
      /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, // IP addresses instead of domain names
    ];
    
    for (const pattern of suspiciousPatterns) {
      if (pattern.test(urlLower)) {
        return true;
      }
    }

    // 3. Check for typosquatting patterns (common misspellings of major sites)
    const typosquattingPatterns = [
      /goog+le/i, /faceb+ook/i, /amazo+n/i, /microso+ft/i, 
      /paypa+l/i, /twit+ter/i, /linkedI+n/i, /instag+ram/i
    ];
    
    for (const pattern of typosquattingPatterns) {
      if (pattern.test(hostname) && !hostname.includes('google.com') && 
          !hostname.includes('facebook.com') && !hostname.includes('amazon.com') &&
          !hostname.includes('microsoft.com') && !hostname.includes('paypal.com') &&
          !hostname.includes('twitter.com') && !hostname.includes('linkedin.com') &&
          !hostname.includes('instagram.com')) {
        return true;
      }
    }

    // 4. Check for suspicious domain age indicators (new domains with common names)
    // Domains with numbers replacing letters (l33t speak)
    if (/[a-z0-9]*[0-9]{2,}[a-z0-9]*\.(click|download|stream|app|site)$/i.test(hostname)) {
      return true;
    }

    // 5. Check for suspicious redirect/shortened URLs with tracking
    if (urlLower.includes('/redirect?') || urlLower.includes('/click?') || 
        urlLower.includes('/out?') || urlLower.includes('/go?')) {
      return true;
    }

    return false;
  }

  /**
   * Check domain reputation for suspicious patterns
   * Detects newly registered domains with suspicious TLDs and patterns
   */
  checkDomainReputation(hostname, url) {
    const hostnameLower = hostname.toLowerCase();
    
    // Suspicious TLDs commonly used for phishing/malware
    const suspiciousTLDs = [
      '.shop', '.click', '.download', '.stream', '.trade',
      '.site', '.online', '.website', '.app', '.store',
      '.host', '.cloud', '.work', '.top', '.bid',
      '.faith', '.review', '.tk', '.ml', '.ga', '.cf'
    ];

    for (const tld of suspiciousTLDs) {
      if (hostnameLower.endsWith(tld)) {
        // Check for additional red flags
        const subdomain = hostnameLower.replace(tld, '');
        
        // Random character patterns (common in scam domains)
        if (/^[a-z]{2,}\./.test(subdomain) && subdomain.match(/[a-z]/g).length < 10) {
          // Random 2-20 char subdomains on suspicious TLDs
          return {
            isSuspicious: true,
            reason: `Suspicious domain pattern: ${tld} TLD with obfuscated subdomain`
          };
        }

        // Generic brand names with suspicious TLDs (typosquatting)
        if (/^(bank|crypto|wallet|trading|exchange|payment|secure)/.test(subdomain)) {
          return {
            isSuspicious: true,
            reason: `Typosquatting attempt: Generic financial service brand on suspicious ${tld} TLD`
          };
        }

        // Multiple random string segments
        if ((subdomain.match(/\./g) || []).length > 1) {
          return {
            isSuspicious: true,
            reason: `Suspicious subdomain pattern on ${tld} TLD`
          };
        }
      }
    }

    // Check for URL parameters that look like tracking/redirect IDs
    const url_lower = url.toLowerCase();
    const hasSuspiciousParams = /[?&](param_\d+|id|redirect|url|click_id|ref|utm|goto)=/i.test(url_lower) &&
                                /[?&]param_\d+=\d{6,}/.test(url_lower); // Long numeric IDs
    
    if (hasSuspiciousParams && hostnameLower.includes('.shop')) {
      return {
        isSuspicious: true,
        reason: 'Suspicious redirect pattern with numeric tracking IDs on shop domain'
      };
    }

    return { isSuspicious: false };
  }
}

module.exports = SafetyCheck;
