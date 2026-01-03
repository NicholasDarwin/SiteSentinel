/**
 * Safety & Threats Checks
 */

const axios = require('axios');
const { calculateCategoryScore } = require('../utils/score-calculator.util');
const logger = require('../utils/logger.util');

class SafetyCheck {
  /**
   * Detect scam/phishing content patterns in page body
   * @param {string} bodyLower - Lowercase page content
   * @param {string} url - The URL being analyzed
   * @returns {{ isScam: boolean, reason: string }}
   */
  detectScamContent(bodyLower, url) {
    try {
      // Scam/phishing content patterns
      const scamPatterns = [
        { pattern: /your.*(account|computer|device).*(has been|is).*(compromised|hacked|infected)/i, reason: 'Fake security warning detected' },
        { pattern: /call.*\d{3}.*\d{3}.*\d{4}.*immediately/i, reason: 'Tech support scam phone number detected' },
        { pattern: /microsoft.*support.*call/i, reason: 'Fake Microsoft support scam detected' },
        { pattern: /apple.*support.*call/i, reason: 'Fake Apple support scam detected' },
        { pattern: /congratulations.*you.*(won|winner|selected)/i, reason: 'Prize/lottery scam detected' },
        { pattern: /claim.*your.*(prize|reward|gift)/i, reason: 'Prize claim scam detected' },
        { pattern: /verify.*your.*(identity|account).*immediately/i, reason: 'Urgency phishing pattern detected' },
        { pattern: /your.*password.*expired/i, reason: 'Password phishing pattern detected' },
        { pattern: /unusual.*activity.*your.*account/i, reason: 'Account phishing pattern detected' },
        { pattern: /suspended.*account.*verify/i, reason: 'Account suspension phishing detected' },
        { pattern: /bitcoin.*double|double.*bitcoin/i, reason: 'Cryptocurrency scam detected' },
        { pattern: /send.*btc.*receive.*double/i, reason: 'Cryptocurrency doubling scam detected' },
        { pattern: /click.*here.*verify.*identity/i, reason: 'Identity verification phishing detected' }
      ];

      for (const { pattern, reason } of scamPatterns) {
        if (pattern.test(bodyLower)) {
          return { isScam: true, reason: `WARNING: ${reason}` };
        }
      }

      return { isScam: false, reason: '' };
    } catch (err) {
      logger.error('Error in detectScamContent:', err.message);
      return { isScam: false, reason: '' };
    }
  }

  /**
   * Detect credential harvesting patterns
   * @param {string} bodyLower - Lowercase page content
   * @param {string} hostname - The hostname being analyzed
   * @returns {{ isHarvesting: boolean, reason: string }}
   */
  detectCredentialHarvesting(bodyLower, hostname) {
    try {
      // Check for login forms on suspicious domains
      const hasLoginForm = /type\s*=\s*["']?password/i.test(bodyLower);
      const hasSensitiveFields = /(social.*security|ssn|credit.*card|card.*number|cvv|expir)/i.test(bodyLower);
      
      // Known legitimate login domains
      const legitimateLoginDomains = [
        'google.com', 'facebook.com', 'microsoft.com', 'apple.com', 
        'amazon.com', 'paypal.com', 'github.com', 'twitter.com', 'linkedin.com',
        'accounts.google.com', 'login.microsoft.com', 'appleid.apple.com'
      ];
      
      const isLegitDomain = legitimateLoginDomains.some(d => hostname.includes(d));
      
      if (hasLoginForm && !isLegitDomain) {
        // Check for brand impersonation
        const brandPatterns = [
          { brand: 'google', pattern: /google.*sign.*in|sign.*in.*google/i },
          { brand: 'facebook', pattern: /facebook.*log.*in|log.*in.*facebook/i },
          { brand: 'microsoft', pattern: /microsoft.*sign.*in|outlook.*sign.*in/i },
          { brand: 'apple', pattern: /apple.*id.*sign|icloud.*sign/i },
          { brand: 'paypal', pattern: /paypal.*log.*in/i },
          { brand: 'amazon', pattern: /amazon.*sign.*in/i }
        ];
        
        for (const { brand, pattern } of brandPatterns) {
          if (pattern.test(bodyLower) && !hostname.includes(brand)) {
            return { 
              isHarvesting: true, 
              reason: `DANGER: Potential ${brand.charAt(0).toUpperCase() + brand.slice(1)} credential phishing - login form on non-${brand} domain` 
            };
          }
        }
      }
      
      if (hasSensitiveFields && !isLegitDomain) {
        return { 
          isHarvesting: true, 
          reason: 'WARNING: Page requests sensitive information (SSN/credit card) on untrusted domain' 
        };
      }
      
      return { isHarvesting: false, reason: '' };
    } catch (err) {
      logger.error('Error in detectCredentialHarvesting:', err.message);
      return { isHarvesting: false, reason: '' };
    }
  }

  async analyze(url) {
    const checks = [];
    const hostname = new URL(url).hostname;
    let analysisError = null;

    try {
      const response = await axios.get(url, { 
        timeout: 15000,
        validateStatus: () => true
      });

      const headers = response.headers;
      const body = response.data ? String(response.data) : '';
      const bodyLower = body.toLowerCase();
      const isHttps = url.startsWith('https://');

      // 1. Scam/Phishing Content Detection (check page content first) - Isolated with try/catch
      let scamDetection = { isScam: false, reason: '' };
      try {
        scamDetection = this.detectScamContent(bodyLower, url);
      } catch (scamErr) {
        logger.error('Scam detection failed:', scamErr.message);
        // Continue with empty result rather than failing entire analysis
      }
      
      // 2. Malware / Phishing Indicators - Isolated with try/catch
      let malwareDetected = scamDetection.isScam;
      let detectionDetails = scamDetection.reason;

      // Try Google Safe Browsing API if available
      const gsApiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
      if (!malwareDetected && gsApiKey) {
        try {
          const gsPayload = {
            client: { clientId: 'sitesentinel', clientVersion: '2.0.0' },
            threatInfo: {
              threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
              platformTypes: ['ANY_PLATFORM'],
              threatEntryTypes: ['URL'],
              threatEntries: [{ url }]
            }
          };
          const gsUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${gsApiKey}`;
          const gsResp = await axios.post(gsUrl, gsPayload, { timeout: 10000 });
          if (gsResp.data && Object.keys(gsResp.data).length > 0) {
            malwareDetected = true;
            detectionDetails = 'DANGER: Google Safe Browsing flagged this site for malware or phishing';
          }
        } catch (err) { 
          logger.debug('Google Safe Browsing API not available:', err.message);
          /* Fall back to local detection */ 
        }
      }

      // Try local phishing detection
      if (!malwareDetected) {
        try {
          malwareDetected = this.detectPhishingIndicators(url, hostname);
          if (malwareDetected) {
            detectionDetails = 'WARNING: Suspicious URL patterns detected (possible phishing/scam site)';
          }
        } catch (phishErr) {
          logger.error('Phishing detection failed:', phishErr.message);
        }
      }

      // Try domain reputation check
      if (!malwareDetected) {
        try {
          const domainCheck = this.checkDomainReputation(hostname, url);
          if (domainCheck.isSuspicious) {
            malwareDetected = true;
            detectionDetails = `WARNING: ${domainCheck.reason}`;
          }
        } catch (domainErr) {
          logger.error('Domain reputation check failed:', domainErr.message);
        }
      }

      checks.push({
        name: 'Malware/Phishing Indicators',
        status: malwareDetected ? 'fail' : 'pass',
        description: malwareDetected ? detectionDetails : 'No malware or phishing indicators detected',
        severity: 'critical',
        explanation: 'This check scans for known malware signatures, phishing patterns, and scam content using multiple detection methods including Google Safe Browsing API.'
      });

      // 3. Credential Harvesting Detection - Isolated with try/catch
      let credentialHarvesting = { isHarvesting: false, reason: '' };
      try {
        credentialHarvesting = this.detectCredentialHarvesting(bodyLower, hostname);
      } catch (credErr) {
        logger.error('Credential harvesting detection failed:', credErr.message);
      }
      checks.push({
        name: 'Credential Harvesting',
        status: credentialHarvesting.isHarvesting ? 'fail' : 'pass',
        description: credentialHarvesting.isHarvesting 
          ? credentialHarvesting.reason 
          : 'No credential harvesting patterns detected',
        severity: 'critical',
        explanation: 'Detects fake login forms and pages that attempt to steal passwords or sensitive information like credit cards and SSNs.'
      });

      // 4. SSL Certificate Status
      checks.push({
        name: 'SSL Certificate Status',
        status: isHttps ? 'pass' : 'fail',
        description: isHttps 
          ? 'Site uses HTTPS encryption - your connection is secure' 
          : 'Site uses HTTP (unencrypted) - data can be intercepted by attackers',
        severity: 'critical',
        explanation: 'HTTPS encrypts all data between your browser and the website, protecting sensitive information from interception.'
      });

      // 5. Form Security
      const hasForms = /<form/i.test(body);
      const hasPasswordField = /<input[^>]*type\s*=\s*["']?password/i.test(body);
      
      let formStatus = 'pass';
      let formDesc = 'No forms detected, or all forms are on secure HTTPS';
      
      if (hasPasswordField && !isHttps) {
        formStatus = 'fail';
        formDesc = 'CRITICAL: Password field on non-HTTPS page - login credentials can be stolen';
      } else if (hasForms && !isHttps) {
        formStatus = 'warn';
        formDesc = 'Forms detected on non-HTTPS page - submitted data is not encrypted';
      } else if (hasForms && isHttps) {
        formDesc = 'Forms are protected by HTTPS encryption';
      }

      checks.push({
        name: 'Form Security',
        status: formStatus,
        description: formDesc,
        severity: 'critical',
        explanation: 'Password and form fields should always be on HTTPS pages to prevent credentials from being intercepted.'
      });

      // 6. XSS Protection - Check headers and meta tags for CSP
      const csp = headers['content-security-policy'] || '';
      const cspReportOnly = headers['content-security-policy-report-only'] || '';
      const xssHeader = headers['x-xss-protection'] || '';
      
      // Also check for CSP in meta tags (common for static sites)
      const metaCsp = body.match(/<meta[^>]*http-equiv\s*=\s*["']Content-Security-Policy["'][^>]*content\s*=\s*["']([^"']+)["']/i);
      const effectiveCsp = csp || (metaCsp ? metaCsp[1] : '');
      
      let xssStatus, xssDesc, xssExplanation;
      if (effectiveCsp && (effectiveCsp.includes('script-src') || effectiveCsp.includes('default-src'))) {
        xssStatus = 'pass';
        xssDesc = 'Content Security Policy (CSP) is configured - protects against script injection attacks';
        xssExplanation = 'CSP restricts which scripts can run on the page, preventing malicious code injection.';
      } else if (cspReportOnly) {
        xssStatus = 'warn';
        xssDesc = 'CSP in report-only mode - monitoring but not blocking attacks';
        xssExplanation = 'CSP is configured but only reporting violations, not blocking them. Consider enabling enforcement.';
      } else if (xssHeader === '1; mode=block') {
        xssStatus = 'pass';
        xssDesc = 'X-XSS-Protection header enabled in blocking mode';
        xssExplanation = 'Browser XSS filter is enabled and will block detected attacks.';
      } else if (xssHeader) {
        xssStatus = 'warn';
        xssDesc = 'X-XSS-Protection header present but not in full blocking mode';
        xssExplanation = 'XSS protection is partially configured. Consider setting to "1; mode=block".';
      } else {
        // Check if this might be a major provider using infrastructure-level CSP
        const knownInfraProviders = ['google.com', 'cloudflare.com', 'amazon.com', 'microsoft.com', 'facebook.com'];
        const isKnownProvider = knownInfraProviders.some(p => hostname.includes(p));
        if (isKnownProvider) {
          xssStatus = 'info';
          xssDesc = 'No CSP in HTTP headers - may be applied at infrastructure level or via service worker';
          xssExplanation = 'Major providers often apply security policies at the CDN/infrastructure level rather than in HTTP headers.';
        } else {
          xssStatus = 'warn';
          xssDesc = 'No XSS protection headers detected - site may be vulnerable to script injection';
          xssExplanation = 'Consider implementing Content-Security-Policy to protect against cross-site scripting attacks.';
        }
      }

      checks.push({
        name: 'XSS (Cross-Site Scripting) Protection',
        status: xssStatus,
        description: xssDesc,
        severity: 'high',
        explanation: xssExplanation
      });

      // 7. External Scripts - Check for potentially malicious scripts
      const scriptTags = body.match(/<script[^>]*src\s*=\s*["']([^"']+)["'][^>]*>/gi) || [];
      const trustedCDNs = ['googleapis.com', 'gstatic.com', 'cloudflare.com', 'jsdelivr.net', 
                          'unpkg.com', 'cdnjs.cloudflare.com', 'jquery.com', 'bootstrapcdn.com',
                          'google.com', 'facebook.net', 'twitter.com', 'linkedin.com'];
      
      const externalScripts = scriptTags.filter(tag => {
        const srcMatch = tag.match(/src\s*=\s*["']([^"']+)["']/i);
        return srcMatch && !srcMatch[1].startsWith('/') && !srcMatch[1].includes(hostname);
      });
      
      const untrustedScripts = externalScripts.filter(tag => {
        const srcMatch = tag.match(/src\s*=\s*["']([^"']+)["']/i);
        return srcMatch && !trustedCDNs.some(cdn => srcMatch[1].includes(cdn));
      });

      let scriptStatus = 'pass';
      let scriptDesc = 'No external scripts detected';
      
      if (untrustedScripts.length > 0) {
        scriptStatus = 'warn';
        scriptDesc = `${untrustedScripts.length} script(s) from unknown sources detected - verify they are legitimate`;
      } else if (externalScripts.length > 0) {
        scriptDesc = `${externalScripts.length} external script(s) loaded from trusted CDNs`;
      }

      checks.push({
        name: 'External Scripts',
        status: scriptStatus,
        description: scriptDesc,
        severity: 'high',
        explanation: 'External scripts from unknown sources could potentially contain malicious code or tracking. Trusted CDNs are generally safe.'
      });

      // 8. Iframe Usage
      const iframes = body.match(/<iframe[^>]*>/gi) || [];
      const externalIframes = iframes.filter(iframe => {
        const srcMatch = iframe.match(/src\s*=\s*["']([^"']+)["']/i);
        return srcMatch && !srcMatch[1].startsWith('/') && !srcMatch[1].includes(hostname);
      });

      let iframeStatus = 'pass';
      let iframeDesc = 'No iframes detected on page';
      
      if (externalIframes.length > 0) {
        iframeStatus = 'warn';
        iframeDesc = `${externalIframes.length} external iframe(s) detected - verify they're from trusted sources`;
      } else if (iframes.length > 0) {
        iframeDesc = `${iframes.length} iframe(s) detected, all from same domain`;
      }

      checks.push({
        name: 'Iframe Usage',
        status: iframeStatus,
        description: iframeDesc,
        severity: 'medium',
        explanation: 'Iframes can embed content from other websites. External iframes should be from trusted sources only.'
      });

      // 9. Clickjacking Protection
      const xFrameOptions = (headers['x-frame-options'] || '').toUpperCase();
      const hasFrameAncestors = effectiveCsp.includes('frame-ancestors');
      
      let clickjackStatus = 'warn';
      let clickjackDesc = 'No clickjacking protection - site can be embedded in malicious iframes';
      
      if (xFrameOptions === 'DENY' || hasFrameAncestors) {
        clickjackStatus = 'pass';
        clickjackDesc = 'Clickjacking protection enabled - site cannot be embedded in iframes';
      } else if (xFrameOptions === 'SAMEORIGIN') {
        clickjackStatus = 'pass';
        clickjackDesc = 'Clickjacking protection enabled - only same-origin embedding allowed';
      }

      checks.push({
        name: 'Clickjacking Protection',
        status: clickjackStatus,
        description: clickjackDesc,
        severity: 'medium',
        explanation: 'Clickjacking protection prevents attackers from overlaying invisible elements on your site to trick users into clicking malicious links.'
      });

      // 10. Mixed Content (HTTPS loading HTTP resources)
      let mixedStatus = 'pass';
      let mixedDesc = 'No mixed content issues';
      
      if (isHttps) {
        const httpResources = body.match(/(?:src|href)\s*=\s*["']http:\/\/[^"']+["']/gi) || [];
        if (httpResources.length > 0) {
          mixedStatus = 'warn';
          mixedDesc = `${httpResources.length} insecure HTTP resource(s) on HTTPS page - may cause security warnings`;
        }
      }

      checks.push({
        name: 'Mixed Content',
        status: mixedStatus,
        description: mixedDesc,
        severity: 'medium',
        explanation: 'Mixed content occurs when an HTTPS page loads resources over HTTP, potentially exposing sensitive data.'
      });

    } catch (error) {
      logger.error('Safety analysis error:', error.message);
      analysisError = error;
      checks.push({
        name: 'Safety Analysis Error',
        status: 'error',
        description: 'Safety analysis unavailable (engine error)',
        severity: 'critical',
        explanation: 'An error occurred during safety analysis. This category will not contribute to the overall score.'
      });
    }

    // Calculate score - if there was an analysis error, mark category as unavailable
    let score;
    let categoryStatus = 'available';
    
    if (analysisError) {
      score = null;
      categoryStatus = 'unavailable';
    } else {
      score = calculateCategoryScore(checks);
      const malwareCheck = checks.find(c => c.name === 'Malware/Phishing Indicators');
      const malwareFlag = !!(malwareCheck && (malwareCheck.status === 'fail' || malwareCheck.status === 'error'));
      if (malwareFlag) {
        score = 0;
      }
    }

    return {
      category: 'Safety & Threats',
      icon: 'shield-alert',
      score,
      status: categoryStatus,
      checks,
      malwareDetected: checks.some(c => c.name === 'Malware/Phishing Indicators' && c.status === 'fail')
    };
  }

  detectPhishingIndicators(url, hostname) {
    try {
      const urlLower = url.toLowerCase();
      
      // Check for obfuscated payloads
      if (/\/[A-Za-z0-9+/]{50,}={0,2}($|\?|\/)/i.test(urlLower)) return true;
      
      // Suspicious patterns
      if (/[?&](click_id|cid|zoneid|landing_id)/i.test(urlLower)) return true;
      if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(urlLower)) return true;
      
      // Typosquatting
      const typos = [/goog+le/i, /faceb+ook/i, /amazo+n/i, /paypa+l/i];
      const legit = ['google.com', 'facebook.com', 'amazon.com', 'paypal.com'];
      for (const pattern of typos) {
        if (pattern.test(hostname) && !legit.some(d => hostname.includes(d))) return true;
      }

      return false;
    } catch (err) {
      logger.error('Error in detectPhishingIndicators:', err.message);
      return false;
    }
  }

  checkDomainReputation(hostname, url) {
    try {
      const suspicious = ['.click', '.download', '.tk', '.ml', '.ga', '.cf', '.top'];
      for (const tld of suspicious) {
        if (hostname.endsWith(tld)) {
          return { isSuspicious: true, reason: `Suspicious ${tld} domain - commonly used for scams` };
        }
      }
      return { isSuspicious: false };
    } catch (err) {
      logger.error('Error in checkDomainReputation:', err.message);
      return { isSuspicious: false };
    }
  }
}

module.exports = SafetyCheck;
