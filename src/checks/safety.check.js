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

      const headers = response.headers;
      const body = response.data ? String(response.data) : '';
      const isHttps = url.startsWith('https://');

      // 1. Malware / Phishing Indicators
      let malwareDetected = false;
      let detectionDetails = null;

      const gsApiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
      if (gsApiKey) {
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
        } catch (err) { /* Fall back to local detection */ }
      }

      if (!malwareDetected) {
        malwareDetected = this.detectPhishingIndicators(url, hostname);
        if (malwareDetected) {
          detectionDetails = 'WARNING: Suspicious URL patterns detected (possible phishing/scam site)';
        }
      }

      if (!malwareDetected) {
        const domainCheck = this.checkDomainReputation(hostname, url);
        if (domainCheck.isSuspicious) {
          malwareDetected = true;
          detectionDetails = `WARNING: ${domainCheck.reason}`;
        }
      }

      checks.push({
        name: 'Malware/Phishing Indicators',
        status: malwareDetected ? 'fail' : 'pass',
        description: malwareDetected ? detectionDetails : 'No malware or phishing indicators detected',
        severity: 'critical'
      });

      // 2. SSL Certificate Status
      checks.push({
        name: 'SSL Certificate Status',
        status: isHttps ? 'pass' : 'fail',
        description: isHttps 
          ? 'Site uses HTTPS encryption - your connection is secure' 
          : 'Site uses HTTP (unencrypted) - data can be intercepted by attackers',
        severity: 'critical'
      });

      // 3. Form Security
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
        severity: 'critical'
      });

      // 4. XSS Protection - Actually check the headers
      const csp = headers['content-security-policy'] || '';
      const xssHeader = headers['x-xss-protection'] || '';
      
      let xssStatus, xssDesc;
      if (csp && (csp.includes('script-src') || csp.includes('default-src'))) {
        xssStatus = 'pass';
        xssDesc = 'Content Security Policy (CSP) is configured - protects against script injection attacks';
      } else if (xssHeader === '1; mode=block') {
        xssStatus = 'pass';
        xssDesc = 'X-XSS-Protection header enabled in blocking mode';
      } else if (xssHeader) {
        xssStatus = 'warn';
        xssDesc = 'X-XSS-Protection header present but not in full blocking mode';
      } else {
        xssStatus = 'warn';
        xssDesc = 'No XSS protection headers detected - site may be vulnerable to script injection';
      }

      checks.push({
        name: 'XSS (Cross-Site Scripting) Protection',
        status: xssStatus,
        description: xssDesc,
        severity: 'high'
      });

      // 5. External Scripts - Check for potentially malicious scripts
      const scriptTags = body.match(/<script[^>]*src\s*=\s*["']([^"']+)["'][^>]*>/gi) || [];
      const trustedCDNs = ['googleapis.com', 'gstatic.com', 'cloudflare.com', 'jsdelivr.net', 
                          'unpkg.com', 'cdnjs.cloudflare.com', 'jquery.com', 'bootstrapcdn.com'];
      
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
        scriptDesc = `${untrustedScripts.length} script(s) from unknown sources detected - could be tracking or malicious`;
      } else if (externalScripts.length > 0) {
        scriptDesc = `${externalScripts.length} external script(s) loaded from trusted CDNs`;
      }

      checks.push({
        name: 'External Scripts',
        status: scriptStatus,
        description: scriptDesc,
        severity: 'high'
      });

      // 6. Iframe Usage
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
        severity: 'medium'
      });

      // 7. Clickjacking Protection
      const xFrameOptions = (headers['x-frame-options'] || '').toUpperCase();
      const hasFrameAncestors = csp.includes('frame-ancestors');
      
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
        severity: 'medium'
      });

      // 8. Mixed Content (HTTPS loading HTTP resources)
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

    let score = calculateCategoryScore(checks);
    const malwareCheck = checks.find(c => c.name === 'Malware/Phishing Indicators');
    const malwareFlag = !!(malwareCheck && (malwareCheck.status === 'fail' || malwareCheck.status === 'error'));
    if (malwareFlag) {
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

  detectPhishingIndicators(url, hostname) {
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
  }

  checkDomainReputation(hostname, url) {
    const suspicious = ['.click', '.download', '.tk', '.ml', '.ga', '.cf', '.top'];
    for (const tld of suspicious) {
      if (hostname.endsWith(tld)) {
        return { isSuspicious: true, reason: `Suspicious ${tld} domain - commonly used for scams` };
      }
    }
    return { isSuspicious: false };
  }
}

module.exports = SafetyCheck;
