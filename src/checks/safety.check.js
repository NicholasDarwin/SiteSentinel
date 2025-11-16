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
        const malwareKeywords = [
          'malware', 'virus', 'trojan', 'ransomware', 'phishing', 'infected', 'malicious',
          'drive-by', 'you have been infected', 'click here to download', 'decrypt', 'scam'
        ];
        const detectedKeywords = malwareKeywords.filter(k => body.includes(k));
        if (detectedKeywords.length > 0) {
          malwareDetected = true;
          detectionDetails = `Keyword indicators detected: ${detectedKeywords.join(', ')}`;
        }

        // Detect phishing redirect/confirmation scams ("click to confirm you are not a bot")
        const phishingPatterns = /click\.php|redirect\.php|click_id=|zoneid=|_pd=.*durframet\.com|_pd=.*chroelhome\.com/i;
        if (phishingPatterns.test(body) || phishingPatterns.test(urlLower)) {
          malwareDetected = true;
          detectionDetails = `Phishing redirect scam detected: fake verification/CAPTCHA prompt`;
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
}

module.exports = SafetyCheck;
