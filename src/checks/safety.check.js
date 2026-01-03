/**
 * Safety & Threats Checks
 */

const axios = require('axios');
const { calculateCategoryScore } = require('../utils/score-calculator.util');
const logger = require('../utils/logger.util');

class SafetyCheck {
  /**
   * Detect deceptive download page patterns (malware distribution)
   * @param {string} bodyLower - Lowercase page content
   * @param {string} url - The URL being analyzed
   * @param {string} hostname - The hostname
   * @returns {{ isDeceptive: boolean, reason: string, riskScore: number, signals: string[] }}
   */
  detectDeceptiveDownload(bodyLower, url, hostname) {
    try {
      const signals = [];
      let riskScore = 0;

      // === HIGH-RISK DOWNLOAD LANGUAGE PATTERNS ===
      const deceptiveDownloadPhrases = [
        { pattern: /your\s+(free\s+)?download\s+is\s+ready/i, weight: 30, signal: 'Deceptive "download ready" messaging' },
        { pattern: /complete\s+download/i, weight: 25, signal: 'Generic "complete download" prompt' },
        { pattern: /download\s+now/i, weight: 15, signal: '"Download Now" call-to-action' },
        { pattern: /setup\s+file/i, weight: 25, signal: 'Generic "setup file" reference' },
        { pattern: /click\s+(here\s+)?to\s+download/i, weight: 20, signal: 'Click-to-download prompt' },
        { pattern: /start\s+download/i, weight: 20, signal: '"Start download" button' },
        { pattern: /downloading\s+will\s+start/i, weight: 25, signal: 'Auto-download messaging' },
        { pattern: /file\s+is\s+ready/i, weight: 25, signal: 'Generic "file ready" messaging' },
        { pattern: /install(er)?\s+file/i, weight: 25, signal: 'Generic "installer" reference' },
        { pattern: /free\s+installer/i, weight: 30, signal: 'Free installer claim' },
        { pattern: /get\s+your\s+(free\s+)?file/i, weight: 25, signal: 'Generic file delivery language' },
        { pattern: /download\s+manager/i, weight: 20, signal: 'Download manager reference' },
        { pattern: /fast(er)?\s+download/i, weight: 20, signal: 'Fast download claim' },
        { pattern: /secure\s+download/i, weight: 15, signal: 'False security claim on download' },
        { pattern: /direct\s+download/i, weight: 15, signal: 'Direct download claim' },
        { pattern: /one\s+click\s+download/i, weight: 20, signal: 'One-click download claim' }
      ];

      for (const { pattern, weight, signal } of deceptiveDownloadPhrases) {
        if (pattern.test(bodyLower)) {
          riskScore += weight;
          signals.push(signal);
        }
      }

      // === MISSING SOFTWARE METADATA (legitimate software always has this) ===
      const hasPublisher = /publisher|developed\s+by|created\s+by|made\s+by|by\s+[A-Z][a-z]+\s+(Inc|LLC|Ltd|Corp)/i.test(bodyLower);
      const hasVersion = /version\s*[\d.]+|v[\d.]+|release\s+[\d.]+/i.test(bodyLower);
      const hasChecksum = /(sha256|sha1|md5|checksum)\s*:?\s*[a-f0-9]{32,}/i.test(bodyLower);
      const hasLicense = /(license|eula|terms\s+of\s+(service|use)|privacy\s+policy|copyright)/i.test(bodyLower);
      const hasProductName = /<title>[^<]*\b(software|app|application|tool|program)\b[^<]*<\/title>/i.test(bodyLower);

      if (!hasPublisher && signals.length > 0) {
        riskScore += 20;
        signals.push('No software publisher/vendor identified');
      }
      if (!hasVersion && signals.length > 0) {
        riskScore += 15;
        signals.push('No software version information');
      }
      if (!hasLicense && signals.length > 0) {
        riskScore += 15;
        signals.push('No license or legal information');
      }

      // === URL PATH ANALYSIS ===
      const urlPath = new URL(url).pathname;
      
      // Long hex/hash-like paths are extremely suspicious
      const hashPattern = /\/[a-f0-9]{24,}$/i;
      const longRandomPath = /\/[a-zA-Z0-9]{32,}$/;
      
      if (hashPattern.test(urlPath)) {
        riskScore += 35;
        signals.push('Hash-like obfuscated URL path (high risk)');
      } else if (longRandomPath.test(urlPath)) {
        riskScore += 30;
        signals.push('Long random/obfuscated URL path');
      }

      // Short UUID-like paths also suspicious in download context
      const uuidPattern = /\/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/i;
      if (uuidPattern.test(urlPath) && signals.length > 0) {
        riskScore += 15;
        signals.push('UUID-based tracking URL');
      }

      // === DOMAIN ANALYSIS ===
      const suspiciousDownloadDomains = [
        'getflux', 'download', 'file', 'soft', 'installer', 'setup', 
        'get', 'grab', 'fetch', 'dlfile', 'filehost', 'upload',
        'mediafire', '4shared', 'zippyshare', 'uploadhaven'
      ];
      
      const domainLower = hostname.toLowerCase();
      for (const keyword of suspiciousDownloadDomains) {
        if (domainLower.includes(keyword)) {
          riskScore += 20;
          signals.push(`Domain contains "${keyword}" - common in file-dropper networks`);
          break;
        }
      }

      // Short-lived/burner domain patterns
      const burnerTLDs = ['.xyz', '.top', '.club', '.online', '.site', '.icu', '.buzz', '.fun'];
      for (const tld of burnerTLDs) {
        if (hostname.endsWith(tld)) {
          riskScore += 15;
          signals.push(`Suspicious TLD "${tld}" common with disposable domains`);
          break;
        }
      }

      // === EXECUTABLE DOWNLOAD DETECTION ===
      const executablePatterns = [
        /href\s*=\s*["'][^"']*\.(exe|msi|dmg|pkg|deb|rpm|appimage|bat|cmd|ps1|vbs|js)["']/i,
        /download\s*=\s*["'][^"']*\.(exe|msi|dmg|pkg|bat|cmd)["']/i,
        /\.exe\b/i,
        /\.msi\b/i,
        /\.dmg\b/i
      ];

      let hasExecutable = false;
      for (const pattern of executablePatterns) {
        if (pattern.test(bodyLower)) {
          hasExecutable = true;
          break;
        }
      }

      if (hasExecutable && signals.length > 0) {
        riskScore += 25;
        signals.push('Executable file download detected');
      }

      // === FAKE DOWNLOAD GATING PATTERNS ===
      const gatingPatterns = [
        { pattern: /step\s*1.*step\s*2/is, signal: 'Fake multi-step download process' },
        { pattern: /waiting.*seconds?.*download/i, signal: 'Fake countdown timer' },
        { pattern: /please\s+wait.*download/i, signal: 'Fake waiting prompt' },
        { pattern: /generating.*link/i, signal: 'Fake link generation' },
        { pattern: /preparing.*download/i, signal: 'Fake preparation message' }
      ];

      for (const { pattern, signal } of gatingPatterns) {
        if (pattern.test(bodyLower)) {
          riskScore += 20;
          signals.push(signal);
        }
      }

      // === PAGE CONTENT ANALYSIS ===
      // Check for minimal page content (malware pages are often sparse)
      const textContent = bodyLower.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
      const wordCount = textContent.split(' ').filter(w => w.length > 2).length;
      
      if (wordCount < 50 && signals.length >= 2) {
        riskScore += 15;
        signals.push('Sparse page content typical of malware distribution');
      }

      // === DETERMINE FINAL CLASSIFICATION ===
      const isDeceptive = riskScore >= 50;
      
      let reason = '';
      if (isDeceptive) {
        if (riskScore >= 80) {
          reason = 'DANGER: High-confidence malware distribution page detected';
        } else if (riskScore >= 65) {
          reason = 'WARNING: Likely deceptive download page - exercise extreme caution';
        } else {
          reason = 'WARNING: Suspicious download page with multiple red flags';
        }
      }

      return { isDeceptive, reason, riskScore, signals };
    } catch (err) {
      logger.error('Error in detectDeceptiveDownload:', err.message);
      return { isDeceptive: false, reason: '', riskScore: 0, signals: [] };
    }
  }

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

      // 1. Deceptive Download / Malware Distribution Detection (HIGHEST PRIORITY)
      let deceptiveDownload = { isDeceptive: false, reason: '', riskScore: 0, signals: [] };
      try {
        deceptiveDownload = this.detectDeceptiveDownload(bodyLower, url, hostname);
      } catch (ddErr) {
        logger.error('Deceptive download detection failed:', ddErr.message);
      }

      // 2. Scam/Phishing Content Detection (check page content first) - Isolated with try/catch
      let scamDetection = { isScam: false, reason: '' };
      try {
        scamDetection = this.detectScamContent(bodyLower, url);
      } catch (scamErr) {
        logger.error('Scam detection failed:', scamErr.message);
        // Continue with empty result rather than failing entire analysis
      }
      
      // 3. Malware / Phishing Indicators - Combine all detection methods
      let malwareDetected = deceptiveDownload.isDeceptive || scamDetection.isScam;
      let detectionDetails = deceptiveDownload.reason || scamDetection.reason;
      let detectionSignals = deceptiveDownload.signals || [];

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

      // Build comprehensive description for malware check
      let malwareDescription = 'No malware or phishing indicators detected';
      if (malwareDetected) {
        malwareDescription = detectionDetails;
        if (detectionSignals.length > 0) {
          malwareDescription += ` | Signals: ${detectionSignals.slice(0, 5).join('; ')}`;
        }
      }

      checks.push({
        name: 'Malware/Phishing Indicators',
        status: malwareDetected ? 'fail' : 'pass',
        description: malwareDescription,
        severity: 'critical',
        explanation: 'This check scans for known malware signatures, phishing patterns, deceptive download pages, and scam content using multiple detection methods including behavioral analysis and Google Safe Browsing API.',
        riskScore: deceptiveDownload.riskScore,
        signals: detectionSignals
      });

      // 4. Deceptive Download Page (separate detailed check)
      if (deceptiveDownload.isDeceptive) {
        checks.push({
          name: 'Deceptive Download Page',
          status: 'fail',
          description: `MALWARE DISTRIBUTION: This page exhibits ${detectionSignals.length} suspicious signals typical of malware/PUP distribution`,
          severity: 'critical',
          explanation: 'This check detects pages that use social engineering to trick users into downloading malicious software. Common indicators include: generic download prompts, missing publisher info, obfuscated URLs, and executable delivery without transparency.',
          signals: detectionSignals,
          riskScore: deceptiveDownload.riskScore,
          classification: deceptiveDownload.riskScore >= 80 ? 'Malicious' : 'Highly Suspicious'
        });
      }

      // 5. Credential Harvesting Detection - Isolated with try/catch
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
      
      // Check for obfuscated payloads (base64-like strings)
      if (/\/[A-Za-z0-9+/]{50,}={0,2}($|\?|\/)/i.test(urlLower)) return true;
      
      // Check for long hex strings in URL path (common in malware distribution)
      if (/\/[a-f0-9]{24,}($|\?|\/)/i.test(urlLower)) return true;
      
      // Suspicious tracking/affiliate patterns
      if (/[?&](click_id|cid|zoneid|landing_id|aff_id|campaign_id)/i.test(urlLower)) return true;
      
      // IP address in URL (suspicious)
      if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(urlLower)) return true;
      
      // Typosquatting detection
      const typos = [/goog+le/i, /faceb+ook/i, /amazo+n/i, /paypa+l/i, /micros+oft/i, /app+le/i];
      const legit = ['google.com', 'facebook.com', 'amazon.com', 'paypal.com', 'microsoft.com', 'apple.com'];
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
      const hostLower = hostname.toLowerCase();
      
      // Suspicious TLDs commonly used for scams and malware
      const suspiciousTLDs = [
        '.click', '.download', '.tk', '.ml', '.ga', '.cf', '.top',
        '.xyz', '.icu', '.buzz', '.fun', '.monster', '.cam', '.loan',
        '.work', '.date', '.racing', '.win', '.stream', '.gdn'
      ];
      
      for (const tld of suspiciousTLDs) {
        if (hostLower.endsWith(tld)) {
          return { isSuspicious: true, reason: `Suspicious ${tld} domain - commonly used for scams/malware` };
        }
      }
      
      // Known file-dropper / malware distribution domain patterns
      const malwareDistributionPatterns = [
        { pattern: /getflux/i, reason: 'Domain associated with software bundling/PUP distribution' },
        { pattern: /^(get|grab|fetch|dl|download|file|soft|free)[a-z]*\./i, reason: 'Generic file delivery domain pattern' },
        { pattern: /install(er)?s?[.-]/i, reason: 'Generic installer delivery domain' },
        { pattern: /(setup|patch|crack|keygen|serial)[.-]/i, reason: 'Potentially unwanted software distribution domain' },
        { pattern: /\d{2,}[a-z]*\.(com|net|org)$/i, reason: 'Numeric domain pattern common in malware campaigns' }
      ];
      
      for (const { pattern, reason } of malwareDistributionPatterns) {
        if (pattern.test(hostLower)) {
          return { isSuspicious: true, reason };
        }
      }
      
      // Check URL path for suspicious patterns
      try {
        const urlPath = new URL(url).pathname;
        // Long random/hash paths are suspicious
        if (/\/[a-f0-9]{32,}$/i.test(urlPath)) {
          return { isSuspicious: true, reason: 'Hash-like URL path typical of malware distribution tracking' };
        }
      } catch (e) {
        // Ignore URL parsing errors
      }
      
      return { isSuspicious: false };
    } catch (err) {
      logger.error('Error in checkDomainReputation:', err.message);
      return { isSuspicious: false };
    }
  }
}

module.exports = SafetyCheck;
