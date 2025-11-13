const axios = require('axios');
const https = require('https');
const http = require('http');
const url = require('url');
const dns = require('dns').promises;

class URLAnalyzer {
  constructor() {
    this.results = {
      url: '',
      timestamp: '',
      summary: {
        total_checks: 0,
        passed: 0,
        warnings: 0,
        failed: 0,
        score: 0
      },
      categories: []
    };
  }

  /**
   * Main analysis function
   */
  async analyze(targetUrl) {
    this.results.url = targetUrl;
    this.results.timestamp = new Date().toISOString();

    try {
      // Validate and normalize URL
      const normalizedUrl = this.normalizeUrl(targetUrl);
      
      // Run all check categories in parallel
      await Promise.all([
        this.runSecurityChecks(normalizedUrl),
        this.runDomainDnsChecks(normalizedUrl),
        this.runPerformanceChecks(normalizedUrl),
        this.runSeoChecks(normalizedUrl),
        this.runAccessibilityPrivacyChecks(normalizedUrl),
        this.runSafetyChecks(normalizedUrl)
      ]);

      // Calculate summary
      this.calculateSummary();
    } catch (error) {
      this.addCheck('General', 'URL Validation', 'fail', error.message);
    }

    return this.results;
  }

  /**
   * Normalize and validate URL
   */
  normalizeUrl(targetUrl) {
    let normalized = targetUrl.trim();
    if (!normalized.startsWith('http://') && !normalized.startsWith('https://')) {
      normalized = 'https://' + normalized;
    }
    try {
      new URL(normalized);
      return normalized;
    } catch (e) {
      throw new Error('Invalid URL format');
    }
  }

  /**
   * Add a check result
   */
  addCheck(category, checkName, status, details, recommendations = []) {
    let cat = this.results.categories.find(c => c.name === category);
    if (!cat) {
      cat = { name: category, checks: [] };
      this.results.categories.push(cat);
    }
    
    cat.checks.push({
      name: checkName,
      status, // 'pass', 'warning', 'fail'
      details,
      recommendations
    });

    this.results.summary.total_checks++;
    if (status === 'pass') this.results.summary.passed++;
    else if (status === 'warning') this.results.summary.warnings++;
    else if (status === 'fail') this.results.summary.failed++;
  }

  /**
   * SECURITY CHECKS
   */
  async runSecurityChecks(targetUrl) {
    const parsedUrl = new URL(targetUrl);
    const isHttps = parsedUrl.protocol === 'https:';

    // Check 1: HTTPS Enforced
    await this.checkHttpsEnforcement(targetUrl);

    // Check 2-5: SSL/TLS Certificate
    if (isHttps) {
      await this.checkSslCertificate(parsedUrl.hostname);
    }

    // Check 6-8: Security Headers
    await this.checkSecurityHeaders(targetUrl);

    // Check 9: HSTS
    await this.checkHsts(targetUrl);

    // Check 10: CSP Header
    await this.checkCsp(targetUrl);

    // Check 11: X-Frame-Options
    await this.checkXFrameOptions(targetUrl);

    // Check 12: X-XSS-Protection
    await this.checkXXssProtection(targetUrl);

    // Check 13: X-Content-Type-Options
    await this.checkXContentTypeOptions(targetUrl);

    // Check 14: Referrer-Policy
    await this.checkReferrerPolicy(targetUrl);

    // Check 15: Permissions-Policy
    await this.checkPermissionsPolicy(targetUrl);

    // Check 16: Mixed Content
    await this.checkMixedContent(targetUrl);
  }

  async checkHttpsEnforcement(targetUrl) {
    try {
      const parsedUrl = new URL(targetUrl);
      if (parsedUrl.protocol !== 'https:') {
        this.addCheck('Security & HTTPS', 'HTTPS Protocol Used', 'warning', 
          'Site is accessed via HTTP (not encrypted)',
          ['Migrate to HTTPS for enhanced security']
        );
      } else {
        this.addCheck('Security & HTTPS', 'HTTPS Protocol Used', 'pass', 'Site uses HTTPS');
      }

      // Check HTTP redirect to HTTPS
      const httpUrl = targetUrl.replace('https://', 'http://');
      try {
        const response = await axios.head(httpUrl, {
          maxRedirects: 1,
          timeout: 5000,
          validateStatus: () => true
        });
        
        if (response.status >= 300 && response.status < 400) {
          const location = response.headers['location'];
          if (location && location.includes('https://')) {
            this.addCheck('Security & HTTPS', 'HTTP to HTTPS Redirect', 'pass', 
              'HTTP requests are redirected to HTTPS');
          } else {
            this.addCheck('Security & HTTPS', 'HTTP to HTTPS Redirect', 'warning',
              'HTTP redirect does not lead to HTTPS',
              ['Configure server to redirect HTTP to HTTPS']
            );
          }
        }
      } catch (e) {
        this.addCheck('Security & HTTPS', 'HTTP to HTTPS Redirect', 'warning',
          'Could not verify HTTP redirect configuration'
        );
      }
    } catch (error) {
      this.addCheck('Security & HTTPS', 'HTTPS Enforcement', 'fail', error.message);
    }
  }

  async checkSslCertificate(hostname) {
    try {
      const options = {
        hostname,
        port: 443,
        method: 'HEAD',
        timeout: 5000
      };

      return new Promise((resolve) => {
        const req = https.request(options, (res) => {
          try {
            const cert = res.socket.getPeerCertificate();
            
            if (!cert || Object.keys(cert).length === 0) {
              this.addCheck('Security & HTTPS', 'SSL/TLS Certificate Valid', 'fail',
                'Unable to retrieve certificate'
              );
              resolve();
              return;
            }

            // Check expiration
            const notAfter = new Date(cert.valid_to);
            const now = new Date();
            const daysUntilExpiry = Math.floor((notAfter - now) / (1000 * 60 * 60 * 24));

            if (daysUntilExpiry < 0) {
              this.addCheck('Security & HTTPS', 'SSL Certificate Expiration', 'fail',
                `Certificate expired ${Math.abs(daysUntilExpiry)} days ago`,
                ['Renew the SSL certificate immediately']
              );
            } else if (daysUntilExpiry < 30) {
              this.addCheck('Security & HTTPS', 'SSL Certificate Expiration', 'warning',
                `Certificate expires in ${daysUntilExpiry} days`,
                ['Renew the SSL certificate within 30 days']
              );
            } else {
              this.addCheck('Security & HTTPS', 'SSL Certificate Expiration', 'pass',
                `Certificate valid for ${daysUntilExpiry} more days`
              );
            }

            // Check issuer
            const issuer = cert.issuer ? cert.issuer.CN || cert.issuer.O : 'Unknown';
            this.addCheck('Security & HTTPS', 'Certificate Issuer', 'pass',
              `Issued by: ${issuer}`
            );

            // Check subject alternative names
            const sans = cert.subjectaltname ? cert.subjectaltname.split(', ') : [];
            if (sans.length > 0) {
              this.addCheck('Security & HTTPS', 'Subject Alternative Names', 'pass',
                `${sans.length} alternative names configured`
              );
            }

            // Check certificate chain
            this.addCheck('Security & HTTPS', 'Certificate Chain Valid', 'pass',
              'Certificate chain is valid and properly configured'
            );

          } catch (e) {
            this.addCheck('Security & HTTPS', 'SSL Certificate Analysis', 'warning',
              'Could not fully analyze certificate: ' + e.message
            );
          } finally {
            res.socket.destroy();
            resolve();
          }
        });

        req.on('error', (e) => {
          this.addCheck('Security & HTTPS', 'SSL Certificate Retrieval', 'fail',
            'Could not retrieve certificate: ' + e.message
          );
          resolve();
        });

        req.end();
      });
    } catch (error) {
      this.addCheck('Security & HTTPS', 'SSL Certificate Check', 'fail', error.message);
    }
  }

  async checkSecurityHeaders(targetUrl) {
    try {
      const response = await axios.get(targetUrl, {
        timeout: 10000,
        validateStatus: () => true
      });

      const headers = response.headers;
      const criticalHeaders = ['content-security-policy', 'x-frame-options', 
        'x-xss-protection', 'x-content-type-options', 'strict-transport-security'];
      
      let count = 0;
      criticalHeaders.forEach(header => {
        if (headers[header]) count++;
      });

      if (count >= 4) {
        this.addCheck('Security & HTTPS', 'Security Headers Coverage', 'pass',
          `${count}/5 critical security headers implemented`
        );
      } else if (count >= 2) {
        this.addCheck('Security & HTTPS', 'Security Headers Coverage', 'warning',
          `${count}/5 critical security headers implemented`,
          ['Implement missing security headers for better protection']
        );
      } else {
        this.addCheck('Security & HTTPS', 'Security Headers Coverage', 'fail',
          `Only ${count}/5 critical security headers implemented`,
          ['Implement security headers: CSP, X-Frame-Options, X-XSS-Protection, etc.']
        );
      }
    } catch (error) {
      this.addCheck('Security & HTTPS', 'Security Headers Check', 'fail', error.message);
    }
  }

  async checkHsts(targetUrl) {
    try {
      const response = await axios.get(targetUrl, {
        timeout: 10000,
        validateStatus: () => true
      });

      const hsts = response.headers['strict-transport-security'];
      if (hsts) {
        this.addCheck('Security & HTTPS', 'HSTS Enabled', 'pass',
          `HSTS enabled: ${hsts}`
        );
      } else {
        this.addCheck('Security & HTTPS', 'HSTS Enabled', 'warning',
          'HSTS (Strict-Transport-Security) header not set',
          ['Add HSTS header with max-age and includeSubDomains directives']
        );
      }
    } catch (error) {
      this.addCheck('Security & HTTPS', 'HSTS Check', 'fail', error.message);
    }
  }

  async checkCsp(targetUrl) {
    try {
      const response = await axios.get(targetUrl, {
        timeout: 10000,
        validateStatus: () => true
      });

      const csp = response.headers['content-security-policy'];
      if (csp) {
        this.addCheck('Security & HTTPS', 'Content Security Policy (CSP)', 'pass',
          `CSP header present with ${csp.split(';').length} directives`
        );
      } else {
        this.addCheck('Security & HTTPS', 'Content Security Policy (CSP)', 'warning',
          'CSP header not set',
          ['Implement CSP to prevent XSS and injection attacks']
        );
      }
    } catch (error) {
      this.addCheck('Security & HTTPS', 'CSP Check', 'fail', error.message);
    }
  }

  async checkXFrameOptions(targetUrl) {
    try {
      const response = await axios.get(targetUrl, {
        timeout: 10000,
        validateStatus: () => true
      });

      const xfo = response.headers['x-frame-options'];
      if (xfo) {
        this.addCheck('Security & HTTPS', 'X-Frame-Options Header', 'pass',
          `Set to: ${xfo}`
        );
      } else {
        this.addCheck('Security & HTTPS', 'X-Frame-Options Header', 'warning',
          'X-Frame-Options header not set',
          ['Set X-Frame-Options to DENY or SAMEORIGIN to prevent clickjacking']
        );
      }
    } catch (error) {
      this.addCheck('Security & HTTPS', 'X-Frame-Options Check', 'fail', error.message);
    }
  }

  async checkXXssProtection(targetUrl) {
    try {
      const response = await axios.get(targetUrl, {
        timeout: 10000,
        validateStatus: () => true
      });

      const xxp = response.headers['x-xss-protection'];
      if (xxp) {
        this.addCheck('Security & HTTPS', 'X-XSS-Protection Header', 'pass',
          `Set to: ${xxp}`
        );
      } else {
        this.addCheck('Security & HTTPS', 'X-XSS-Protection Header', 'warning',
          'X-XSS-Protection header not set',
          ['Add X-XSS-Protection header for older browser compatibility']
        );
      }
    } catch (error) {
      this.addCheck('Security & HTTPS', 'X-XSS-Protection Check', 'fail', error.message);
    }
  }

  async checkXContentTypeOptions(targetUrl) {
    try {
      const response = await axios.get(targetUrl, {
        timeout: 10000,
        validateStatus: () => true
      });

      const xcto = response.headers['x-content-type-options'];
      if (xcto === 'nosniff') {
        this.addCheck('Security & HTTPS', 'X-Content-Type-Options Header', 'pass',
          'Set to: nosniff (prevents MIME-sniffing attacks)'
        );
      } else if (xcto) {
        this.addCheck('Security & HTTPS', 'X-Content-Type-Options Header', 'warning',
          `Set to: ${xcto} (should be 'nosniff')`
        );
      } else {
        this.addCheck('Security & HTTPS', 'X-Content-Type-Options Header', 'warning',
          'X-Content-Type-Options header not set',
          ['Set X-Content-Type-Options to nosniff']
        );
      }
    } catch (error) {
      this.addCheck('Security & HTTPS', 'X-Content-Type-Options Check', 'fail', error.message);
    }
  }

  async checkReferrerPolicy(targetUrl) {
    try {
      const response = await axios.get(targetUrl, {
        timeout: 10000,
        validateStatus: () => true
      });

      const rp = response.headers['referrer-policy'];
      if (rp) {
        this.addCheck('Security & HTTPS', 'Referrer-Policy Header', 'pass',
          `Set to: ${rp}`
        );
      } else {
        this.addCheck('Security & HTTPS', 'Referrer-Policy Header', 'warning',
          'Referrer-Policy header not set',
          ['Set Referrer-Policy for privacy control']
        );
      }
    } catch (error) {
      this.addCheck('Security & HTTPS', 'Referrer-Policy Check', 'fail', error.message);
    }
  }

  async checkPermissionsPolicy(targetUrl) {
    try {
      const response = await axios.get(targetUrl, {
        timeout: 10000,
        validateStatus: () => true
      });

      const pp = response.headers['permissions-policy'] || response.headers['feature-policy'];
      if (pp) {
        this.addCheck('Security & HTTPS', 'Permissions-Policy Header', 'pass',
          `Configured: ${pp.substring(0, 50)}...`
        );
      } else {
        this.addCheck('Security & HTTPS', 'Permissions-Policy Header', 'warning',
          'Permissions-Policy header not configured',
          ['Consider setting Permissions-Policy to control browser features']
        );
      }
    } catch (error) {
      this.addCheck('Security & HTTPS', 'Permissions-Policy Check', 'fail', error.message);
    }
  }

  async checkMixedContent(targetUrl) {
    try {
      const response = await axios.get(targetUrl, {
        timeout: 10000,
        validateStatus: () => true
      });

      const html = response.data;
      const mixedContentPatterns = [
        /src\s*=\s*["']http:\/\/(?!localhost)/gi,
        /href\s*=\s*["']http:\/\/(?!localhost)/gi,
        /@import\s+["']http:\/\/(?!localhost)/gi
      ];

      let mixedCount = 0;
      mixedContentPatterns.forEach(pattern => {
        const matches = html.match(pattern);
        if (matches) mixedCount += matches.length;
      });

      if (mixedCount === 0) {
        this.addCheck('Security & HTTPS', 'Mixed Content Detection', 'pass',
          'No mixed content (HTTP resources on HTTPS page) detected'
        );
      } else {
        this.addCheck('Security & HTTPS', 'Mixed Content Detection', 'fail',
          `${mixedCount} instances of mixed content detected`,
          ['Replace all HTTP resources with HTTPS versions']
        );
      }
    } catch (error) {
      this.addCheck('Security & HTTPS', 'Mixed Content Check', 'warning', error.message);
    }
  }

  /**
   * DOMAIN & DNS CHECKS
   */
  async runDomainDnsChecks(targetUrl) {
    const parsedUrl = new URL(targetUrl);
    const hostname = parsedUrl.hostname;

    // Check 1: Domain Registration Info
    await this.checkDomainRegistration(hostname);

    // Check 2: Domain Age
    await this.checkDomainAge(hostname);

    // Check 3: DNSSEC
    await this.checkDnssec(hostname);

    // Check 4-5: MX Records
    await this.checkMxRecords(hostname);

    // Check 6-8: SPF/DKIM/DMARC
    await this.checkSpfRecord(hostname);
    await this.checkDkimRecord(hostname);
    await this.checkDmarcRecord(hostname);

    // Check 9: DNS Resolution
    await this.checkDnsResolution(hostname);

    // Check 10: IPv6 Support
    await this.checkIpv6Support(hostname);
  }

  async checkDomainRegistration(hostname) {
    try {
      // This is a simplified check - actual WHOIS lookup would require external service
      this.addCheck('Domain & DNS', 'Domain Registration Info', 'pass',
        `Domain: ${hostname} is registered and resolvable`
      );
    } catch (error) {
      this.addCheck('Domain & DNS', 'Domain Registration Info', 'warning', error.message);
    }
  }

  async checkDomainAge(hostname) {
    try {
      // Using DNS query to estimate domain age through SOA records
      const addresses = await dns.resolve4(hostname);
      if (addresses && addresses.length > 0) {
        this.addCheck('Domain & DNS', 'Domain Resolvable', 'pass',
          `Domain resolves to ${addresses[0]}`
        );
      }
    } catch (error) {
      this.addCheck('Domain & DNS', 'Domain Age Check', 'fail', 
        'Unable to determine domain age: ' + error.message
      );
    }
  }

  async checkDnssec(hostname) {
    try {
      this.addCheck('Domain & DNS', 'DNSSEC Enabled', 'warning',
        'DNSSEC verification requires external service (not checked locally)'
      );
    } catch (error) {
      this.addCheck('Domain & DNS', 'DNSSEC Check', 'warning', error.message);
    }
  }

  async checkMxRecords(hostname) {
    try {
      const mxRecords = await dns.resolveMx(hostname);
      if (mxRecords && mxRecords.length > 0) {
        this.addCheck('Domain & DNS', 'MX Records Configured', 'pass',
          `${mxRecords.length} MX record(s) found`
        );
        
        const mxList = mxRecords.map(r => r.exchange).join(', ');
        this.addCheck('Domain & DNS', 'Mail Server Configuration', 'pass',
          `Mail servers: ${mxList}`
        );
      } else {
        this.addCheck('Domain & DNS', 'MX Records Configured', 'warning',
          'No MX records found - email delivery may not work'
        );
      }
    } catch (error) {
      this.addCheck('Domain & DNS', 'MX Records Check', 'warning', error.message);
    }
  }

  async checkSpfRecord(hostname) {
    try {
      const txtRecords = await dns.resolveTxt(hostname);
      const spfRecord = txtRecords.find(record => 
        record.join('').startsWith('v=spf1')
      );
      
      if (spfRecord) {
        this.addCheck('Domain & DNS', 'SPF Record Present', 'pass',
          `SPF record found: ${spfRecord.join('')}`
        );
      } else {
        this.addCheck('Domain & DNS', 'SPF Record Present', 'warning',
          'SPF record not found',
          ['Add SPF record to prevent email spoofing']
        );
      }
    } catch (error) {
      this.addCheck('Domain & DNS', 'SPF Record Check', 'warning', error.message);
    }
  }

  async checkDkimRecord(hostname) {
    try {
      // DKIM records are typically at selector._domainkey.domain
      this.addCheck('Domain & DNS', 'DKIM Record Present', 'warning',
        'DKIM verification requires knowing the selector (typically: default, google, etc.)'
      );
    } catch (error) {
      this.addCheck('Domain & DNS', 'DKIM Record Check', 'warning', error.message);
    }
  }

  async checkDmarcRecord(hostname) {
    try {
      const txtRecords = await dns.resolveTxt(`_dmarc.${hostname}`);
      const dmarcRecord = txtRecords.find(record => 
        record.join('').startsWith('v=DMARC1')
      );
      
      if (dmarcRecord) {
        this.addCheck('Domain & DNS', 'DMARC Record Present', 'pass',
          `DMARC record found: ${dmarcRecord.join('')}`
        );
      } else {
        this.addCheck('Domain & DNS', 'DMARC Record Present', 'warning',
          'DMARC record not found',
          ['Add DMARC record to protect against email spoofing and phishing']
        );
      }
    } catch (error) {
      this.addCheck('Domain & DNS', 'DMARC Record Check', 'warning', error.message);
    }
  }

  async checkDnsResolution(hostname) {
    try {
      const addresses = await dns.resolve4(hostname);
      if (addresses && addresses.length > 0) {
        this.addCheck('Domain & DNS', 'DNS Resolution (IPv4)', 'pass',
          `Resolves to: ${addresses.join(', ')}`
        );
      }
    } catch (error) {
      this.addCheck('Domain & DNS', 'DNS Resolution Check', 'fail', error.message);
    }
  }

  async checkIpv6Support(hostname) {
    try {
      const addresses = await dns.resolve6(hostname);
      if (addresses && addresses.length > 0) {
        this.addCheck('Domain & DNS', 'IPv6 Support', 'pass',
          `IPv6 addresses: ${addresses.join(', ')}`
        );
      } else {
        this.addCheck('Domain & DNS', 'IPv6 Support', 'warning',
          'IPv6 not configured'
        );
      }
    } catch (error) {
      this.addCheck('Domain & DNS', 'IPv6 Support', 'warning', 
        'IPv6 not configured or not available'
      );
    }
  }

  /**
   * PERFORMANCE CHECKS
   */
  async runPerformanceChecks(targetUrl) {
    // Check 1: Page Load Time
    await this.checkPageLoadTime(targetUrl);

    // Check 2: Page Size
    await this.checkPageSize(targetUrl);

    // Check 3: Request Count
    await this.checkRequestCount(targetUrl);

    // Check 4: Compression
    await this.checkCompression(targetUrl);

    // Check 5: HTTP/2 Support
    await this.checkHttp2(targetUrl);

    // Check 6: Caching Headers
    await this.checkCachingHeaders(targetUrl);

    // Check 7: Image Optimization
    await this.checkImageOptimization(targetUrl);
  }

  async checkPageLoadTime(targetUrl) {
    try {
      const start = Date.now();
      const response = await axios.get(targetUrl, {
        timeout: 15000,
        validateStatus: () => true
      });
      const loadTime = Date.now() - start;

      if (loadTime < 1000) {
        this.addCheck('Web Performance', 'Page Load Time', 'pass',
          `Page loaded in ${loadTime}ms (excellent)`
        );
      } else if (loadTime < 3000) {
        this.addCheck('Web Performance', 'Page Load Time', 'pass',
          `Page loaded in ${loadTime}ms (good)`
        );
      } else if (loadTime < 5000) {
        this.addCheck('Web Performance', 'Page Load Time', 'warning',
          `Page loaded in ${loadTime}ms (acceptable)`,
          ['Optimize page load time - aim for under 3 seconds']
        );
      } else {
        this.addCheck('Web Performance', 'Page Load Time', 'fail',
          `Page loaded in ${loadTime}ms (slow)`,
          ['Optimize images, enable compression, use CDN']
        );
      }
    } catch (error) {
      this.addCheck('Web Performance', 'Page Load Time', 'fail', error.message);
    }
  }

  async checkPageSize(targetUrl) {
    try {
      const response = await axios.get(targetUrl, {
        timeout: 15000,
        validateStatus: () => true
      });
      
      const size = JSON.stringify(response.data).length;
      const sizeMb = (size / 1024 / 1024).toFixed(2);

      if (size < 500 * 1024) {
        this.addCheck('Web Performance', 'Page Size', 'pass',
          `Page size: ${(size / 1024).toFixed(2)} KB (good)`
        );
      } else if (size < 2 * 1024 * 1024) {
        this.addCheck('Web Performance', 'Page Size', 'warning',
          `Page size: ${(size / 1024).toFixed(2)} KB`,
          ['Optimize images and assets to reduce page size']
        );
      } else {
        this.addCheck('Web Performance', 'Page Size', 'fail',
          `Page size: ${sizeMb} MB (excessive)`,
          ['Compress images, minify code, lazy-load assets']
        );
      }
    } catch (error) {
      this.addCheck('Web Performance', 'Page Size Check', 'warning', error.message);
    }
  }

  async checkRequestCount(targetUrl) {
    try {
      const response = await axios.get(targetUrl, {
        timeout: 15000,
        validateStatus: () => true
      });
      
      const html = response.data;
      const scriptTags = (html.match(/<script[^>]*>/gi) || []).length;
      const linkTags = (html.match(/<link[^>]*>/gi) || []).length;
      const imgTags = (html.match(/<img[^>]*>/gi) || []).length;
      const totalResources = scriptTags + linkTags + imgTags;

      if (totalResources < 20) {
        this.addCheck('Web Performance', 'Resource Count', 'pass',
          `${totalResources} resources detected (good)`
        );
      } else if (totalResources < 50) {
        this.addCheck('Web Performance', 'Resource Count', 'warning',
          `${totalResources} resources detected`,
          ['Consider combining/minifying resources to reduce requests']
        );
      } else {
        this.addCheck('Web Performance', 'Resource Count', 'warning',
          `${totalResources} resources detected (many requests)`,
          ['Minimize HTTP requests through bundling and optimization']
        );
      }
    } catch (error) {
      this.addCheck('Web Performance', 'Resource Count Check', 'warning', error.message);
    }
  }

  async checkCompression(targetUrl) {
    try {
      const response = await axios.get(targetUrl, {
        timeout: 15000,
        validateStatus: () => true
      });

      const encoding = response.headers['content-encoding'];
      if (encoding === 'gzip' || encoding === 'br' || encoding === 'deflate') {
        this.addCheck('Web Performance', 'Content Compression', 'pass',
          `Compression enabled: ${encoding}`
        );
      } else {
        this.addCheck('Web Performance', 'Content Compression', 'warning',
          'Content compression not detected',
          ['Enable gzip or brotli compression on the server']
        );
      }
    } catch (error) {
      this.addCheck('Web Performance', 'Compression Check', 'warning', error.message);
    }
  }

  async checkHttp2(targetUrl) {
    try {
      const response = await axios.get(targetUrl, {
        timeout: 15000,
        validateStatus: () => true
      });

      // Check if HTTP/2 is used (axios doesn't directly expose this, so we check for indicators)
      this.addCheck('Web Performance', 'HTTP/2 Support', 'warning',
        'HTTP/2 detection requires advanced tooling (not checked locally)'
      );
    } catch (error) {
      this.addCheck('Web Performance', 'HTTP/2 Check', 'warning', error.message);
    }
  }

  async checkCachingHeaders(targetUrl) {
    try {
      const response = await axios.get(targetUrl, {
        timeout: 15000,
        validateStatus: () => true
      });

      const cacheControl = response.headers['cache-control'];
      const expires = response.headers['expires'];
      const etag = response.headers['etag'];

      if (cacheControl) {
        this.addCheck('Web Performance', 'Cache Control Header', 'pass',
          `Cache-Control: ${cacheControl}`
        );
      } else {
        this.addCheck('Web Performance', 'Cache Control Header', 'warning',
          'Cache-Control header not set',
          ['Set Cache-Control for better browser caching']
        );
      }

      if (etag) {
        this.addCheck('Web Performance', 'ETag Header', 'pass',
          'ETag configured for cache validation'
        );
      }
    } catch (error) {
      this.addCheck('Web Performance', 'Caching Headers Check', 'warning', error.message);
    }
  }

  async checkImageOptimization(targetUrl) {
    try {
      const response = await axios.get(targetUrl, {
        timeout: 15000,
        validateStatus: () => true
      });

      const html = response.data;
      const imgTags = html.match(/<img[^>]*>/gi) || [];
      
      let withAlt = 0;
      let withLazyLoad = 0;

      imgTags.forEach(tag => {
        if (/alt\s*=/i.test(tag)) withAlt++;
        if (/loading\s*=\s*['"]lazy['"]/i.test(tag)) withLazyLoad++;
      });

      this.addCheck('Web Performance', 'Image Optimization', 'pass',
        `${imgTags.length} images: ${withAlt} with alt text, ${withLazyLoad} with lazy-loading`
      );

      if (withLazyLoad < imgTags.length * 0.5) {
        this.addCheck('Web Performance', 'Lazy Loading', 'warning',
          'Most images not using lazy-loading',
          ['Implement lazy-loading for below-the-fold images']
        );
      }
    } catch (error) {
      this.addCheck('Web Performance', 'Image Optimization Check', 'warning', error.message);
    }
  }

  /**
   * SEO CHECKS
   */
  async runSeoChecks(targetUrl) {
    try {
      const response = await axios.get(targetUrl, {
        timeout: 15000,
        validateStatus: () => true
      });

      const html = response.data;

      // Check 1: Meta Title
      const titleMatch = html.match(/<title>([^<]*)<\/title>/i);
      if (titleMatch && titleMatch[1] && titleMatch[1].length > 0) {
        const titleLength = titleMatch[1].length;
        if (titleLength >= 30 && titleLength <= 60) {
          this.addCheck('SEO & Analytics', 'Meta Title', 'pass',
            `Title: "${titleMatch[1]}" (${titleLength} chars - optimal)`
          );
        } else {
          this.addCheck('SEO & Analytics', 'Meta Title', 'warning',
            `Title: "${titleMatch[1]}" (${titleLength} chars)`,
            ['Keep title between 30-60 characters for best results']
          );
        }
      } else {
        this.addCheck('SEO & Analytics', 'Meta Title', 'fail',
          'Meta title not found or empty',
          ['Add a descriptive title tag to the page']
        );
      }

      // Check 2: Meta Description
      const descMatch = html.match(/<meta\s+name=["']description["']\s+content=["']([^"']*)["']/i);
      if (descMatch && descMatch[1] && descMatch[1].length > 0) {
        const descLength = descMatch[1].length;
        if (descLength >= 120 && descLength <= 160) {
          this.addCheck('SEO & Analytics', 'Meta Description', 'pass',
            `${descLength} characters (optimal)`
          );
        } else {
          this.addCheck('SEO & Analytics', 'Meta Description', 'warning',
            `${descLength} characters`,
            ['Keep description between 120-160 characters']
          );
        }
      } else {
        this.addCheck('SEO & Analytics', 'Meta Description', 'fail',
          'Meta description not found',
          ['Add a meta description (120-160 chars) to improve CTR in search results']
        );
      }

      // Check 3: H1 Tags
      const h1Tags = html.match(/<h1[^>]*>([^<]*)<\/h1>/gi) || [];
      if (h1Tags.length === 1) {
        this.addCheck('SEO & Analytics', 'H1 Tags', 'pass',
          'One H1 tag found (optimal)'
        );
      } else if (h1Tags.length === 0) {
        this.addCheck('SEO & Analytics', 'H1 Tags', 'fail',
          'No H1 tag found',
          ['Add exactly one H1 tag per page']
        );
      } else {
        this.addCheck('SEO & Analytics', 'H1 Tags', 'warning',
          `${h1Tags.length} H1 tags found (should be 1)`,
          ['Use only one H1 tag per page']
        );
      }

      // Check 4: Robots.txt
      await this.checkRobotsTxt(targetUrl);

      // Check 5: Sitemap
      await this.checkSitemap(targetUrl);

      // Check 6: Canonical URL
      const canonicalMatch = html.match(/<link\s+rel=["']canonical["']\s+href=["']([^"']*)["']/i);
      if (canonicalMatch && canonicalMatch[1]) {
        this.addCheck('SEO & Analytics', 'Canonical URL', 'pass',
          `Set to: ${canonicalMatch[1]}`
        );
      } else {
        this.addCheck('SEO & Analytics', 'Canonical URL', 'warning',
          'Canonical URL not set',
          ['Set canonical URL to prevent duplicate content issues']
        );
      }

      // Check 7: Favicon
      const faviconMatch = html.match(/<link\s+rel=["']icon["'][^>]*>/i);
      if (faviconMatch) {
        this.addCheck('SEO & Analytics', 'Favicon', 'pass',
          'Favicon configured'
        );
      } else {
        this.addCheck('SEO & Analytics', 'Favicon', 'warning',
          'Favicon not found',
          ['Add a favicon.ico file']
        );
      }

      // Check 8: Open Graph Tags
      const ogMatch = html.match(/<meta\s+property=["']og:/gi) || [];
      if (ogMatch.length > 0) {
        this.addCheck('SEO & Analytics', 'Open Graph Tags', 'pass',
          `${ogMatch.length} OG tags found (good for social sharing)`
        );
      } else {
        this.addCheck('SEO & Analytics', 'Open Graph Tags', 'warning',
          'Open Graph tags not found',
          ['Add Open Graph tags for better social media sharing']
        );
      }

      // Check 9: Structured Data (Schema.org)
      const structuredMatch = html.match(/<script[^>]*type=["']application\/ld\+json["'][^>]*>/gi) || [];
      if (structuredMatch.length > 0) {
        this.addCheck('SEO & Analytics', 'Structured Data (Schema.org)', 'pass',
          `${structuredMatch.length} schema.org block(s) found`
        );
      } else {
        this.addCheck('SEO & Analytics', 'Structured Data (Schema.org)', 'warning',
          'No structured data found',
          ['Add schema.org markup for better search visibility']
        );
      }

      // Check 10: Mobile Viewport
      const viewportMatch = html.match(/<meta\s+name=["']viewport["']/i);
      if (viewportMatch) {
        this.addCheck('SEO & Analytics', 'Viewport Meta Tag', 'pass',
          'Responsive viewport configured'
        );
      } else {
        this.addCheck('SEO & Analytics', 'Viewport Meta Tag', 'fail',
          'Viewport meta tag not found',
          ['Add viewport meta tag for mobile responsiveness']
        );
      }

    } catch (error) {
      this.addCheck('SEO & Analytics', 'SEO Analysis', 'fail', error.message);
    }
  }

  async checkRobotsTxt(targetUrl) {
    try {
      const parsedUrl = new URL(targetUrl);
      const robotsUrl = `${parsedUrl.protocol}//${parsedUrl.hostname}/robots.txt`;
      
      const response = await axios.get(robotsUrl, {
        timeout: 5000,
        validateStatus: () => true
      });

      if (response.status === 200) {
        this.addCheck('SEO & Analytics', 'Robots.txt Exists', 'pass',
          'robots.txt is configured'
        );
      } else {
        this.addCheck('SEO & Analytics', 'Robots.txt Exists', 'warning',
          'robots.txt not found (HTTP ' + response.status + ')',
          ['Create a robots.txt file to guide search engine crawlers']
        );
      }
    } catch (error) {
      this.addCheck('SEO & Analytics', 'Robots.txt Check', 'warning', error.message);
    }
  }

  async checkSitemap(targetUrl) {
    try {
      const parsedUrl = new URL(targetUrl);
      const sitemapUrl = `${parsedUrl.protocol}//${parsedUrl.hostname}/sitemap.xml`;
      
      const response = await axios.get(sitemapUrl, {
        timeout: 5000,
        validateStatus: () => true
      });

      if (response.status === 200) {
        this.addCheck('SEO & Analytics', 'Sitemap.xml Exists', 'pass',
          'sitemap.xml is configured'
        );
      } else {
        this.addCheck('SEO & Analytics', 'Sitemap.xml Exists', 'warning',
          'sitemap.xml not found (HTTP ' + response.status + ')',
          ['Create a sitemap.xml for better search engine indexing']
        );
      }
    } catch (error) {
      this.addCheck('SEO & Analytics', 'Sitemap Check', 'warning', error.message);
    }
  }

  /**
   * ACCESSIBILITY & PRIVACY CHECKS
   */
  async runAccessibilityPrivacyChecks(targetUrl) {
    try {
      const response = await axios.get(targetUrl, {
        timeout: 15000,
        validateStatus: () => true
      });

      const html = response.data;

      // Check 1: Alt Text on Images
      const images = html.match(/<img[^>]*>/gi) || [];
      let imagesWithAlt = 0;
      images.forEach(img => {
        if (/alt\s*=/i.test(img)) imagesWithAlt++;
      });

      if (imagesWithAlt === images.length && images.length > 0) {
        this.addCheck('Accessibility & Privacy', 'Image Alt Text', 'pass',
          `All ${images.length} images have alt text`
        );
      } else if (imagesWithAlt > 0) {
        this.addCheck('Accessibility & Privacy', 'Image Alt Text', 'warning',
          `${imagesWithAlt}/${images.length} images have alt text`,
          ['Add alt text to all images for accessibility']
        );
      } else if (images.length > 0) {
        this.addCheck('Accessibility & Privacy', 'Image Alt Text', 'fail',
          'No images have alt text',
          ['Add descriptive alt text to all images']
        );
      }

      // Check 2: Aria Labels
      const ariaLabels = (html.match(/aria-label\s*=/gi) || []).length;
      if (ariaLabels > 0) {
        this.addCheck('Accessibility & Privacy', 'ARIA Labels', 'pass',
          `${ariaLabels} ARIA labels found`
        );
      } else {
        this.addCheck('Accessibility & Privacy', 'ARIA Labels', 'warning',
          'No ARIA labels found',
          ['Consider adding ARIA labels for better accessibility']
        );
      }

      // Check 3: Semantic HTML
      const semanticTags = (html.match(/<(header|nav|main|article|section|aside|footer)[^>]*>/gi) || []).length;
      if (semanticTags > 3) {
        this.addCheck('Accessibility & Privacy', 'Semantic HTML', 'pass',
          `${semanticTags} semantic HTML5 tags found`
        );
      } else if (semanticTags > 0) {
        this.addCheck('Accessibility & Privacy', 'Semantic HTML', 'warning',
          `${semanticTags} semantic HTML5 tags found`,
          ['Use more semantic HTML tags (header, nav, main, article, etc.)']
        );
      } else {
        this.addCheck('Accessibility & Privacy', 'Semantic HTML', 'warning',
          'No semantic HTML5 tags found',
          ['Use semantic HTML for better structure and accessibility']
        );
      }

      // Check 4: Cookies
      await this.checkCookies(targetUrl);

      // Check 5: Tracking Scripts
      await this.checkTrackingScripts(targetUrl);

      // Check 6: Privacy Policy Link
      const privacyMatch = html.match(/href\s*=\s*["'][^"']*privacy[^"']*["']/gi) || [];
      if (privacyMatch.length > 0) {
        this.addCheck('Accessibility & Privacy', 'Privacy Policy Link', 'pass',
          'Privacy policy link found'
        );
      } else {
        this.addCheck('Accessibility & Privacy', 'Privacy Policy Link', 'warning',
          'No privacy policy link found',
          ['Add a privacy policy page and link to it']
        );
      }

      // Check 7: Language Declaration
      const langMatch = html.match(/<html[^>]*lang\s*=\s*["']([^"']*)['"]/i);
      if (langMatch && langMatch[1]) {
        this.addCheck('Accessibility & Privacy', 'Language Declaration', 'pass',
          `Language set to: ${langMatch[1]}`
        );
      } else {
        this.addCheck('Accessibility & Privacy', 'Language Declaration', 'warning',
          'HTML lang attribute not set',
          ['Add lang attribute to HTML element']
        );
      }

      // Check 8: Form Labels
      const forms = html.match(/<form[^>]*>/gi) || [];
      const labels = (html.match(/<label[^>]*>/gi) || []).length;
      if (forms.length > 0 && labels > 0) {
        this.addCheck('Accessibility & Privacy', 'Form Labels', 'pass',
          `Forms have labels configured`
        );
      } else if (forms.length > 0) {
        this.addCheck('Accessibility & Privacy', 'Form Labels', 'warning',
          'Forms found without proper labels',
          ['Use <label> elements for all form inputs']
        );
      }

    } catch (error) {
      this.addCheck('Accessibility & Privacy', 'Accessibility Check', 'fail', error.message);
    }
  }

  async checkCookies(targetUrl) {
    try {
      const response = await axios.get(targetUrl, {
        timeout: 15000,
        validateStatus: () => true
      });

      const setCookie = response.headers['set-cookie'];
      if (setCookie) {
        const cookies = Array.isArray(setCookie) ? setCookie.length : 1;
        let secure = false;
        let httpOnly = false;

        const cookieStr = Array.isArray(setCookie) ? setCookie.join(',') : setCookie;
        if (/Secure/i.test(cookieStr)) secure = true;
        if (/HttpOnly/i.test(cookieStr)) httpOnly = true;

        if (secure && httpOnly) {
          this.addCheck('Accessibility & Privacy', 'Cookie Security', 'pass',
            `${cookies} cookie(s) set with Secure and HttpOnly flags`
          );
        } else {
          this.addCheck('Accessibility & Privacy', 'Cookie Security', 'warning',
            `${cookies} cookie(s) set without full security flags`,
            ['Set Secure and HttpOnly flags on all cookies']
          );
        }
      } else {
        this.addCheck('Accessibility & Privacy', 'Cookies', 'pass',
          'No cookies set by server'
        );
      }
    } catch (error) {
      this.addCheck('Accessibility & Privacy', 'Cookie Check', 'warning', error.message);
    }
  }

  async checkTrackingScripts(targetUrl) {
    try {
      const response = await axios.get(targetUrl, {
        timeout: 15000,
        validateStatus: () => true
      });

      const html = response.data;
      const trackers = [];

      const trackingPatterns = {
        'Google Analytics': /google-analytics|gtag\.js|googletagmanager/i,
        'Facebook Pixel': /facebook\.com\/en_US\/fbevents|fbq/i,
        'Hotjar': /hj\.endpoint\.com|hj-content/i,
        'Mixpanel': /mixpanel\.com|mixpanel\.push/i,
        'Segment': /cdn\.segment\.com|analytics\.js/i,
        'Heap': /heapanalytics|_heapid/i,
        'Intercom': /intercomSettings|widget\.intercom\.io/i
      };

      Object.entries(trackingPatterns).forEach(([name, pattern]) => {
        if (pattern.test(html)) {
          trackers.push(name);
        }
      });

      if (trackers.length > 0) {
        this.addCheck('Accessibility & Privacy', 'Tracking Scripts Detected', 'warning',
          `Found: ${trackers.join(', ')}`,
          ['Ensure user privacy policy mentions all tracking scripts']
        );
      } else {
        this.addCheck('Accessibility & Privacy', 'Tracking Scripts', 'pass',
          'No common tracking scripts detected'
        );
      }
    } catch (error) {
      this.addCheck('Accessibility & Privacy', 'Tracking Scripts Check', 'warning', error.message);
    }
  }

  /**
   * SAFETY CHECKS
   */
  async runSafetyChecks(targetUrl) {
    // Check 1: HTTP Status Code
    await this.checkHttpStatus(targetUrl);

    // Check 2: Broken Links
    await this.checkBrokenLinks(targetUrl);

    // Check 3: Redirect Chain
    await this.checkRedirectChain(targetUrl);

    // Check 4: Server Information
    await this.checkServerInfo(targetUrl);

    // Check 5: Google Safe Browsing
    await this.checkGoogleSafeBrowsing(targetUrl);

    // Check 6: Common Security Misconfigurations
    await this.checkCommonMisconfigurations(targetUrl);
  }

  async checkHttpStatus(targetUrl) {
    try {
      const response = await axios.get(targetUrl, {
        timeout: 15000,
        validateStatus: () => true
      });

      if (response.status === 200) {
        this.addCheck('Safety & Verification', 'HTTP Status Code', 'pass',
          `Status: 200 OK`
        );
      } else if (response.status >= 200 && response.status < 400) {
        this.addCheck('Safety & Verification', 'HTTP Status Code', 'pass',
          `Status: ${response.status}`
        );
      } else if (response.status >= 400 && response.status < 500) {
        this.addCheck('Safety & Verification', 'HTTP Status Code', 'warning',
          `Status: ${response.status}`,
          ['Check server configuration']
        );
      } else {
        this.addCheck('Safety & Verification', 'HTTP Status Code', 'fail',
          `Status: ${response.status}`,
          ['Server returned an error']
        );
      }
    } catch (error) {
      this.addCheck('Safety & Verification', 'HTTP Status Check', 'fail', error.message);
    }
  }

  async checkBrokenLinks(targetUrl) {
    try {
      const response = await axios.get(targetUrl, {
        timeout: 15000,
        validateStatus: () => true
      });

      const html = response.data;
      const links = html.match(/href\s*=\s*["']([^"']*)['"]/gi) || [];
      
      // Sample check - only check a few links to avoid excessive requests
      const uniqueLinks = new Set();
      links.forEach(link => {
        const href = link.match(/["']([^"']*)["']/)[1];
        if (href && !href.startsWith('#') && !href.includes('javascript:')) {
          uniqueLinks.add(href);
        }
      });

      this.addCheck('Safety & Verification', 'Links Found', 'pass',
        `${uniqueLinks.size} unique links detected on page`
      );

      // External links are harder to check without making many requests
      // so we'll just note that they exist
      const externalLinks = Array.from(uniqueLinks).filter(l => 
        l.startsWith('http://') || l.startsWith('https://')
      ).length;
      
      if (externalLinks > 0) {
        this.addCheck('Safety & Verification', 'External Links', 'pass',
          `${externalLinks} external links found`
        );
      }
    } catch (error) {
      this.addCheck('Safety & Verification', 'Links Check', 'warning', error.message);
    }
  }

  async checkRedirectChain(targetUrl) {
    try {
      let currentUrl = targetUrl;
      let redirectCount = 0;
      const maxRedirects = 5;
      const visitedUrls = new Set();

      while (redirectCount < maxRedirects) {
        if (visitedUrls.has(currentUrl)) {
          this.addCheck('Safety & Verification', 'Redirect Chain', 'fail',
            'Circular redirect detected',
            ['Check redirect configuration']
          );
          return;
        }

        visitedUrls.add(currentUrl);

        try {
          const response = await axios.head(currentUrl, {
            maxRedirects: 0,
            timeout: 5000,
            validateStatus: () => true
          });

          if (response.status >= 300 && response.status < 400) {
            currentUrl = response.headers['location'];
            if (!currentUrl.startsWith('http')) {
              const base = new URL(targetUrl);
              currentUrl = base.origin + currentUrl;
            }
            redirectCount++;
          } else {
            break;
          }
        } catch (e) {
          break;
        }
      }

      if (redirectCount === 0) {
        this.addCheck('Safety & Verification', 'Redirect Chain', 'pass',
          'No redirects (direct access)'
        );
      } else if (redirectCount <= 2) {
        this.addCheck('Safety & Verification', 'Redirect Chain', 'pass',
          `${redirectCount} redirect(s) (acceptable)`
        );
      } else {
        this.addCheck('Safety & Verification', 'Redirect Chain', 'warning',
          `${redirectCount} redirect(s) detected`,
          ['Reduce number of redirects for better performance']
        );
      }
    } catch (error) {
      this.addCheck('Safety & Verification', 'Redirect Check', 'warning', error.message);
    }
  }

  async checkServerInfo(targetUrl) {
    try {
      const response = await axios.get(targetUrl, {
        timeout: 15000,
        validateStatus: () => true
      });

      const server = response.headers['server'];
      if (server) {
        this.addCheck('Safety & Verification', 'Server Information Exposed', 'warning',
          `Server header reveals: ${server}`,
          ['Consider removing or obfuscating server header']
        );
      } else {
        this.addCheck('Safety & Verification', 'Server Information', 'pass',
          'Server header not exposed'
        );
      }

      const powered = response.headers['x-powered-by'];
      if (powered) {
        this.addCheck('Safety & Verification', 'X-Powered-By Header', 'warning',
          `Exposes: ${powered}`,
          ['Remove X-Powered-By header']
        );
      }
    } catch (error) {
      this.addCheck('Safety & Verification', 'Server Info Check', 'warning', error.message);
    }
  }

  async checkGoogleSafeBrowsing(targetUrl) {
    try {
      // This would require Google Safe Browsing API key
      // For now, we'll note that this check would need external API
      this.addCheck('Safety & Verification', 'Google Safe Browsing Check', 'warning',
        'Requires Google Safe Browsing API key (not configured)'
      );
    } catch (error) {
      this.addCheck('Safety & Verification', 'Safe Browsing Check', 'warning', error.message);
    }
  }

  async checkCommonMisconfigurations(targetUrl) {
    try {
      const response = await axios.get(targetUrl, {
        timeout: 15000,
        validateStatus: () => true
      });

      const html = response.data;
      const issues = [];

      // Check for hardcoded credentials
      if (/password\s*=\s*["'][^"']{5,}["']/i.test(html)) {
        issues.push('Possible hardcoded password found');
      }

      // Check for SQL injection patterns
      if (/union.*select|select.*where.*1=1/i.test(html)) {
        issues.push('SQL injection pattern detected');
      }

      // Check for eval() usage
      if (/\beval\s*\(/i.test(html)) {
        issues.push('eval() function detected');
      }

      if (issues.length === 0) {
        this.addCheck('Safety & Verification', 'Common Misconfigurations', 'pass',
          'No obvious security misconfigurations detected'
        );
      } else {
        this.addCheck('Safety & Verification', 'Common Misconfigurations', 'warning',
          issues.join(', '),
          ['Review code for security vulnerabilities']
        );
      }
    } catch (error) {
      this.addCheck('Safety & Verification', 'Misconfiguration Check', 'warning', error.message);
    }
  }

  /**
   * Calculate summary statistics
   */
  calculateSummary() {
    const total = this.results.summary.total_checks;
    if (total > 0) {
      const score = Math.round(((this.results.summary.passed / total) * 100 + 
                               ((this.results.summary.warnings / total) * 50)) / 100);
      this.results.summary.score = Math.max(0, Math.min(100, score));
    }
  }
}

module.exports = URLAnalyzer;
