/**
 * Performance Checks
 */

const axios = require('axios');
const { calculateCategoryScore } = require('../utils/score-calculator.util');

class PerformanceCheck {
  async analyze(url) {
    const checks = [];

    try {
      // 1. Page Load Time
      const startTime = Date.now();
      const response = await axios.get(url, { 
        timeout: 20000,
        validateStatus: () => true,
        maxRedirects: 5
      });
      const loadTime = Date.now() - startTime;

      checks.push({
        name: 'Page Load Time',
        status: loadTime < 3000 ? 'pass' : loadTime < 5000 ? 'warn' : 'fail',
        description: `Load time: ${loadTime}ms ${loadTime < 3000 ? '(Excellent)' : loadTime < 5000 ? '(Acceptable)' : '(Slow)'}`,
        severity: 'medium',
        explanation: 'Page load time directly impacts user experience. Sites should load in under 3 seconds for optimal engagement.'
      });

      // 2. HTTP/2 or HTTP/3 Support
      const httpVersion = response.httpVersion || '1.1';
      checks.push({
        name: 'HTTP Version',
        status: httpVersion === '2.0' || httpVersion === '3.0' ? 'pass' : 'info',
        description: `Using HTTP/${httpVersion}`,
        severity: 'medium',
        explanation: 'HTTP/2 and HTTP/3 provide faster page loads through multiplexing and improved compression.'
      });

      // 3. Content Compression
      const contentEncoding = response.headers['content-encoding'];
      checks.push({
        name: 'Content Compression',
        status: contentEncoding ? 'pass' : 'info',
        description: contentEncoding ? `Compression enabled: ${contentEncoding}` : 'No compression detected (may be applied at CDN level)',
        severity: 'low',
        explanation: 'Compression (gzip, brotli) reduces file sizes and improves load times.'
      });

      // 4. Cache Control Headers
      const cacheControl = response.headers['cache-control'];
      checks.push({
        name: 'Browser Caching',
        status: cacheControl ? 'pass' : 'info',
        description: cacheControl ? `Cache-Control: ${cacheControl}` : 'No cache policy set',
        severity: 'low',
        explanation: 'Browser caching allows repeat visitors to load pages faster by storing resources locally.'
      });

      // 5. CDN Usage (check Server header)
      const server = response.headers['server'] || '';
      const cdnIndicators = ['cloudflare', 'akamai', 'cdn', 'cloudfront', 'fastly', 'gws', 'vercel', 'netlify'];
      const hasCDN = cdnIndicators.some(indicator => server.toLowerCase().includes(indicator));
      
      // Also check via headers
      const cfRay = response.headers['cf-ray'];
      const xCache = response.headers['x-cache'];
      const viaCDN = cfRay || (xCache && xCache.toLowerCase().includes('hit'));
      
      checks.push({
        name: 'CDN/Performance Optimization',
        status: hasCDN || viaCDN ? 'pass' : 'info',
        description: hasCDN || viaCDN 
          ? `CDN detected${server ? `: ${server}` : ''}`
          : 'No CDN detected (optional for smaller sites)',
        severity: 'low',
        explanation: 'CDNs distribute content globally, reducing latency for users worldwide.'
      });

      // 6. Response Size
      const contentLength = response.headers['content-length'];
      const sizeKB = contentLength ? (parseInt(contentLength) / 1024).toFixed(2) : null;
      checks.push({
        name: 'Response Size',
        status: sizeKB && parseFloat(sizeKB) < 500 ? 'pass' : sizeKB ? 'info' : 'info',
        description: sizeKB 
          ? `HTML size: ${sizeKB} KB${parseFloat(sizeKB) > 500 ? ' (consider optimization)' : ''}` 
          : 'Size information not available (chunked transfer)',
        severity: 'medium',
        explanation: 'Smaller page sizes load faster, especially on mobile networks.'
      });

      // 7. Redirect Efficiency
      checks.push({
        name: 'Redirect Efficiency',
        status: response.status === 200 ? 'pass' : response.status >= 300 && response.status < 400 ? 'warn' : 'info',
        description: `HTTP Status: ${response.status}${response.status >= 300 && response.status < 400 ? ' (redirect occurred)' : ''}`,
        severity: 'medium',
        explanation: 'Redirects add latency. Direct responses (200) are faster than redirect chains.'
      });

      // 8. Keep-Alive
      const connection = response.headers['connection'];
      checks.push({
        name: 'Keep-Alive Connection',
        status: connection === 'keep-alive' || !connection ? 'pass' : 'info',
        description: connection === 'keep-alive' ? 'Keep-Alive enabled' : 'Connection reuse not detected',
        severity: 'low',
        explanation: 'Keep-Alive allows multiple requests over a single connection, reducing overhead.'
      });

    } catch (error) {
      checks.push({
        name: 'Performance Check Error',
        status: 'error',
        description: `Unable to test: ${error.message}`,
        severity: 'critical',
        explanation: 'Performance analysis could not be completed due to a connection error.'
      });
    }

    const score = calculateCategoryScore(checks);
    
    return {
      category: 'Performance',
      icon: 'zap',
      score: score,
      status: score === null ? 'unavailable' : 'available',
      checks
    };
  }
}

module.exports = PerformanceCheck;
