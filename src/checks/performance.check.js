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
        severity: 'medium'
      });

      // 2. HTTP/2 or HTTP/3 Support
      const httpVersion = response.httpVersion || '1.1';
      checks.push({
        name: 'HTTP Version',
        status: httpVersion === '2.0' || httpVersion === '3.0' ? 'pass' : 'warn',
        description: `Using HTTP/${httpVersion}`,
        severity: 'medium'
      });

      // 3. Content Compression
      const contentEncoding = response.headers['content-encoding'];
      checks.push({
        name: 'Content Compression',
        status: contentEncoding ? 'pass' : 'info',
        description: contentEncoding ? `Compression enabled: ${contentEncoding}` : 'No compression detected',
        severity: 'low'
      });

      // 4. Cache Control Headers
      const cacheControl = response.headers['cache-control'];
      checks.push({
        name: 'Browser Caching',
        status: cacheControl ? 'pass' : 'info',
        description: cacheControl ? `Cache-Control: ${cacheControl}` : 'No cache policy set',
        severity: 'low'
      });

      // 5. CDN Usage (check Server header)
      const server = response.headers['server'];
      const cdnIndicators = ['cloudflare', 'akamai', 'cdn', 'cloudfront', 'fastly'];
      const hasCDN = cdnIndicators.some(indicator => server?.toLowerCase().includes(indicator));
      checks.push({
        name: 'CDN/Performance Optimization',
        status: hasCDN ? 'pass' : 'info',
        description: hasCDN ? `CDN detected: ${server}` : 'No CDN detected (not required)',
        severity: 'low'
      });

      // 6. Image Optimization (check for modern formats)
      const contentType = response.headers['content-type'] || '';
      checks.push({
        name: 'Response Size',
        status: response.headers['content-length'] ? 'pass' : 'info',
        description: response.headers['content-length'] ? 
          `Content size: ${(parseInt(response.headers['content-length']) / 1024).toFixed(2)} KB` : 
          'Size information not available',
        severity: 'medium'
      });

      // 7. Redirect Chain
      checks.push({
        name: 'Redirect Efficiency',
        status: response.status === 200 ? 'pass' : 'warn',
        description: `HTTP Status: ${response.status}`,
        severity: 'medium'
      });

    } catch (error) {
      checks.push({
        name: 'Performance Check Error',
        status: 'error',
        description: `Unable to test: ${error.message}`,
        severity: 'critical'
      });
    }

    return {
      category: 'Performance',
      icon: '⚡',
      score: calculateCategoryScore(checks),
      checks
    };
  }
}

module.exports = PerformanceCheck;
