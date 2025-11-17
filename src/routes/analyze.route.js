/**
 * API Routes for URL Analysis
 */

const express = require('express');
const router = express.Router();
const SecurityCheck = require('../checks/security.check');
const DnsCheck = require('../checks/dns.check');
const PerformanceCheck = require('../checks/performance.check');
const SeoCheck = require('../checks/seo.check');
const AccessibilityCheck = require('../checks/accessibility.check');
const SafetyCheck = require('../checks/safety.check');
const LinkAnalysisCheck = require('../checks/link-analysis.check');
const { validateUrl } = require('../utils/validators.util');
const { calculateOverallScore, getScoreLabel, getScoreColor } = require('../utils/score-calculator.util');
const logger = require('../utils/logger.util');

/**
 * POST /api/analyze
 * Analyze a given URL across all security, performance, and quality metrics
 */
router.post('/analyze', async (req, res) => {
  let validatedUrl = null;
  try {
    const { url } = req.body;

    // Validate input
    if (!url || typeof url !== 'string') {
      return res.status(400).json({ 
        error: 'URL is required and must be a string',
        success: false 
      });
    }

    // Validate URL format
    validatedUrl = validateUrl(url);
    if (!validatedUrl) {
      return res.status(400).json({ 
        error: 'Invalid URL format. Please provide a valid HTTP or HTTPS URL.',
        success: false 
      });
    }

    logger.info(`Analyzing URL: ${validatedUrl}`);

    // Helper to safely wrap check execution
    const safeCheck = async (checkFn, checkName, fallbackIcon) => {
      try {
        logger.debug(`Starting check: ${checkName}`);
        const result = await checkFn;
        logger.debug(`Completed check: ${checkName}`, { score: result?.score });
        // Ensure result is valid
        if (!result || typeof result !== 'object' || !('score' in result)) {
          logger.warn(`${checkName} returned invalid result:`, result);
          return { category: checkName, icon: fallbackIcon, score: 0, checks: [{ name: 'Invalid Response', status: 'error', description: 'Check returned invalid data', severity: 'critical' }] };
        }
        return result;
      } catch (err) {
        logger.error(`${checkName} error:`, err?.message || String(err));
        return { category: checkName, icon: fallbackIcon, score: 0, checks: [{ name: 'Error', status: 'error', description: String(err?.message || err || 'Unknown error'), severity: 'critical' }] };
      }
    };

    logger.debug('Starting parallel checks execution');
    // Run all checks in parallel for better performance
    const [security, dns, performance, seo, accessibility, safety, linkAnalysis] = await Promise.all([
      safeCheck(new SecurityCheck().analyze(validatedUrl), 'Security & HTTPS', '🔒'),
      safeCheck(new DnsCheck().analyze(validatedUrl), 'DNS & Domain', '🌐'),
      safeCheck(new PerformanceCheck().analyze(validatedUrl), 'Performance', '⚡'),
      safeCheck(new SeoCheck().analyze(validatedUrl), 'SEO & Meta', '📱'),
      safeCheck(new AccessibilityCheck().analyze(validatedUrl), 'Accessibility', '♿'),
      safeCheck(new SafetyCheck().analyze(validatedUrl), 'Safety & Threats', '⚠️'),
      safeCheck(new LinkAnalysisCheck().analyze(validatedUrl), 'Link Analysis', '🔗')
    ]);
    logger.debug('All parallel checks completed');

    // Compile all categories
    const categories = [
      security,
      dns,
      performance,
      seo,
      accessibility,
      safety,
      linkAnalysis
    ];

    logger.info(`Categories received: ${categories.length}, Valid: ${categories.filter(c => c && 'score' in c).length}`);
    categories.forEach((cat, idx) => {
      logger.debug(`Category ${idx}:`, { hasScore: cat && 'score' in cat, type: typeof cat, keys: cat ? Object.keys(cat) : 'null' });
    });

    // Filter to only valid categories
    const validCategories = categories.filter(cat => cat && typeof cat === 'object' && 'score' in cat);

    // Ensure we have at least some categories
    if (validCategories.length === 0) {
      logger.error('No valid categories after filtering');
      return res.status(500).json({
        error: 'All analysis checks failed',
        success: false
      });
    }

    // Calculate overall score
    let overallScore = calculateOverallScore(validCategories);

    // If any category reports a confirmed malware detection, force overall score to 0
    const malwareDetected = validCategories.some(cat => cat && cat.malwareDetected === true);
    if (malwareDetected) {
      overallScore = 0;
    }

    // If link analysis detected suspicious redirects, significantly lower the score
    const suspiciousRedirects = validCategories.some(cat => cat && cat.suspiciousRedirectsDetected === true);
    if (suspiciousRedirects) {
      overallScore = Math.min(overallScore, 25); // Cap at 25/100 for suspicious redirects
    }

    const scoreLabel = getScoreLabel(overallScore);
    const scoreColor = getScoreColor(overallScore);

    const result = {
      success: true,
      url: validatedUrl,
      timestamp: new Date().toISOString(),
      overall: {
        score: overallScore,
        label: scoreLabel,
        color: scoreColor
      },
      categories: validCategories
    };

    logger.info(`Analysis completed for ${validatedUrl}. Score: ${overallScore}/${100}`);
    res.json(result);

  } catch (error) {
    logger.error('Analysis error', error);
    // Return a valid response structure even on error
    res.status(200).json({ 
      success: true,
      url: validatedUrl || 'unknown',
      timestamp: new Date().toISOString(),
      overall: {
        score: 0,
        label: 'Error',
        color: '#dc2626'
      },
      categories: [{
        category: 'Analysis Error',
        icon: '❌',
        score: 0,
        checks: [{
          name: 'Error',
          status: 'error',
          description: error.message || 'An unexpected error occurred during analysis',
          severity: 'critical'
        }]
      }]
    });
  }
});

/**
 * GET /api/health
 * Health check endpoint
 */
router.get('/health', (req, res) => {
  res.json({ 
    status: 'operational',
    timestamp: new Date().toISOString(),
    version: '2.0.0'
  });
});

module.exports = router;
