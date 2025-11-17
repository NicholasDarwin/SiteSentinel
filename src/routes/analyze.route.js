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
const { validateUrl } = require('../utils/validators.util');
const { calculateOverallScore, getScoreLabel, getScoreColor } = require('../utils/score-calculator.util');
const logger = require('../utils/logger.util');

/**
 * POST /api/analyze
 * Analyze a given URL across all security, performance, and quality metrics
 */
router.post('/analyze', async (req, res) => {
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
    const validatedUrl = validateUrl(url);
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
        const result = await checkFn;
        // Ensure result is valid
        if (!result || typeof result !== 'object' || !('score' in result)) {
          logger.warn(`${checkName} returned invalid result:`, result);
          return { category: checkName, icon: fallbackIcon, score: 0, checks: [{ name: 'Invalid Response', status: 'error', description: 'Check returned invalid data', severity: 'critical' }] };
        }
        return result;
      } catch (err) {
        logger.error(`${checkName} error:`, err);
        return { category: checkName, icon: fallbackIcon, score: 0, checks: [{ name: 'Error', status: 'error', description: String(err?.message || err || 'Unknown error'), severity: 'critical' }] };
      }
    };

    // Run all checks in parallel for better performance
    const [security, dns, performance, seo, accessibility, safety] = await Promise.all([
      safeCheck(new SecurityCheck().analyze(validatedUrl), 'Security & HTTPS', '🔒'),
      safeCheck(new DnsCheck().analyze(validatedUrl), 'DNS & Domain', '🌐'),
      safeCheck(new PerformanceCheck().analyze(validatedUrl), 'Performance', '⚡'),
      safeCheck(new SeoCheck().analyze(validatedUrl), 'SEO & Meta', '📱'),
      safeCheck(new AccessibilityCheck().analyze(validatedUrl), 'Accessibility', '♿'),
      safeCheck(new SafetyCheck().analyze(validatedUrl), 'Safety & Threats', '⚠️')
    ]);

    // Compile all categories
    const categories = [
      security,
      dns,
      performance,
      seo,
      accessibility,
      safety
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
    res.status(500).json({ 
      error: 'Analysis failed',
      details: error.message,
      success: false 
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
