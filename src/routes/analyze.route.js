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

    // Run all checks in parallel for better performance
    const [security, dns, performance, seo, accessibility, safety] = await Promise.all([
      new SecurityCheck().analyze(validatedUrl),
      new DnsCheck().analyze(validatedUrl),
      new PerformanceCheck().analyze(validatedUrl),
      new SeoCheck().analyze(validatedUrl),
      new AccessibilityCheck().analyze(validatedUrl),
      new SafetyCheck().analyze(validatedUrl)
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

    // Calculate overall score
    const overallScore = calculateOverallScore(categories);
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
      categories
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
