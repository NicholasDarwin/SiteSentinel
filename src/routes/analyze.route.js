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
const ExternalLinksCheck = require('../checks/external-links.check');
const WhoisCheck = require('../checks/whois.check');
const { validateUrl, getHostname } = require('../utils/validators.util');
const { calculateOverallScore, getScoreLabel, getScoreColor, annotateCheckPoints } = require('../utils/score-calculator.util');
const { assertHostnameIsSafe } = require('../utils/ssrf-guard.util');
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

    // SSRF pre-check: reject obviously-unsafe targets (localhost, private/link-local
    // IPs, cloud metadata addresses) before dispatching any of the 9 parallel
    // checks. This is defense-in-depth for the initial target - each check that
    // fetches over HTTP additionally re-validates every redirect hop it follows
    // (see http.util.js / ssrf-guard.util.js), since a malicious site could
    // otherwise redirect a check to an internal address after this point.
    //
    // IMPORTANT: only reject when the hostname resolves to a *blocked* address
    // (code ERR_SSRF_BLOCKED). A plain DNS lookup failure (unregistered domain,
    // temporary resolver issue, etc) is a completely different situation - that's
    // not a restricted destination, it's just an unreachable one, and each check
    // already handles that correctly on its own (reporting "unable to determine",
    // never "safe" - see safety.check.js). Treating a DNS failure as an SSRF block
    // here would incorrectly short-circuit the whole analysis before any check got
    // a chance to run and report that properly.
    try {
      await assertHostnameIsSafe(getHostname(validatedUrl));
    } catch (ssrfError) {
      if (ssrfError && ssrfError.code === 'ERR_SSRF_BLOCKED') {
        logger.warn(`Rejected SSRF-risky target: ${validatedUrl}`, { reason: ssrfError.message });
        return res.status(400).json({
          error: 'This URL cannot be analyzed: it resolves to a restricted or private network destination.',
          success: false
        });
      }
      // Any other error (DNS lookup failure, etc) - let the request proceed; the
      // individual checks will each attempt to fetch it and report accordingly.
      logger.debug(`SSRF pre-check lookup failed (not a block, proceeding): ${validatedUrl}`, { reason: ssrfError.message });
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
    const [security, dns, performance, seo, accessibility, safety, linkAnalysis, externalLinks, whois] = await Promise.all([
      safeCheck(new SecurityCheck().analyze(validatedUrl), 'Security & HTTPS', 'lock'),
      safeCheck(new DnsCheck().analyze(validatedUrl), 'DNS & Domain', 'globe'),
      safeCheck(new PerformanceCheck().analyze(validatedUrl), 'Performance', 'zap'),
      safeCheck(new SeoCheck().analyze(validatedUrl), 'SEO & Meta', 'bar-chart'),
      safeCheck(new AccessibilityCheck().analyze(validatedUrl), 'Accessibility', 'accessibility'),
      safeCheck(new SafetyCheck().analyze(validatedUrl), 'Safety & Threats', 'shield-alert'),
      safeCheck(new LinkAnalysisCheck().analyze(validatedUrl), 'Link Analysis', 'link'),
      safeCheck(new ExternalLinksCheck().analyze(validatedUrl), 'External Links', 'external-link'),
      safeCheck(new WhoisCheck().analyze(validatedUrl), 'WHOIS & Domain Info', 'file-text')
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
      linkAnalysis,
      externalLinks,
      whois
    ];

    logger.info(`Categories received: ${categories.length}, Valid: ${categories.filter(c => c && 'score' in c).length}`);
    categories.forEach((cat, idx) => {
      logger.debug(`Category ${idx}:`, { hasScore: cat && 'score' in cat, type: typeof cat, keys: cat ? Object.keys(cat) : 'null' });
    });

    // Filter to only valid categories (those that actually ran)
    const validCategories = categories.filter(cat => cat && typeof cat === 'object');

    // Annotate every check in every category with pointsDeducted/maxPoints (and a
    // default confidence/summary for checks that don't yet carry the newer
    // structured-evidence fields) so the Score Breakdown view and evidence panel
    // work consistently across all 9 categories, not just the ones that have been
    // given full evidence support.
    validCategories.forEach(cat => {
      if (cat && Array.isArray(cat.checks)) annotateCheckPoints(cat.checks);
    });

    // Ensure we have at least some categories
    if (validCategories.length === 0) {
      logger.error('No valid categories after filtering');
      return res.status(500).json({
        error: 'All analysis checks failed',
        success: false
      });
    }

    // Calculate overall score with breakdown
    const scoreResult = calculateOverallScore(validCategories);
    let overallScore = scoreResult.score;
    const scoreBreakdown = scoreResult.breakdown;

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

    // If most categories couldn't be analyzed at all (e.g. the target doesn't
    // resolve, or times out on every request), the numeric score - however it's
    // computed from the handful of categories that DID run (DNS/WHOIS lookups
    // don't require fetching the page itself, so they can "succeed" even when
    // the site is completely unreachable) - would misleadingly read as a normal
    // rating. Surface that plainly instead of letting an unreachable domain show
    // up as "Good". The raw score/breakdown are still included for reference.
    const includedCategories = scoreBreakdown.includedCategories;
    const totalCategoriesCount = scoreBreakdown.totalCategories;
    const unableToAnalyze = totalCategoriesCount > 0 && (includedCategories / totalCategoriesCount) < (1 / 3);

    const scoreLabel = unableToAnalyze ? 'Unable to Analyze' : getScoreLabel(overallScore);
    const scoreColor = unableToAnalyze ? '#6b7280' : getScoreColor(overallScore);

    const result = {
      success: true,
      url: validatedUrl,
      timestamp: new Date().toISOString(),
      overall: {
        score: overallScore,
        label: scoreLabel,
        color: scoreColor,
        unableToAnalyze,
        note: unableToAnalyze
          ? `Only ${includedCategories} of ${totalCategoriesCount} categories could be analyzed - the target was largely unreachable, so this score is not a meaningful security rating.`
          : undefined,
        breakdown: scoreBreakdown
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
        icon: 'alert-circle',
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
