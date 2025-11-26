/**
 * AI Routes for Security & Safety Insights
 * Uses Hugging Face Inference API (FREE)
 */

const express = require('express');
const axios = require('axios');
const router = express.Router();
const logger = require('../utils/logger.util');

const ENABLE_AI = String(process.env.ENABLE_AI || '0').toLowerCase() === '1' || 
                  String(process.env.ENABLE_AI || '').toLowerCase() === 'true';

router.get('/enabled', (req, res) => {
  res.json({ enabled: ENABLE_AI });
});

/**
 * POST /api/ai/quick-assessment
 * Body: { report: <SiteSentinel JSON>, url?: string }
 * Returns: { score: 0-100, message: string }
 */
router.post('/quick-assessment', async (req, res) => {
  try {
    if (!ENABLE_AI) {
      return res.status(403).json({ error: 'AI disabled on server' });
    }

    const { report, url } = req.body || {};
    if (!report || typeof report !== 'object') {
      return res.status(400).json({ error: 'Missing or invalid report JSON' });
    }

    // Simple rule-based assessment (no API needed)
    const overallScore = report.overall?.score || 0;
    const categories = report.categories || [];
    
    let criticalIssues = 0;
    let warnings = 0;
    let issuesList = [];
    
    categories.forEach(cat => {
      if (cat.checks) {
        cat.checks.forEach(check => {
          if (check.status === 'fail') {
            criticalIssues++;
            if (check.severity === 'critical') {
              issuesList.push(check.name);
            }
          } else if (check.status === 'warn') {
            warnings++;
          }
        });
      }
    });

    // Calculate AI score based on analysis
    let aiScore = overallScore;
    if (criticalIssues > 5) aiScore = Math.min(aiScore, 40);
    else if (criticalIssues > 2) aiScore = Math.min(aiScore, 60);
    
    // Generate message
    let message = '';
    if (aiScore >= 85) {
      message = `Excellent security posture with ${criticalIssues} critical issues and ${warnings} warnings. Site follows best practices.`;
    } else if (aiScore >= 70) {
      message = `Good security with ${criticalIssues} critical issues. Address: ${issuesList.slice(0, 2).join(', ') || 'minor warnings'}.`;
    } else if (aiScore >= 50) {
      message = `Moderate security concerns. ${criticalIssues} critical issues found including: ${issuesList.slice(0, 2).join(', ')}.`;
    } else {
      message = `Serious security risks detected. ${criticalIssues} critical issues require immediate attention: ${issuesList.slice(0, 3).join(', ')}.`;
    }

    res.json({ score: Math.round(aiScore), message });
  } catch (err) {
    logger.error('AI quick assessment error:', err?.message || err);
    res.json({ score: 50, message: 'AI assessment temporarily unavailable.' });
  }
});

/**
 * POST /api/ai/security-insights
 * Body: { report: <SiteSentinel JSON>, question?: string, url?: string }
 */
router.post('/security-insights', async (req, res) => {
  try {
    if (!ENABLE_AI) {
      return res.status(403).json({ error: 'AI disabled on server' });
    }

    const { report, question } = req.body || {};
    if (!report || typeof report !== 'object') {
      return res.status(400).json({ error: 'Missing or invalid report JSON' });
    }

    // Generate detailed insights from the report
    const categories = report.categories || [];
    let findings = [];
    let checklist = [];
    
    categories.forEach(cat => {
      if (cat.checks) {
        cat.checks.forEach(check => {
          if (check.status === 'fail' && check.severity === 'critical') {
            findings.push(`Critical: ${cat.category}: ${check.name} - ${check.description}`);
            checklist.push(`Fix ${check.name.toLowerCase()}`);
          } else if (check.status === 'warn') {
            findings.push(`Warning: ${cat.category}: ${check.name} - ${check.description}`);
          }
        });
      }
    });

    let answer = '## Security Analysis\n\n';
    answer += '### Critical Findings:\n';
    answer += findings.length > 0 ? findings.slice(0, 8).join('\n') : 'No critical issues found\n';
    answer += '\n\n### Priority Checklist:\n';
    if (checklist.length > 0) {
      checklist.slice(0, 6).forEach((item, i) => {
        answer += `${i + 1}. ${item}\n`;
      });
    } else {
      answer += 'All security checks passed\n';
    }
    answer += `\n### Overall Risk Score: ${report.overall?.score || 0}/100\n`;

    res.json({ answer });
  } catch (err) {
    logger.error('AI insights error:', err?.message || err);
    res.status(500).json({ error: 'AI insights error', detail: err.message });
  }
});

module.exports = router;
