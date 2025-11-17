/**
 * AI Routes for Security & Safety Insights
 */

const express = require('express');
const axios = require('axios');
const router = express.Router();
const logger = require('../utils/logger.util');

const ENABLE_AI = String(process.env.ENABLE_AI || process.env.ENABLE_GPT5 || '0')
  .toLowerCase() === '1' || String(process.env.ENABLE_AI || '').toLowerCase() === 'true';

router.get('/enabled', (req, res) => {
  res.json({ enabled: ENABLE_AI });
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
    if (!process.env.OPENAI_API_KEY) {
      return res.status(500).json({ error: 'Missing OPENAI_API_KEY' });
    }

    const { report, question, url } = req.body || {};
    if (!report || typeof report !== 'object') {
      return res.status(400).json({ error: 'Missing or invalid report JSON' });
    }

    const systemPrompt = [
      'You are SiteSentinel AI Security Analyst.',
      'Given a website analysis report (security, DNS, performance, SEO, accessibility, safety),',
      'identify vulnerabilities and safety risks, explain impact, and propose prioritized fixes.',
      'Output strictly in this format:',
      '- Findings: bullet list of "issue -> impact -> fix"',
      '- Quick Checklist: 5-8 short prioritized actions',
      '- Risk Score: 0-100 (higher = safer)',
      'Keep concise, technical, and actionable. Avoid speculation beyond provided data.',
    ].join('\n');

    // Trim huge payloads defensively
    const safeReport = JSON.stringify(report);
    const limitedReport = safeReport.length > 120000 ? safeReport.slice(0, 120000) + '...<truncated>' : safeReport;

    const messages = [
      { role: 'system', content: systemPrompt },
      {
        role: 'user',
        content: `URL: ${url || report.url || 'unknown'}\nQuestion: ${question || 'What are the most critical vulnerabilities and safety risks and how do we fix them?'}\n\nReport JSON:\n${limitedReport}`
      }
    ];

    const resp = await axios.post(
      'https://api.openai.com/v1/chat/completions',
      {
        model: 'gpt-5',
        temperature: 0.2,
        messages
      },
      {
        timeout: 25000,
        headers: {
          Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
          'Content-Type': 'application/json'
        }
      }
    );

    const answer = resp?.data?.choices?.[0]?.message?.content?.trim() || 'No answer.';
    res.json({ answer });
  } catch (err) {
    logger.error('AI insights error:', err?.response?.data || err?.message || err);
    const detail = err?.response?.data || err?.message || 'Unknown error';
    res.status(502).json({ error: 'AI provider error', detail });
  }
});

module.exports = router;
