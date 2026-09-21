/**
 * Score Calculation Utilities
 *
 * Single source of truth for how findings turn into points. Two axes:
 *  - SEVERITY_WEIGHTS: how many points a single check is worth, by severity.
 *  - CATEGORY_WEIGHTS: how much each category counts toward the overall score.
 *
 * Category scoring is deduction-based: each category starts at 100 points and
 * loses points for each failing/warning check, then is floored at
 * CATEGORY_SCORE_FLOOR. The floor exists specifically so that one or two
 * findings - even critical ones - can't read as "0/100, total failure" the
 * way a naive average could. A category can still legitimately show 0 when a
 * check explicitly overrides the score for a *confirmed* (not heuristic)
 * finding - e.g. safety.check.js sets Safety & Threats to exactly 0 only for
 * a high-confidence malware/phishing confirmation - but that is a deliberate,
 * narrow exception living in that check, not something this calculator does
 * on its own from ordinary point deductions.
 */

// How many points a single check is worth, by severity, and how much of that
// is deducted for a 'warn' vs a 'fail'. Change values here to retune scoring
// globally - nothing else in the codebase should hardcode point values.
const SEVERITY_WEIGHTS = {
  critical: { maxPoints: 35 },
  high: { maxPoints: 20 },
  medium: { maxPoints: 10 },
  low: { maxPoints: 5 },
  info: { maxPoints: 0 }
};

// Fraction of a check's maxPoints deducted for a 'warn' status (a 'fail'
// deducts the full maxPoints).
const WARN_DEDUCTION_RATIO = 0.5;

// A category's score is never allowed to read as lower than this from
// ordinary point deductions - see module doc comment above.
const CATEGORY_SCORE_FLOOR = 15;

// How much each category counts toward the overall score.
const CATEGORY_WEIGHTS = {
  'Security & HTTPS': 3,
  'Safety & Threats': 3,
  'DNS & Domain': 2,
  'Performance': 1.5,
  'SEO & Metadata': 1,
  'Accessibility (WCAG 2.1)': 1.5,
  'Link Analysis': 2,
  'External Links': 1.5,
  'WHOIS & Domain Info': 1
};

function severityConfigFor(severity) {
  return SEVERITY_WEIGHTS[severity] || SEVERITY_WEIGHTS.medium;
}

/**
 * How many points a single check is worth (maxPoints) and how many of those
 * points it actually cost (deducted), based on its severity and status.
 * 'fail' costs the full maxPoints, 'warn' costs half, 'pass'/'info' cost 0.
 */
function getCheckPoints(check) {
  const cfg = severityConfigFor(check.severity);
  const maxPoints = cfg.maxPoints;
  let deducted = 0;
  if (check.status === 'fail') {
    deducted = maxPoints;
  } else if (check.status === 'warn') {
    deducted = Math.round(maxPoints * WARN_DEDUCTION_RATIO);
  }
  return { maxPoints, deducted };
}

/**
 * Mutates each check in `checks` to add `maxPoints`, `pointsDeducted`, and a
 * default `confidence` ('medium') when the check didn't already set one.
 * Also adds `summary` as an alias of `description` for checks that don't yet
 * populate the newer structured-evidence fields, so the frontend's Score
 * Breakdown / evidence panel work uniformly across every category - not just
 * the ones that have been given full evidence support.
 * Returns the same array (for chaining), but callers should treat this as a
 * mutation of the objects passed in.
 */
function annotateCheckPoints(checks) {
  if (!Array.isArray(checks)) return checks;
  for (const check of checks) {
    if (!check || typeof check !== 'object') continue;
    if (check.status === 'error' || check.status === 'unavailable') {
      check.maxPoints = 0;
      check.pointsDeducted = 0;
    } else {
      const { maxPoints, deducted } = getCheckPoints(check);
      check.maxPoints = maxPoints;
      check.pointsDeducted = deducted;
    }
    if (!check.confidence) check.confidence = 'medium';
    if (!check.summary) check.summary = check.description;
  }
  return checks;
}

/**
 * Calculate score for a category based on its checks.
 * @param {Array} checks - Array of check results (should already have been
 *   passed through annotateCheckPoints, but this recomputes deductions
 *   defensively if not).
 * @returns {number|null} - Score 0-100 or null if no valid checks
 */
function calculateCategoryScore(checks) {
  if (!checks || checks.length === 0) return null;

  // Filter out checks that are purely informational-error or errored
  const scorableChecks = checks.filter(check =>
    check.status !== 'error' && check.status !== 'unavailable'
  );

  // If no scorable checks, return null (category should not contribute to overall)
  if (scorableChecks.length === 0) return null;

  let totalDeducted = 0;
  for (const check of scorableChecks) {
    const { deducted } = getCheckPoints(check);
    totalDeducted += deducted;
  }

  const raw = Math.round(100 - totalDeducted);
  return Math.max(CATEGORY_SCORE_FLOOR, Math.min(100, raw));
}

/**
 * Calculate overall score from all categories
 * Excludes unavailable categories and normalizes weights dynamically
 * @param {Array} categories - Array of category results
 * @returns {{ score: number, breakdown: object }}
 */
function calculateOverallScore(categories) {
  // Extra defensive checks
  if (!Array.isArray(categories) || categories.length === 0) {
    return {
      score: 0,
      breakdown: {
        includedCategories: 0,
        totalCategories: 0,
        excludedCategories: [],
        categoryScores: []
      }
    };
  }

  const excludedCategories = [];
  const categoryScores = [];
  let weightedSum = 0;
  let totalWeight = 0;

  categories.forEach(cat => {
    if (!cat || typeof cat !== 'object') {
      return;
    }

    const categoryName = cat.category || 'Unknown';

    // Skip categories that are unavailable or have null/undefined scores
    if (cat.status === 'unavailable' || cat.score === null || cat.score === undefined) {
      excludedCategories.push({
        name: categoryName,
        reason: cat.status === 'unavailable' ? 'Analysis unavailable' : 'No valid checks executed'
      });
      return;
    }

    // Check if all checks in the category failed/errored
    if (cat.checks && Array.isArray(cat.checks)) {
      const validChecks = cat.checks.filter(c => c.status !== 'error' && c.status !== 'unavailable');
      if (validChecks.length === 0) {
        excludedCategories.push({
          name: categoryName,
          reason: 'All checks failed or unavailable'
        });
        return;
      }
    }

    const weight = CATEGORY_WEIGHTS[categoryName] || 1;
    const score = typeof cat.score === 'number' ? cat.score : 0;

    weightedSum += score * weight;
    totalWeight += weight;

    categoryScores.push({
      name: categoryName,
      score: score,
      weight: weight,
      contribution: Math.round((score * weight) / (totalWeight || 1))
    });
  });

  const finalScore = totalWeight > 0 ? Math.round(weightedSum / totalWeight) : 0;

  return {
    score: finalScore,
    breakdown: {
      includedCategories: categoryScores.length,
      totalCategories: categories.length,
      excludedCategories,
      categoryScores,
      formula: 'Weighted average of category scores, weighted by category importance (see CATEGORY_WEIGHTS)'
    }
  };
}

function getScoreLabel(score) {
  if (score === null || score === undefined) return 'Not Analyzed';
  if (score >= 90) return 'Excellent';
  if (score >= 75) return 'Good';
  if (score >= 60) return 'Fair';
  if (score >= 45) return 'Poor';
  return 'Critical';
}

function getScoreColor(score) {
  if (score === null || score === undefined) return '#6b7280'; // gray
  if (score >= 90) return '#10b981'; // green
  if (score >= 75) return '#3b82f6'; // blue
  if (score >= 60) return '#f59e0b'; // amber
  if (score >= 45) return '#ef4444'; // red
  return '#dc2626'; // dark red
}

module.exports = {
  SEVERITY_WEIGHTS,
  CATEGORY_WEIGHTS,
  CATEGORY_SCORE_FLOOR,
  WARN_DEDUCTION_RATIO,
  getCheckPoints,
  annotateCheckPoints,
  calculateCategoryScore,
  calculateOverallScore,
  getScoreLabel,
  getScoreColor
};
