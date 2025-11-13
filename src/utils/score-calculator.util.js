/**
 * Score Calculation Utilities
 */

function calculateCategoryScore(checks) {
  if (!checks || checks.length === 0) return 0;
  
  let score = 0;
  checks.forEach(check => {
    if (check.status === 'pass') score += 100;
    else if (check.status === 'warn') score += 50;
    else if (check.status === 'info') score += 75;
    // 'fail' and 'error' contribute 0
  });
  
  return Math.round(score / checks.length);
}

function calculateOverallScore(categories) {
  const scores = categories.map(cat => cat.score);
  return Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
}

function getScoreLabel(score) {
  if (score >= 90) return 'Excellent';
  if (score >= 75) return 'Good';
  if (score >= 60) return 'Fair';
  if (score >= 45) return 'Poor';
  return 'Critical';
}

function getScoreColor(score) {
  if (score >= 90) return '#10b981'; // green
  if (score >= 75) return '#3b82f6'; // blue
  if (score >= 60) return '#f59e0b'; // amber
  if (score >= 45) return '#ef4444'; // red
  return '#dc2626'; // dark red
}

module.exports = {
  calculateCategoryScore,
  calculateOverallScore,
  getScoreLabel,
  getScoreColor
};
