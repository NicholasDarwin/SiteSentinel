/**
 * Score Calculation Utilities
 */

function calculateCategoryScore(checks) {
  if (!checks || checks.length === 0) return 0;
  
  let totalScore = 0;
  let totalWeight = 0;
  
  checks.forEach(check => {
    // Weight checks by severity: critical=3x, high=2x, medium=1x, low=0.5x
    const severityWeight = {
      'critical': 3,
      'high': 2,
      'medium': 1,
      'low': 0.5
    }[check.severity] || 1;
    
    let checkScore = 0;
    if (check.status === 'pass') checkScore = 100;
    else if (check.status === 'warn') checkScore = 60;
    else if (check.status === 'info') checkScore = 75;
    // 'fail' and 'error' contribute 0
    
    totalScore += checkScore * severityWeight;
    totalWeight += severityWeight;
  });
  
  return Math.round(totalScore / totalWeight);
}

function calculateOverallScore(categories) {
  // Filter out any undefined or null categories
  const validCategories = categories.filter(cat => cat && typeof cat === 'object' && 'score' in cat);
  if (validCategories.length === 0) return 0;
  const scores = validCategories.map(cat => cat.score || 0);
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
