/**
 * Score Calculation Utilities
 */

/**
 * Calculate score for a category based on its checks
 * @param {Array} checks - Array of check results
 * @returns {number|null} - Score 0-100 or null if no valid checks
 */
function calculateCategoryScore(checks) {
  if (!checks || checks.length === 0) return null;
  
  // Filter out checks that are purely informational or errored
  const scorableChecks = checks.filter(check => 
    check.status !== 'error' && check.status !== 'unavailable'
  );
  
  // If no scorable checks, return null (category should not contribute to overall)
  if (scorableChecks.length === 0) return null;
  
  let totalScore = 0;
  let totalWeight = 0;
  
  scorableChecks.forEach(check => {
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
    // 'fail' contributes 0
    
    totalScore += checkScore * severityWeight;
    totalWeight += severityWeight;
  });
  
  if (totalWeight === 0) return null;
  
  return Math.round(totalScore / totalWeight);
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
  
  // Category weights based on importance
  const categoryWeights = {
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
    
    const weight = categoryWeights[categoryName] || 1;
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
      formula: 'Weighted average based on category importance'
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
  calculateCategoryScore,
  calculateOverallScore,
  getScoreLabel,
  getScoreColor
};
