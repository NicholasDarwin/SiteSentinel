const {
  calculateCategoryScore,
  calculateOverallScore,
  annotateCheckPoints,
  getCheckPoints,
  CATEGORY_SCORE_FLOOR
} = require('../score-calculator.util');

describe('getCheckPoints', () => {
  test('fail deducts the full severity weight', () => {
    expect(getCheckPoints({ status: 'fail', severity: 'critical' })).toEqual({ maxPoints: 35, deducted: 35 });
  });

  test('warn deducts half the severity weight', () => {
    expect(getCheckPoints({ status: 'warn', severity: 'high' })).toEqual({ maxPoints: 20, deducted: 10 });
  });

  test('pass and info deduct nothing', () => {
    expect(getCheckPoints({ status: 'pass', severity: 'critical' }).deducted).toBe(0);
    expect(getCheckPoints({ status: 'info', severity: 'critical' }).deducted).toBe(0);
  });
});

describe('calculateCategoryScore', () => {
  test('returns null for no checks', () => {
    expect(calculateCategoryScore([])).toBeNull();
    expect(calculateCategoryScore(null)).toBeNull();
  });

  test('a mostly-clean category scores close to 100', () => {
    const checks = [
      { status: 'pass', severity: 'critical' },
      { status: 'pass', severity: 'high' },
      { status: 'warn', severity: 'medium' },
      { status: 'pass', severity: 'low' }
    ];
    expect(calculateCategoryScore(checks)).toBe(95);
  });

  test('one or two findings never drop a category to 0 (floor applies)', () => {
    const checks = [
      { status: 'fail', severity: 'critical' },
      { status: 'fail', severity: 'critical' }
    ];
    const score = calculateCategoryScore(checks);
    expect(score).toBeGreaterThanOrEqual(CATEGORY_SCORE_FLOOR);
    expect(score).toBeGreaterThan(0);
  });

  test('an overwhelmingly bad category is floored, not literally 0', () => {
    const checks = Array.from({ length: 6 }, () => ({ status: 'fail', severity: 'critical' }));
    expect(calculateCategoryScore(checks)).toBe(CATEGORY_SCORE_FLOOR);
  });

  test('excludes error/unavailable checks from scoring', () => {
    const checks = [
      { status: 'error', severity: 'critical' },
      { status: 'unavailable', severity: 'critical' }
    ];
    expect(calculateCategoryScore(checks)).toBeNull();
  });
});

describe('annotateCheckPoints', () => {
  test('adds maxPoints/pointsDeducted/confidence/summary to every check', () => {
    const checks = [{ name: 'X', status: 'warn', severity: 'high', description: 'desc' }];
    annotateCheckPoints(checks);
    expect(checks[0].maxPoints).toBe(20);
    expect(checks[0].pointsDeducted).toBe(10);
    expect(checks[0].confidence).toBe('medium');
    expect(checks[0].summary).toBe('desc');
  });

  test('does not override an existing confidence value', () => {
    const checks = [{ status: 'pass', severity: 'low', confidence: 'high' }];
    annotateCheckPoints(checks);
    expect(checks[0].confidence).toBe('high');
  });

  test('zeroes points for error/unavailable checks', () => {
    const checks = [{ status: 'error', severity: 'critical' }];
    annotateCheckPoints(checks);
    expect(checks[0].maxPoints).toBe(0);
    expect(checks[0].pointsDeducted).toBe(0);
  });
});

describe('calculateOverallScore', () => {
  test('weights categories and excludes unavailable ones', () => {
    const categories = [
      { category: 'Security & HTTPS', score: 100, status: 'available' },
      { category: 'Safety & Threats', score: 50, status: 'available' },
      { category: 'SEO & Metadata', score: null, status: 'unavailable' }
    ];
    const result = calculateOverallScore(categories);
    expect(result.breakdown.includedCategories).toBe(2);
    expect(result.breakdown.excludedCategories).toHaveLength(1);
    // (100*3 + 50*3) / 6 = 75
    expect(result.score).toBe(75);
  });

  test('returns 0 for an empty category list', () => {
    expect(calculateOverallScore([]).score).toBe(0);
  });
});
