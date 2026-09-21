// ─────────────────────────────────────────────────────────────
// SiteSentinel - Frontend Application
// ─────────────────────────────────────────────────────────────

// Important checks that get a "Learn More" button (critical/high severity)
const IMPORTANT_CHECKS = new Set([
  // Critical Security
  'HTTPS Encryption',
  'SSL Certificate Status',
  'Malware/Phishing Indicators',
  'Redirect Scam Detection',
  'Form Security',
  
  // High Priority Security
  'Content Security Policy (CSP)',
  'TLS Protocol Version',
  'XSS (Cross-Site Scripting) Protection',
  'External Scripts',
  'Clickjacking Protection',
  
  // Important DNS/Domain
  'DNS Resolution',
  'SPF Record (Email Security)',
  'DMARC Record (Email Auth)',
  
  // Key Performance
  'Page Load Time',
  
  // Essential SEO
  'Page Title',
  'Meta Description',
  'Mobile Viewport',
  
  // Core Accessibility  
  'Page Language Declaration',
  'Image Alt Text',
  'Form Input Labels'
]);

// ─────────────────────────────────────────────────────────────
// Scoring mirror - MUST stay in sync with src/utils/score-calculator.util.js.
// Duplicated here (rather than imported) because this is a static frontend
// with no build step. Used only to show "this check cost the category N
// points (category would be X/100 without it)" inside the evidence modal -
// the actual category/overall scores always come straight from the server.
// ─────────────────────────────────────────────────────────────
const SEVERITY_WEIGHTS = {
  critical: { maxPoints: 35 },
  high: { maxPoints: 20 },
  medium: { maxPoints: 10 },
  low: { maxPoints: 5 },
  info: { maxPoints: 0 }
};
const WARN_DEDUCTION_RATIO = 0.5;
const CATEGORY_SCORE_FLOOR = 15;

function getCheckPoints(check) {
  const cfg = SEVERITY_WEIGHTS[check.severity] || SEVERITY_WEIGHTS.medium;
  const maxPoints = cfg.maxPoints;
  let deducted = 0;
  if (check.status === 'fail') deducted = maxPoints;
  else if (check.status === 'warn') deducted = Math.round(maxPoints * WARN_DEDUCTION_RATIO);
  return { maxPoints, deducted };
}

function computeCategoryScore(checks) {
  const scorable = (checks || []).filter(c => c.status !== 'error' && c.status !== 'unavailable');
  if (scorable.length === 0) return null;
  let totalDeducted = 0;
  for (const c of scorable) totalDeducted += getCheckPoints(c).deducted;
  return Math.max(CATEGORY_SCORE_FLOOR, Math.min(100, Math.round(100 - totalDeducted)));
}

/** Escapes text for safe insertion into innerHTML. Evidence/description
 * content originates from arbitrary scanned websites, so anything from a
 * check object must be escaped before going into a template string. */
function escapeHtml(value) {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

class SiteSentinelApp {
  constructor() {
    this.form = document.getElementById('analysisForm');
    this.urlInput = document.getElementById('urlInput');
    this.resultsSection = document.getElementById('resultsSection');
    this.categoriesGrid = document.getElementById('categoriesGrid');
    this.overallScore = document.getElementById('overallScore');
    this.scoreLabel = document.getElementById('scoreLabel');
    this.analyzedUrl = document.getElementById('analyzedUrl');
    this.newAnalysisBtn = document.getElementById('newAnalysisBtn');
    this.exportBtn = document.getElementById('exportBtn');
    this.exportJsonBtn = document.getElementById('exportJsonBtn');
    this.submitBtn = this.form.querySelector('button[type="submit"]');
    // Evidence modal
    this.checkModal = document.getElementById('checkModal');
    this.modalBody = document.getElementById('modalBody');
    // AI elements
    this.aiSection = document.getElementById('aiSection');
    this.aiQuestion = document.getElementById('aiQuestion');
    this.aiAskBtn = document.getElementById('aiAskBtn');
    this.aiAnswer = document.getElementById('aiAnswer');
    // AI assessment elements
    this.aiAssessmentCard = document.getElementById('aiAssessmentCard');
    this.aiScore = document.getElementById('aiScore');
    this.aiMessage = document.getElementById('aiMessage');
    
    this.analysisData = null;
    this.bindEvents();
    this.setupAI();
  }

  bindEvents() {
    this.form.addEventListener('submit', (e) => this.handleSubmit(e));
    this.newAnalysisBtn?.addEventListener('click', () => this.resetForm());
    this.exportBtn?.addEventListener('click', () => this.exportReport());
    this.exportJsonBtn?.addEventListener('click', () => this.exportJson());

    // Close modal
    const modalClose = this.checkModal?.querySelector('.modal-close');
    modalClose?.addEventListener('click', () => this.closeCheckModal());
    this.checkModal?.addEventListener('click', (e) => {
      if (e.target === this.checkModal) this.closeCheckModal();
    });
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && this.checkModal?.style.display !== 'none') this.closeCheckModal();
    });
    // "Show all N" reveals the rest of a capped evidence list (already present
    // in the DOM, just hidden - see renderCheckModalContent).
    this.modalBody?.addEventListener('click', (e) => {
      const btn = e.target.closest('.evidence-show-all');
      if (!btn) return;
      btn.parentElement?.querySelectorAll('.evidence-extra').forEach(el => el.classList.remove('hidden'));
      btn.remove();
    });

    // Open the evidence modal for any check item, or toggle a category's score
    // breakdown - both are delegated from the grid since cards are re-rendered
    // on every analysis.
    this.categoriesGrid.addEventListener('click', (e) => {
      const breakdownToggle = e.target.closest('.score-breakdown-toggle');
      if (breakdownToggle) {
        breakdownToggle.closest('.category-card')?.querySelector('.score-breakdown')?.classList.toggle('collapsed');
        return;
      }
      const item = e.target.closest('.check-item[data-check-idx]');
      if (!item) return;
      const catIdx = parseInt(item.dataset.catIdx, 10);
      const checkIdx = parseInt(item.dataset.checkIdx, 10);
      this.openCheckModal(catIdx, checkIdx);
    });

    // AI quick prompts
    document.querySelectorAll('.aiQ').forEach(btn => {
      btn.addEventListener('click', () => {
        if (!this.analysisData) {
          this.aiAnswer && (this.aiAnswer.textContent = 'Run an analysis first.');
          return;
        }
        if (this.aiQuestion) this.aiQuestion.value = btn.dataset.q || '';
        this.askAI();
      });
    });

    // AI ask
    this.aiAskBtn?.addEventListener('click', () => this.askAI());
  }

  handleSubmit(e) {
    e.preventDefault();
    const url = this.urlInput.value.trim();

    if (!url) {
      alert('Please enter a valid URL');
      return;
    }

    this.analyzeUrl(url);
  }

  async analyzeUrl(url) {
    // Show loading state
    this.resultsSection.style.display = 'none';
    this.submitBtn.disabled = true;
    this.submitBtn.textContent = 'Analyzing...';
    const loadingOverlay = document.getElementById('loadingOverlay');
    if (loadingOverlay) loadingOverlay.style.display = 'flex';

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });

      let data;
      try {
        data = await response.json();
      } catch (e) {
        throw new Error(`Invalid JSON response from server: ${e.message}`);
      }

      if (!response.ok) {
        throw new Error(data.error || data.details || 'Analysis failed');
      }

      // Validate response structure
      if (!data || typeof data !== 'object') {
        throw new Error('Server returned invalid response format');
      }

      if (!data.success) {
        throw new Error(data.error || 'Analysis was not successful');
      }

      if (!data.overall || typeof data.overall.score === 'undefined') {
        console.error('Invalid response structure:', data);
        throw new Error('Server returned data without score');
      }

      this.analysisData = data;
      this.displayResults(data);
      
      // Get AI quick assessment if enabled
      if (this.aiCapable) {
        this.getAIAssessment(data);
      }
    } catch (error) {
      alert(`Error: ${error.message}`);
      console.error('Analysis error:', error);
    } finally {
      this.submitBtn.disabled = false;
      this.submitBtn.textContent = 'Analyze';
      if (loadingOverlay) loadingOverlay.style.display = 'none';
    }
  }

  displayResults(data) {
    // Comprehensive validation
    if (!data || typeof data !== 'object') {
      console.error('Invalid data type:', typeof data);
      alert('Invalid analysis response received (invalid type)');
      return;
    }
    
    if (!data.overall) {
      console.error('Missing overall object:', data);
      alert('Invalid analysis response received (missing overall)');
      return;
    }
    
    if (typeof data.overall.score !== 'number' || data.overall.score === undefined || data.overall.score === null) {
      console.error('Invalid score:', data.overall.score, typeof data.overall.score);
      alert('Invalid analysis response received (missing score)');
      return;
    }
    
    // Update overall score
    this.overallScore.textContent = data.overall.score;
    this.scoreLabel.textContent = data.overall.label || 'Unknown';

    // Credential Harvesting warning popup logic
    const credHarvestWarning = document.getElementById('credHarvestWarning');
    const credHarvestWarningText = document.getElementById('credHarvestWarningText');
    let showCredHarvest = false;
    let credHarvestMsg = '';
    // Find the Safety & Threats category and its Credential Harvesting check
    const safetyCat = (data.categories || []).find(cat => cat.category && cat.category.toLowerCase().includes('safety'));
    if (safetyCat && Array.isArray(safetyCat.checks)) {
      const credCheck = safetyCat.checks.find(c => c.name && c.name.toLowerCase().includes('credential harvesting'));
      // The backend marks the "known retail domain" case as a NOTICE inside the
      // description while keeping status 'pass' (so it doesn't drop the score).
      // Checking for a status that isn't 'fail' or 'pass' can never be true here -
      // that check always returns exactly one of those two - so match on the NOTICE
      // prefix instead.
      if (credCheck && credCheck.description && credCheck.description.startsWith('NOTICE:')) {
        showCredHarvest = true;
        credHarvestMsg = credCheck.description;
      }
    }
    if (showCredHarvest && credHarvestWarning && credHarvestWarningText) {
      credHarvestWarningText.textContent = credHarvestMsg;
      credHarvestWarning.style.display = 'block';
    } else if (credHarvestWarning) {
      credHarvestWarning.style.display = 'none';
    }

    // Apply color gradient to overall score circle
    const scoreColor = this.getScoreColor(data.overall.score);
    const scoreArc = document.getElementById('scoreArc');
    if (scoreArc) {
      scoreArc.style.stroke = scoreColor;
    }

    // Update URL
    this.analyzedUrl.textContent = data.url || 'Unknown';

    // Display categories
    this.categoriesGrid.innerHTML = '';

    const categories = data.categories || [];
    if (!Array.isArray(categories)) {
      console.error('Categories is not an array:', categories);
      alert('Invalid categories format');
      return;
    }

    categories.forEach((category, catIdx) => {
      const card = this.createCategoryCard(category, catIdx);
      this.categoriesGrid.appendChild(card);
    });

    // Show results section
    this.resultsSection.style.display = 'block';
    this.resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });

    // Reveal AI section if enabled
    this.toggleAIVisibility(true);
  }

  createCategoryCard(category, catIdx) {
    // Defensive checks
    if (!category || typeof category.score === 'undefined') {
      console.warn('Invalid category:', category);
      return document.createElement('div');
    }

    const card = document.createElement('div');
    card.className = 'category-card';

    const scoreColor = this.getScoreColor(category.score);
    let checks = category.checks || [];

    // Sort checks: important (critical/high) first, then by status (fail > warn > info > pass)
    const statusOrder = { fail: 0, error: 0, warn: 1, info: 2, pass: 3 };
    checks = [...checks].sort((a, b) => {
      const aImportant = IMPORTANT_CHECKS.has(a.name) ? 0 : 1;
      const bImportant = IMPORTANT_CHECKS.has(b.name) ? 0 : 1;
      if (aImportant !== bImportant) return aImportant - bImportant;
      return (statusOrder[a.status] || 3) - (statusOrder[b.status] || 3);
    });

    // Separate important and other checks
    const importantChecks = checks.filter(c => IMPORTANT_CHECKS.has(c.name));
    const otherChecks = checks.filter(c => !IMPORTANT_CHECKS.has(c.name));

    // Check if this is External Links category
    const isExternalLinks = category.category === 'External Links';
    const hasExternalLinks = isExternalLinks && category.scoredLinks && category.scoredLinks.length > 0;

    const categoryName = escapeHtml(category.category || 'Unknown');

    card.innerHTML = `
      <div class="category-card-header">
        <div class="category-title">
          <h3>${categoryName}</h3>
          <div class="category-score">${importantChecks.length} key checks · ${otherChecks.length} additional</div>
        </div>
        <div class="category-badge" style="background: ${scoreColor}">
          ${category.score}/100
        </div>
      </div>
      <div class="category-body">
        <button type="button" class="score-breakdown-toggle">Score breakdown <span class="toggle-icon">▾</span></button>
        ${this.renderScoreBreakdown(category)}
        ${importantChecks.length > 0 ? `
          <div class="checks-section important-checks">
            <div class="section-label"><svg class="section-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg> Key Checks</div>
            <ul class="check-list">
              ${importantChecks.map(check => this.createCheckItem(check, true, catIdx, category)).join('')}
            </ul>
          </div>
        ` : ''}
        ${otherChecks.length > 0 ? `
          <div class="checks-section other-checks ${importantChecks.length > 0 ? 'collapsed' : ''}">
            <div class="section-label section-label-toggle" onclick="this.parentElement.classList.toggle('collapsed')">
              <svg class="section-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/></svg> Additional Checks <span class="toggle-icon">▼</span>
            </div>
            <ul class="check-list">
              ${otherChecks.map(check => this.createCheckItem(check, false, catIdx, category)).join('')}
            </ul>
          </div>
        ` : ''}
        ${hasExternalLinks ? this.createExternalLinksSection(category.scoredLinks) : ''}
      </div>
    `;

    // Toggle expand/collapse
    card.querySelector('.category-card-header').addEventListener('click', () => {
      card.classList.toggle('expanded');
      card.querySelector('.category-body').style.display =
        card.classList.contains('expanded') ? 'block' : 'none';
    });

    // Set expanded by default
    card.classList.add('expanded');

    return card;
  }

  /**
   * Collapsible table listing every check in the category and exactly how
   * many points it added or removed, so it's possible to see precisely why
   * a category score dropped (or didn't).
   */
  renderScoreBreakdown(category) {
    const checks = category.checks || [];
    if (checks.length === 0) return '';

    const rows = checks.map(c => {
      const max = c.maxPoints || 0;
      const deducted = c.pointsDeducted || 0;
      const delta = deducted > 0 ? `−${deducted}` : (max > 0 ? '0' : '—');
      return `
        <tr class="score-breakdown-row">
          <td class="sb-check-name">${this.getStatusIcon(c.status)} ${escapeHtml(c.name)}</td>
          <td class="sb-status status-${escapeHtml(c.status)}">${escapeHtml((c.status || '').toUpperCase())}</td>
          <td class="sb-points">${delta}${max > 0 ? ` / ${max}` : ''}</td>
        </tr>
      `;
    }).join('');

    const totalMax = checks.reduce((s, c) => s + (c.maxPoints || 0), 0);
    const totalDeducted = checks.reduce((s, c) => s + (c.pointsDeducted || 0), 0);
    const rawScore = Math.round(100 - totalDeducted);
    const floorNote = rawScore < category.score
      ? `<p class="score-breakdown-note">A floor is applied so a small number of findings can't read as a total 0/100 - the raw deduction here would have put this category at ${Math.max(0, rawScore)}.</p>`
      : '';

    return `
      <div class="score-breakdown collapsed">
        <table class="score-breakdown-table">
          <thead><tr><th>Check</th><th>Status</th><th>Points</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
        <p class="score-breakdown-total">Total deducted: ${totalDeducted} pts from a 100-point baseline${totalMax ? ` (${totalMax} pts were at stake across ${checks.length} checks)` : ''} → ${category.score}/100</p>
        ${floorNote}
      </div>
    `;
  }

  createExternalLinksSection(externalLinks) {
    return `
      <div class="external-links-section">
        <h4>External Links Found (${externalLinks.length})</h4>
        <div class="external-links-list">
          ${externalLinks.map(link => `
            <div class="external-link-item ${this.getLinkStatusClass(link.status)}">
              <span class="link-icon">${this.getLinkStatusIcon(link.status)}</span>
              <a href="${link.url}" target="_blank" rel="noopener noreferrer" class="link-url-text">${this.truncateUrl(link.url)}</a>
              <div class="link-score-badge">
                ${link.score !== null ? `<span class="score-value" style="background: ${this.getScoreColor(link.score)}">${link.score}</span>` : '<span class="score-value not-scored">--</span>'}
                <span class="score-status">${link.status}</span>
              </div>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }

  getLinkStatusIcon(status) {
    const icons = {
      'Safe': '<svg class="status-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6L9 17l-5-5"/></svg>',
      'Warning': '<svg class="status-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>',
      'Unsafe': '<svg class="status-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>',
      'Broken': '<svg class="status-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6L6 18M6 6l12 12"/></svg>',
      'Unreachable': '<svg class="status-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M4.93 4.93l14.14 14.14"/></svg>',
      'Unknown': '<svg class="status-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 015.83 1c0 2-3 3-3 3m.08 4h.01"/></svg>',
      'Not Scored': '<svg class="status-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14"/></svg>'
    };
    return icons[status] || '<svg class="status-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/></svg>';
  }

  getLinkStatusClass(status) {
    return status.toLowerCase().replace(/\s+/g, '-');
  }

  truncateUrl(url) {
    try {
      const urlObj = new URL(url);
      const domain = urlObj.hostname;
      const path = urlObj.pathname + urlObj.search;
      if (path.length > 40) {
        return domain + path.substring(0, 40) + '...';
      }
      return domain + path;
    } catch {
      return url.length > 60 ? url.substring(0, 60) + '...' : url;
    }
  }

  createCheckItem(check, isImportant, catIdx, category) {
    const statusIcon = this.getStatusIcon(check.status);
    // Checks are rendered from a sorted copy of category.checks - look up the
    // original index so the click handler can find this exact check object
    // again via this.analysisData.categories[catIdx].checks[originalIdx].
    const originalIdx = (category.checks || []).indexOf(check);
    const name = escapeHtml(check.name);
    const description = escapeHtml(check.description);
    const pointsBadge = check.maxPoints > 0
      ? `<span class="points-badge status-${escapeHtml(check.status)}">${check.pointsDeducted > 0 ? '−' + check.pointsDeducted : '0'} pt${check.maxPoints === 1 ? '' : 's'}</span>`
      : '';

    if (isImportant) {
      return `
        <li class="check-item check-item-important" data-cat-idx="${catIdx}" data-check-idx="${originalIdx}">
          <div class="check-icon">${statusIcon}</div>
          <div class="check-details">
            <div class="check-name-row">
              <span class="check-name">${name}</span>
              <span class="importance-badge">Important</span>
              ${pointsBadge}
            </div>
            <div class="check-description">${description}</div>
            <span class="learn-more-btn">View evidence →</span>
          </div>
        </li>
      `;
    }

    return `
      <li class="check-item check-item-clickable" data-cat-idx="${catIdx}" data-check-idx="${originalIdx}">
        <div class="check-icon">${statusIcon}</div>
        <div class="check-details">
          <div class="check-name-row">
            <span class="check-name">${name}</span>
            ${pointsBadge}
          </div>
          <div class="check-description">${description}</div>
        </div>
      </li>
    `;
  }

  // ─────────────────────────────────────────────────────────────
  // Evidence modal
  // ─────────────────────────────────────────────────────────────

  openCheckModal(catIdx, checkIdx) {
    const category = this.analysisData?.categories?.[catIdx];
    const check = category?.checks?.[checkIdx];
    if (!this.checkModal || !this.modalBody || !category || !check) return;
    this.modalBody.innerHTML = this.renderCheckModalContent(check, category);
    this.checkModal.style.display = 'flex';
  }

  closeCheckModal() {
    if (this.checkModal) this.checkModal.style.display = 'none';
  }

  renderCheckModalContent(check, category) {
    const evidence = check.evidence || [];
    const visibleCount = 20;
    const confidence = check.confidence || 'medium';

    const otherChecks = (category.checks || []).filter(c => c !== check);
    const scoreWithout = computeCategoryScore(otherChecks);
    const scoreImpactLine = check.pointsDeducted > 0
      ? `<strong>−${check.pointsDeducted} of ${check.maxPoints} possible points</strong> from ${escapeHtml(category.category)}${scoreWithout !== null ? ` (category: ${scoreWithout} → ${category.score})` : ` (category: ${category.score}/100)`}`
      : `No points deducted from ${escapeHtml(category.category)} (category: ${category.score}/100)`;

    const evidenceHtml = evidence.length === 0
      ? '<p class="modal-empty-note">No structured evidence captured for this check.</p>'
      : `
        <div class="evidence-list">
          ${evidence.map((item, i) => `<div class="evidence-item${i >= visibleCount ? ' evidence-extra hidden' : ''}">${this.renderEvidenceItem(item)}</div>`).join('')}
        </div>
        ${evidence.length > visibleCount ? `<button type="button" class="btn btn-outline evidence-show-all">Show all ${evidence.length}</button>` : ''}
      `;

    const hasStructuredFields = check.method || evidence.length > 0 || check.risk || check.fix;

    return `
      <div class="modal-check-header">
        <span class="modal-check-icon status-${escapeHtml(check.status)}">${this.getStatusIcon(check.status)}</span>
        <div>
          <h2 class="modal-check-title">${escapeHtml(check.name)}</h2>
          <div class="modal-check-badges">
            <span class="modal-badge status-${escapeHtml(check.status)}">${escapeHtml((check.status || 'unknown').toUpperCase())}</span>
            <span class="modal-badge confidence-${escapeHtml(confidence)}">Confidence: ${escapeHtml(confidence)}</span>
          </div>
        </div>
      </div>

      <div class="modal-section">
        <h4>Score impact</h4>
        <p>${scoreImpactLine}</p>
      </div>

      <div class="modal-section">
        <h4>Verdict</h4>
        <p>${escapeHtml(check.description)}</p>
      </div>

      ${check.method ? `
        <div class="modal-section">
          <h4>What we checked</h4>
          <p>${escapeHtml(check.method)}</p>
        </div>
      ` : ''}

      <div class="modal-section">
        <h4>Evidence${evidence.length ? ` (${Math.min(visibleCount, evidence.length)} of ${evidence.length})` : ''}</h4>
        ${evidenceHtml}
      </div>

      ${check.risk ? `
        <div class="modal-section">
          <h4>Why this matters</h4>
          <p>${escapeHtml(check.risk)}</p>
        </div>
      ` : ''}

      ${check.fix ? `
        <div class="modal-section">
          <h4>How to fix</h4>
          ${check.fix.includes('\n') ? `<pre class="modal-fix-snippet">${escapeHtml(check.fix)}</pre>` : `<p>${escapeHtml(check.fix)}</p>`}
        </div>
      ` : ''}

      ${check.confidenceNote ? `
        <div class="modal-section modal-confidence-note">
          <h4>Possible false positive?</h4>
          <p>${escapeHtml(check.confidenceNote)}</p>
        </div>
      ` : ''}

      ${!hasStructuredFields ? `
        <p class="modal-empty-note">Detailed evidence isn't available for this check type yet - showing the summary and point impact only.</p>
      ` : ''}
    `;
  }

  renderEvidenceItem(item) {
    if (!item || !item.type) return `<pre class="evidence-snippet">${escapeHtml(JSON.stringify(item))}</pre>`;

    switch (item.type) {
      case 'headers': {
        const headers = item.headers || {};
        const keys = Object.keys(headers);
        const highlight = (item.highlightHeader || '').toLowerCase();
        const rows = keys.length
          ? keys.map(k => `<tr class="${k.toLowerCase() === highlight ? 'evidence-header-highlight' : ''}"><td>${escapeHtml(k)}</td><td>${escapeHtml(headers[k])}</td></tr>`).join('')
          : '<tr><td colspan="2">No headers captured</td></tr>';
        const missingNote = highlight && item.present === false
          ? `<p class="evidence-missing-header">Header "${escapeHtml(item.highlightHeader)}" is <strong>missing</strong> from the response.</p>`
          : '';
        const chain = (item.redirectChain || []).map(h => `${escapeHtml(h.url)} (${escapeHtml(h.status)})`).join(' → ');
        return `
          <div class="evidence-headers">
            <p class="evidence-meta">Final URL: <code>${escapeHtml(item.finalUrl)}</code> · Status: <code>${escapeHtml(item.statusCode)}</code></p>
            ${chain ? `<p class="evidence-meta">Redirects: ${chain}${item.finalUrl ? ` → ${escapeHtml(item.finalUrl)}` : ''}</p>` : ''}
            ${missingNote}
            <table class="evidence-headers-table"><tbody>${rows}</tbody></table>
          </div>
        `;
      }
      case 'dom':
        return `
          <div class="evidence-dom">
            ${item.label ? `<p class="evidence-meta">${escapeHtml(item.label)}</p>` : ''}
            <p class="evidence-meta">Selector: <code>${escapeHtml(item.selector)}</code>${item.line ? ` · Line ${escapeHtml(item.line)}, Col ${escapeHtml(item.column)}` : ''}</p>
            <pre class="evidence-snippet"><code>${escapeHtml(item.snippet)}</code></pre>
          </div>
        `;
      case 'pattern':
      case 'note':
        return `
          <div class="evidence-pattern">
            ${item.matchedRule ? `<p class="evidence-meta">Rule: ${escapeHtml(item.matchedRule)}</p>` : ''}
            ${item.matchedText ? `<p class="evidence-meta">Matched: <code>${escapeHtml(item.matchedText)}</code></p>` : ''}
            <pre class="evidence-snippet">${escapeHtml(item.context)}</pre>
          </div>
        `;
      case 'script':
        return `
          <div class="evidence-script">
            <p class="evidence-meta">
              ${item.isInline ? 'Inline script' : `<code>${escapeHtml(item.src)}</code>`}
              <span class="evidence-classification classification-${escapeHtml(item.classification)}">${escapeHtml(item.classification)}</span>
            </p>
            <p class="evidence-meta">${escapeHtml(item.classificationReason)}</p>
            ${!item.isInline ? `<p class="evidence-meta">async=${item.attributes?.async ? 'yes' : 'no'} · defer=${item.attributes?.defer ? 'yes' : 'no'} · integrity=${item.attributes?.integrity ? 'yes' : 'no'} · crossorigin=${escapeHtml(item.attributes?.crossorigin || 'none')}</p>` : ''}
            ${item.inlineSnippet ? `<pre class="evidence-snippet"><code>${escapeHtml(item.inlineSnippet)}</code></pre>` : ''}
          </div>
        `;
      case 'mixed-content':
        return `
          <div class="evidence-mixed">
            <p class="evidence-meta"><code>${escapeHtml(item.url)}</code></p>
            <p class="evidence-meta">Tag: &lt;${escapeHtml(item.tag)}&gt; attribute: ${escapeHtml(item.attribute)} · <span class="evidence-classification classification-${escapeHtml(item.activity)}">${escapeHtml(item.activity)}</span></p>
          </div>
        `;
      case 'link':
        return `
          <div class="evidence-link">
            <p class="evidence-meta"><a href="${escapeHtml(item.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(item.url)}</a></p>
            <p class="evidence-meta">Source: <span class="evidence-classification">${escapeHtml(item.sourceType)}</span>${item.sourceDetail ? ` — ${escapeHtml(item.sourceDetail)}` : ''}</p>
          </div>
        `;
      default:
        return `<pre class="evidence-snippet">${escapeHtml(JSON.stringify(item))}</pre>`;
    }
  }

  getStatusIcon(status) {
    const icons = {
      pass: '<svg class="status-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6L9 17l-5-5"/></svg>',
      warn: '<svg class="status-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>',
      info: '<svg class="status-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4m0-4h.01"/></svg>',
      fail: '<svg class="status-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6L6 18M6 6l12 12"/></svg>',
      error: '<svg class="status-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6m0-6l6 6"/></svg>'
    };
    return icons[status] || '•';
  }

  getScoreColor(score) {
    // Smooth gradient: green (75+) -> yellow (50-75) -> orange (25-50) -> red (0-25)
    if (score >= 75) {
      // Green: 75-100
      const ratio = (score - 75) / 25; // 0 to 1
      const r = Math.round(16 + ratio * 56); // #10 to #48
      const g = Math.round(184 + ratio * 16); // #b8 to #d0
      return `rgb(${r}, ${g}, 0)`;
    } else if (score >= 50) {
      // Green to Yellow: 50-75
      const ratio = (score - 50) / 25; // 0 to 1
      const r = Math.round(16 + ratio * 239); // #10 to #ff
      const g = Math.round(200 - ratio * 50); // #c8 to #78
      return `rgb(${r}, ${g}, 0)`;
    } else if (score >= 25) {
      // Yellow to Orange: 25-50
      const ratio = (score - 25) / 25; // 0 to 1
      const r = 255;
      const g = Math.round(165 - ratio * 10); // #a5 to #9b
      return `rgb(${r}, ${g}, 0)`;
    } else {
      // Orange to Red: 0-25
      return `rgb(255, ${Math.round(155 * (score / 25))}, 0)`;
    }
  }

  getScoreLabel(score) {
    if (score >= 90) return 'Excellent';
    if (score >= 75) return 'Good';
    if (score >= 60) return 'Fair';
    if (score >= 45) return 'Poor';
    return 'Critical';
  }

  resetForm() {
    this.urlInput.value = '';
    this.urlInput.focus();
    this.resultsSection.style.display = 'none';
    this.categoriesGrid.innerHTML = '';
    this.toggleAIVisibility(false);
    // Hide AI assessment
    if (this.aiAssessmentCard) {
      this.aiAssessmentCard.style.display = 'none';
    }
  }

  exportReport() {
    if (!this.analysisData) {
      alert('No analysis data to export');
      return;
    }

    const report = this.generateReport();
    const blob = new Blob([report], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SiteSentinel-Report-${new Date().toISOString().split('T')[0]}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  exportJson() {
    if (!this.analysisData) {
      alert('No analysis data to export');
      return;
    }

    const blob = new Blob([JSON.stringify(this.analysisData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SiteSentinel-Report-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  getStatusText(status) {
    const labels = { pass: '[PASS]', warn: '[WARN]', info: '[INFO]', fail: '[FAIL]', error: '[ERROR]' };
    return labels[status] || '[?]';
  }

  formatEvidenceForText(item) {
    if (!item) return '';
    switch (item.type) {
      case 'headers':
        return `[headers] finalUrl=${item.finalUrl} status=${item.statusCode}${item.highlightHeader ? ` | ${item.highlightHeader}=${item.present ? (item.headers?.[item.highlightHeader] || 'present') : 'MISSING'}` : ''}`;
      case 'dom':
        return `[dom] ${item.selector}${item.line ? ` (line ${item.line}, col ${item.column})` : ''}: ${item.snippet}`;
      case 'pattern':
      case 'note':
        return `[${item.type}] ${item.matchedRule ? item.matchedRule + ' | ' : ''}${item.matchedText ? `matched "${item.matchedText}" | ` : ''}context: ${item.context}`;
      case 'script':
        return `[script] ${item.isInline ? 'inline' : item.src} (${item.classification}: ${item.classificationReason})`;
      case 'mixed-content':
        return `[mixed-content] ${item.url} <${item.tag} ${item.attribute}> (${item.activity})`;
      case 'link':
        return `[link] ${item.url} (source: ${item.sourceType}${item.sourceDetail ? `, ${item.sourceDetail}` : ''})`;
      default:
        return JSON.stringify(item);
    }
  }

  generateReport() {
    const data = this.analysisData;
    let report = `
╔════════════════════════════════════════════════════════╗
║           SiteSentinel - Analysis Report               ║
╚════════════════════════════════════════════════════════╝

URL: ${data.url}
Analyzed: ${data.timestamp}
Overall Score: ${data.overall.score}/100 (${data.overall.label})

════════════════════════════════════════════════════════════

`;

    data.categories.forEach(category => {
      report += `\n${category.category} - ${category.score}/100\n`;
      report += '─'.repeat(60) + '\n\n';

      category.checks.forEach(check => {
        report += `${this.getStatusText(check.status)} ${check.name}\n`;
        let statusLine = `   Status: ${(check.status || '').toUpperCase()}`;
        if (check.maxPoints) statusLine += ` | Points: -${check.pointsDeducted || 0}/${check.maxPoints}`;
        if (check.confidence) statusLine += ` | Confidence: ${check.confidence}`;
        report += statusLine + '\n';
        report += `   ${check.description}\n`;
        if (check.method) report += `   Method: ${check.method}\n`;
        if (check.risk) report += `   Why it matters: ${check.risk}\n`;
        if (check.fix) report += `   Fix: ${check.fix.replace(/\n/g, '\n         ')}\n`;
        if (check.confidenceNote) report += `   Note: ${check.confidenceNote}\n`;
        if (check.evidence && check.evidence.length > 0) {
          report += `   Evidence (${check.evidence.length}):\n`;
          check.evidence.slice(0, 20).forEach((ev, i) => {
            report += `     ${i + 1}. ${this.formatEvidenceForText(ev)}\n`;
          });
          if (check.evidence.length > 20) report += `     ... and ${check.evidence.length - 20} more (see JSON export for the full list)\n`;
        }
        report += '\n';
      });
    });

    report += '\n════════════════════════════════════════════════════════════\n';
    report += 'Generated by SiteSentinel - https://github.com/NicholasDarwin/SiteSentinel\n';

    return report;
  }

  async setupAI() {
    try {
      const r = await fetch('/api/ai/enabled');
      const j = await r.json();
      const enabled = !!j?.enabled;
      // Only show after results to avoid clutter; remember capability
      this.aiCapable = enabled;
    } catch (e) {
      this.aiCapable = false;
    }
  }

  toggleAIVisibility(forceShow) {
    if (!this.aiSection) return;
    const show = !!this.aiCapable && !!forceShow;
    this.aiSection.style.display = show ? '' : 'none';
  }

  async askAI() {
    if (!this.analysisData) {
      this.aiAnswer && (this.aiAnswer.textContent = 'Run an analysis first.');
      return;
    }
    if (!this.aiCapable) {
      this.aiAnswer && (this.aiAnswer.textContent = 'AI is disabled on the server.');
      return;
    }
    const question = (this.aiQuestion?.value || '').trim();
    if (this.aiAnswer) this.aiAnswer.textContent = 'Thinking...';
    try {
      const r = await fetch('/api/ai/security-insights', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question, report: this.analysisData, url: this.analysisData?.url })
      });
      const j = await r.json();
      if (this.aiAnswer) this.aiAnswer.textContent = j?.answer || j?.error || 'No answer.';
    } catch (e) {
      if (this.aiAnswer) this.aiAnswer.textContent = 'Error contacting AI service.';
    }
  }

  async getAIAssessment(data) {
    if (!this.aiAssessmentCard || !this.aiCapable) return;
    
    // Show card with loading state
    this.aiAssessmentCard.style.display = 'block';
    if (this.aiScore) this.aiScore.textContent = '--';
    if (this.aiMessage) this.aiMessage.textContent = 'Analyzing security posture...';
    
    try {
      const r = await fetch('/api/ai/quick-assessment', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ report: data, url: data?.url })
      });
      const j = await r.json();
      
      if (j?.score !== undefined && j?.message) {
        if (this.aiScore) {
          this.aiScore.textContent = `${j.score}/100`;
          // Color based on score
          const color = this.getScoreColor(j.score);
          this.aiScore.style.color = color;
        }
        if (this.aiMessage) this.aiMessage.textContent = j.message;
      }
    } catch (e) {
      if (this.aiMessage) this.aiMessage.textContent = 'AI assessment unavailable.';
    }
  }
}

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  new SiteSentinelApp();
});
