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

// Mapping of check names to their detail page URLs
const CHECK_DETAIL_PAGES = {
  // Safety & Threats checks (Critical)
  'Malware/Phishing Indicators': 'safety/malware-phishing.html',
  'SSL Certificate Status': 'safety/ssl-certificate.html',
  'Form Security': 'safety/form-security.html',
  'XSS (Cross-Site Scripting) Protection': 'safety/xss-protection.html',
  'External Scripts': 'safety/external-scripts.html',
  'Clickjacking Protection': 'safety/iframe-usage.html',
  'Mixed Content': 'safety/ssl-certificate.html',
  'Iframe Usage': 'safety/iframe-usage.html',
  
  // Security & HTTPS checks (Critical/High)
  'HTTPS Encryption': 'agents/security-agent.html',
  'Content Security Policy (CSP)': 'agents/security-agent.html',
  'TLS Protocol Version': 'agents/security-agent.html',
  'Redirect Scam Detection': 'agents/security-agent.html',
  
  // DNS & Domain checks (Important)
  'DNS Resolution': 'agents/dns-agent.html',
  'SPF Record (Email Security)': 'agents/dns-agent.html',
  'DMARC Record (Email Auth)': 'agents/dns-agent.html',
  
  // Performance checks
  'Page Load Time': 'agents/performance-agent.html',
  
  // SEO & Metadata checks
  'Page Title': 'agents/seo-agent.html',
  'Meta Description': 'agents/seo-agent.html',
  'Mobile Viewport': 'agents/seo-agent.html',
  
  // Accessibility checks
  'Page Language Declaration': 'agents/accessibility-agent.html',
  'Image Alt Text': 'agents/accessibility-agent.html',
  'Form Input Labels': 'agents/accessibility-agent.html'
};

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
    this.submitBtn = this.form.querySelector('button[type="submit"]');
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
    
    // Close modal
    const modal = document.getElementById('checkModal');
    const modalClose = document.querySelector('.modal-close');
    modalClose?.addEventListener('click', () => modal.style.display = 'none');
    modal?.addEventListener('click', (e) => {
      if (e.target === modal) modal.style.display = 'none';
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
    
    categories.forEach(category => {
      const card = this.createCategoryCard(category);
      this.categoriesGrid.appendChild(card);
    });

    // Show results section
    this.resultsSection.style.display = 'block';
    this.resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });

    // Reveal AI section if enabled
    this.toggleAIVisibility(true);
  }

  createCategoryCard(category) {
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
    
    card.innerHTML = `
      <div class="category-card-header">
        <div class="category-title">
          <h3>${category.category || 'Unknown'}</h3>
          <div class="category-score">${importantChecks.length} key checks · ${otherChecks.length} additional</div>
        </div>
        <div class="category-badge" style="background: ${scoreColor}">
          ${category.score}/100
        </div>
      </div>
      <div class="category-body">
        ${importantChecks.length > 0 ? `
          <div class="checks-section important-checks">
            <div class="section-label"><svg class="section-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg> Key Checks</div>
            <ul class="check-list">
              ${importantChecks.map(check => this.createCheckItem(check, true)).join('')}
            </ul>
          </div>
        ` : ''}
        ${otherChecks.length > 0 ? `
          <div class="checks-section other-checks ${importantChecks.length > 0 ? 'collapsed' : ''}">
            <div class="section-label section-label-toggle" onclick="this.parentElement.classList.toggle('collapsed')">
              <svg class="section-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/></svg> Additional Checks <span class="toggle-icon">▼</span>
            </div>
            <ul class="check-list">
              ${otherChecks.map(check => this.createCheckItem(check, false)).join('')}
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

  createCheckItem(check, isImportant = false) {
    const statusIcon = this.getStatusIcon(check.status);
    const detailPage = CHECK_DETAIL_PAGES[check.name];
    const hasDetailPage = !!detailPage;
    const showLearnMore = isImportant && hasDetailPage;
    
    // Store check data for the detail page
    const checkData = encodeURIComponent(JSON.stringify({
      name: check.name,
      status: check.status,
      description: check.description,
      url: this.analysisData?.url || ''
    }));
    
    if (showLearnMore) {
      return `
        <li class="check-item check-item-important">
          <div class="check-icon">${statusIcon}</div>
          <div class="check-details">
            <div class="check-name-row">
              <span class="check-name">${check.name}</span>
              <span class="importance-badge">Important</span>
            </div>
            <div class="check-description">${check.description}</div>
            <a href="${detailPage}?data=${checkData}" class="learn-more-btn" onclick="event.stopPropagation();">
              Learn More →
            </a>
          </div>
        </li>
      `;
    }
    
    return `
      <li class="check-item ${hasDetailPage ? 'check-item-clickable' : ''}" ${hasDetailPage ? `onclick="window.location.href='${detailPage}'"` : ''}>
        <div class="check-icon">${statusIcon}</div>
        <div class="check-details">
          <div class="check-name">${check.name}</div>
          <div class="check-description">${check.description}</div>
        </div>
      </li>
    `;
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
        const icon = this.getStatusIcon(check.status);
        report += `${icon} ${check.name}\n`;
        report += `   Status: ${check.status.toUpperCase()}\n`;
        report += `   ${check.description}\n\n`;
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
