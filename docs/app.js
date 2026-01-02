// ─────────────────────────────────────────────────────────────
// SiteSentinel - Frontend Application
// ─────────────────────────────────────────────────────────────

// Mapping of check names to their detail page URLs
const CHECK_DETAIL_PAGES = {
  // Safety & Threats checks
  'Malware/Phishing Indicators': 'safety/malware-phishing.html',
  'SSL Certificate Status': 'safety/ssl-certificate.html',
  'Form Security': 'safety/form-security.html',
  'Outdated Software Detection': 'safety/outdated-software.html',
  'SQL Injection Protection': 'safety/sql-injection.html',
  'XSS (Cross-Site Scripting) Protection': 'safety/xss-protection.html',
  'Iframe Usage': 'safety/iframe-usage.html',
  'External Scripts': 'safety/external-scripts.html',
  'Rate Limiting / Bot Protection': 'safety/rate-limiting.html',
  'Domain Registrar Status': 'safety/domain-registrar.html',
  
  // Security & HTTPS checks
  'HTTPS Encryption': 'agents/security-agent.html',
  'HSTS Header': 'agents/security-agent.html',
  'Content Security Policy (CSP)': 'agents/security-agent.html',
  'X-Frame-Options Header': 'agents/security-agent.html',
  'X-Content-Type-Options': 'agents/security-agent.html',
  'Referrer-Policy': 'agents/security-agent.html',
  'Permissions-Policy': 'agents/security-agent.html',
  'TLS Protocol Version': 'agents/security-agent.html',
  'Redirect Scam Detection': 'agents/security-agent.html',
  
  // DNS & Domain checks
  'DNS Resolution': 'agents/dns-agent.html',
  'IPv6 Support': 'agents/dns-agent.html',
  'MX Records (Email)': 'agents/dns-agent.html',
  'SPF Record (Email Security)': 'agents/dns-agent.html',
  'DMARC Record (Email Auth)': 'agents/dns-agent.html',
  'DNSSEC': 'agents/dns-agent.html',
  
  // Performance checks
  'Page Load Time': 'agents/performance-agent.html',
  'HTTP Version': 'agents/performance-agent.html',
  'Content Compression': 'agents/performance-agent.html',
  'Browser Caching': 'agents/performance-agent.html',
  'CDN/Performance Optimization': 'agents/performance-agent.html',
  'Response Size': 'agents/performance-agent.html',
  'Redirect Efficiency': 'agents/performance-agent.html',
  
  // SEO & Metadata checks
  'Page Title': 'agents/seo-agent.html',
  'Meta Description': 'agents/seo-agent.html',
  'H1 Tag Structure': 'agents/seo-agent.html',
  'Robots Meta Tag': 'agents/seo-agent.html',
  'Canonical Tag': 'agents/seo-agent.html',
  'Open Graph Tags': 'agents/seo-agent.html',
  'Structured Data (Schema.org)': 'agents/seo-agent.html',
  'Mobile Viewport': 'agents/seo-agent.html',
  'Image Alt Attributes': 'agents/seo-agent.html',
  'Favicon': 'agents/seo-agent.html',
  'Deep Link Discovery': 'agents/seo-agent.html',
  
  // Accessibility checks
  'Page Language Declaration': 'agents/accessibility-agent.html',
  'Image Alt Text': 'agents/accessibility-agent.html',
  'Form Input Labels': 'agents/accessibility-agent.html',
  'Heading Hierarchy (H1-H6)': 'agents/accessibility-agent.html',
  'Color Contrast Ratio': 'agents/accessibility-agent.html',
  'Keyboard Navigation': 'agents/accessibility-agent.html',
  'ARIA Labels & Roles': 'agents/accessibility-agent.html',
  'Skip to Main Content Link': 'agents/accessibility-agent.html',
  'Link Text Quality': 'agents/accessibility-agent.html',
  'Text Readability': 'agents/accessibility-agent.html',
  
  // External Links checks
  'External Links Found': 'agents/external-links-agent.html',
  'Redirect Links': 'agents/external-links-agent.html',
  'Suspicious External Redirects': 'agents/external-links-agent.html',
  'External Link Density': 'agents/external-links-agent.html',
  'External Links Detected': 'agents/external-links-agent.html',
  'External Domains': 'agents/external-links-agent.html',
  
  // WHOIS checks
  'Domain Registration': 'agents/whois-agent.html',
  'Registrar': 'agents/whois-agent.html',
  'Domain Age': 'agents/whois-agent.html',
  'Domain Expiration': 'agents/whois-agent.html',
  'Name Servers': 'agents/whois-agent.html'
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
    const checks = category.checks || [];
    
    // Check if this is External Links category
    const isExternalLinks = category.category === 'External Links';
    const hasExternalLinks = isExternalLinks && category.scoredLinks && category.scoredLinks.length > 0;
    
    card.innerHTML = `
      <div class="category-card-header">
        <div class="category-title">
          <h3>${category.category || 'Unknown'}</h3>
          <div class="category-score">${checks.length} checks</div>
        </div>
        <div class="category-badge" style="background: ${scoreColor}">
          ${category.score}/100
        </div>
      </div>
      <div class="category-body">
        <ul class="check-list">
          ${category.checks.map(check => this.createCheckItem(check)).join('')}
        </ul>
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
      'Safe': '✅',
      'Warning': '⚠️',
      'Unsafe': '🚨',
      'Broken': '❌',
      'Unreachable': '⛔',
      'Unknown': '❓',
      'Not Scored': '➖'
    };
    return icons[status] || '🔗';
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

  createCheckItem(check) {
    const statusIcon = this.getStatusIcon(check.status);
    const detailPage = CHECK_DETAIL_PAGES[check.name];
    const hasDetailPage = !!detailPage;
    
    if (hasDetailPage) {
      return `
        <li class="check-item check-item-clickable" onclick="window.location.href='${detailPage}'" title="Click to learn more about this check">
          <div class="check-icon">${statusIcon}</div>
          <div class="check-details">
            <div class="check-name">${check.name} <span class="check-arrow">→</span></div>
            <div class="check-description">${check.description}</div>
          </div>
        </li>
      `;
    }
    
    return `
      <li class="check-item">
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
      pass: '✅',
      warn: '⚠️',
      info: 'ℹ️',
      fail: '❌',
      error: '🔴'
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
