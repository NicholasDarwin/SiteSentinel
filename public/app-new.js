// ─────────────────────────────────────────────────────────────
// SiteSentinel - Frontend Application
// ─────────────────────────────────────────────────────────────

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
    
    this.analysisData = null;
    this.bindEvents();
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
    this.submitBtn.querySelector('.btn-text').style.display = 'none';
    this.submitBtn.querySelector('.btn-loading').style.display = 'inline';

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Analysis failed');
      }

      const data = await response.json();
      this.analysisData = data;
      this.displayResults(data);
    } catch (error) {
      alert(`Error: ${error.message}`);
      console.error('Analysis error:', error);
    } finally {
      this.submitBtn.disabled = false;
      this.submitBtn.querySelector('.btn-text').style.display = 'inline';
      this.submitBtn.querySelector('.btn-loading').style.display = 'none';
    }
  }

  displayResults(data) {
    // Update overall score
    this.overallScore.textContent = data.overall.score;
    this.scoreLabel.textContent = data.overall.label;
    
    // Update URL
    this.analyzedUrl.textContent = data.url;

    // Display categories
    this.categoriesGrid.innerHTML = '';
    
    data.categories.forEach(category => {
      const card = this.createCategoryCard(category);
      this.categoriesGrid.appendChild(card);
    });

    // Show results section
    this.resultsSection.style.display = 'block';
    this.resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  createCategoryCard(category) {
    const card = document.createElement('div');
    card.className = 'category-card';
    
    const scoreColor = this.getScoreColor(category.score);
    
    card.innerHTML = `
      <div class="category-card-header">
        <div class="category-icon">${category.icon}</div>
        <div class="category-title">
          <h3>${category.category}</h3>
          <div class="category-score">${category.checks.length} checks</div>
        </div>
        <div class="category-badge" style="background: ${scoreColor}">
          ${category.score}/100
        </div>
      </div>
      <div class="category-body">
        <ul class="check-list">
          ${category.checks.map(check => this.createCheckItem(check)).join('')}
        </ul>
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

  createCheckItem(check) {
    const statusIcon = this.getStatusIcon(check.status);
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
    if (score >= 90) return '#10b981'; // green
    if (score >= 75) return '#3b82f6'; // blue
    if (score >= 60) return '#f59e0b'; // amber
    if (score >= 45) return '#ef4444'; // red
    return '#dc2626'; // dark red
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
      report += `\n${category.icon} ${category.category} - ${category.score}/100\n`;
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
}

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  new SiteSentinelApp();
});
