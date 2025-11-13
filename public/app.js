// SiteSentinel Frontend Application
class SiteSentinelApp {
  constructor() {
    this.form = document.getElementById('analyzeForm');
    this.urlInput = document.getElementById('urlInput');
    this.resultsSection = document.getElementById('resultsSection');
    this.errorSection = document.getElementById('errorSection');
    this.loadingSection = document.getElementById('loadingSection');
    this.categoriesContainer = document.getElementById('categoriesContainer');
    this.exportBtn = document.getElementById('exportBtn');
    this.submitBtn = this.form.querySelector('button[type="submit"]');

    this.bindEvents();
  }

  bindEvents() {
    this.form.addEventListener('submit', (e) => this.handleSubmit(e));
    this.exportBtn.addEventListener('click', () => this.exportReport());
  }

  async handleSubmit(e) {
    e.preventDefault();
    const url = this.urlInput.value.trim();

    if (!url) {
      this.showError('Please enter a URL');
      return;
    }

    await this.analyzeUrl(url);
  }

  async analyzeUrl(url) {
    this.showLoading();
    this.submitBtn.disabled = true;
    this.submitBtn.querySelector('.btn-text').style.display = 'none';
    this.submitBtn.querySelector('.btn-loader').style.display = 'inline';

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ url })
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Analysis failed');
      }

      const results = await response.json();
      this.displayResults(results);
    } catch (error) {
      console.error('Error:', error);
      this.showError(error.message);
    } finally {
      this.submitBtn.disabled = false;
      this.submitBtn.querySelector('.btn-text').style.display = 'inline';
      this.submitBtn.querySelector('.btn-loader').style.display = 'none';
    }
  }

  showLoading() {
    this.resultsSection.style.display = 'none';
    this.errorSection.style.display = 'none';
    this.loadingSection.style.display = 'block';
  }

  showError(message) {
    this.resultsSection.style.display = 'none';
    this.loadingSection.style.display = 'none';
    this.errorSection.style.display = 'block';
    document.getElementById('errorMessage').textContent = message;
  }

  displayResults(results) {
    this.loadingSection.style.display = 'none';
    this.errorSection.style.display = 'none';
    this.resultsSection.style.display = 'block';

    // Update summary
    document.getElementById('analyzedUrl').textContent = results.url;
    document.getElementById('analyzedTime').textContent = new Date(results.timestamp).toLocaleString();

    const summary = results.summary;
    document.getElementById('passedCount').textContent = summary.passed;
    document.getElementById('warningCount').textContent = summary.warnings;
    document.getElementById('failedCount').textContent = summary.failed;
    document.getElementById('totalCount').textContent = summary.total_checks;

    const scoreElement = document.getElementById('scoreValue');
    scoreElement.textContent = summary.score;
    const scoreCircle = document.getElementById('scoreCircle');
    scoreCircle.className = 'score-circle ' + this.getScoreClass(summary.score);

    // Display categories
    this.displayCategories(results.categories);

    // Scroll to results
    window.scrollTo({ top: document.querySelector('.summary-card').offsetTop - 100, behavior: 'smooth' });
  }

  getScoreClass(score) {
    if (score >= 80) return 'excellent';
    if (score >= 60) return 'good';
    if (score >= 40) return 'warning';
    return 'poor';
  }

  displayCategories(categories) {
    this.categoriesContainer.innerHTML = '';

    categories.forEach((category, index) => {
      const categoryEl = document.createElement('div');
      categoryEl.className = 'category';

      // Calculate category statistics
      const passed = category.checks.filter(c => c.status === 'pass').length;
      const warnings = category.checks.filter(c => c.status === 'warning').length;
      const failed = category.checks.filter(c => c.status === 'fail').length;

      const headerEl = document.createElement('div');
      headerEl.className = 'category-header';
      headerEl.innerHTML = `
        <h3>${this.escapeHtml(category.name)}</h3>
        <div style="font-size: 0.9em; color: var(--text-secondary); margin-left: 10px;">
          <span style="color: var(--success-color); font-weight: 600;">${passed}</span>
          <span style="color: var(--warning-color); font-weight: 600; margin-left: 10px;">${warnings}</span>
          <span style="color: var(--danger-color); font-weight: 600; margin-left: 10px;">${failed}</span>
          <span class="toggle-icon" style="margin-left: 20px;">▶</span>
        </div>
      `;

      const checksEl = document.createElement('div');
      checksEl.className = 'category-checks';

      category.checks.forEach(check => {
        const checkEl = document.createElement('div');
        checkEl.className = `check-item check-${check.status}`;

        const statusEmoji = check.status === 'pass' ? '✅' : 
                          check.status === 'warning' ? '⚠️' : '❌';

        let recommendationsHtml = '';
        if (check.recommendations && check.recommendations.length > 0) {
          recommendationsHtml = `
            <div class="recommendations">
              <strong>💡 Recommendations:</strong>
              <ul>
                ${check.recommendations.map(rec => `<li>${this.escapeHtml(rec)}</li>`).join('')}
              </ul>
            </div>
          `;
        }

        checkEl.innerHTML = `
          <div class="check-status">${statusEmoji}</div>
          <div class="check-content">
            <div class="check-name">${this.escapeHtml(check.name)}</div>
            <div class="check-details">${this.escapeHtml(check.details)}</div>
            ${recommendationsHtml}
          </div>
        `;

        checksEl.appendChild(checkEl);
      });

      // Toggle functionality
      let isCollapsed = index > 2; // Collapse categories after first 3
      if (isCollapsed) {
        checksEl.classList.add('collapsed');
        headerEl.classList.add('collapsed');
      }

      headerEl.addEventListener('click', () => {
        isCollapsed = !isCollapsed;
        checksEl.classList.toggle('collapsed');
        headerEl.classList.toggle('collapsed');
      });

      categoryEl.appendChild(headerEl);
      categoryEl.appendChild(checksEl);
      this.categoriesContainer.appendChild(categoryEl);
    });
  }

  escapeHtml(text) {
    const map = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
  }

  exportReport() {
    const summary = {
      url: document.getElementById('analyzedUrl').textContent,
      analyzed: document.getElementById('analyzedTime').textContent,
      score: document.getElementById('scoreValue').textContent,
      passed: document.getElementById('passedCount').textContent,
      warnings: document.getElementById('warningCount').textContent,
      failed: document.getElementById('failedCount').textContent,
      total: document.getElementById('totalCount').textContent
    };

    // Extract all checks
    const categories = [];
    document.querySelectorAll('.category').forEach(catEl => {
      const categoryName = catEl.querySelector('.category-header h3').textContent;
      const checks = [];

      catEl.querySelectorAll('.check-item').forEach(checkEl => {
        const status = checkEl.classList[1].replace('check-', '');
        const name = checkEl.querySelector('.check-name').textContent;
        const details = checkEl.querySelector('.check-details').textContent;

        checks.push({ status, name, details });
      });

      categories.push({ name: categoryName, checks });
    });

    // Create CSV content
    let csv = 'SiteSentinel Security Analysis Report\n';
    csv += `URL: ${summary.url}\n`;
    csv += `Analyzed: ${summary.analyzed}\n`;
    csv += `Overall Score: ${summary.score}/100\n\n`;
    csv += `Summary:\n`;
    csv += `Passed: ${summary.passed}\n`;
    csv += `Warnings: ${summary.warnings}\n`;
    csv += `Failed: ${summary.failed}\n`;
    csv += `Total Checks: ${summary.total}\n\n`;
    csv += `Detailed Results:\n\n`;

    categories.forEach(cat => {
      csv += `${cat.name}\n`;
      csv += '---\n';
      cat.checks.forEach(check => {
        csv += `[${check.status.toUpperCase()}] ${check.name}: ${check.details}\n`;
      });
      csv += '\n';
    });

    // Download
    const element = document.createElement('a');
    element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(csv));
    element.setAttribute('download', `sitesentinel-report-${new Date().toISOString().split('T')[0]}.txt`);
    element.style.display = 'none';
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  }
}

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  new SiteSentinelApp();

  // Set focus to input
  document.getElementById('urlInput').focus();
});
