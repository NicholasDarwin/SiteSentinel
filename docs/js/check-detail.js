/**
 * Check Detail Page - Dynamic Result Display
 * This script parses check data from URL parameters and displays the analysis result
 */

document.addEventListener('DOMContentLoaded', function() {
  const urlParams = new URLSearchParams(window.location.search);
  const dataParam = urlParams.get('data');
  
  if (dataParam) {
    try {
      const checkData = JSON.parse(decodeURIComponent(dataParam));
      displayAnalysisResult(checkData);
    } catch (e) {
      console.error('Failed to parse check data:', e);
    }
  }
});

function displayAnalysisResult(checkData) {
  // Create result card if it doesn't exist
  let resultCard = document.getElementById('analysisResult');
  
  if (!resultCard) {
    resultCard = createResultCard();
    const mainContent = document.querySelector('main.page');
    const backLink = mainContent.querySelector('.back-link');
    if (backLink && backLink.nextSibling) {
      mainContent.insertBefore(resultCard, backLink.nextSibling);
    } else {
      mainContent.prepend(resultCard);
    }
  }
  
  resultCard.style.display = 'block';
  
  // Status icons (using SVG icons) and colors
  const statusIcons = { 
    pass: '<svg class="status-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6L9 17l-5-5"/></svg>', 
    warn: '<svg class="status-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>', 
    info: '<svg class="status-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4m0-4h.01"/></svg>', 
    fail: '<svg class="status-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6L6 18M6 6l12 12"/></svg>', 
    error: '<svg class="status-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6m0-6l6 6"/></svg>' 
  };
  const statusColors = { pass: '#10b981', warn: '#f59e0b', info: '#06b6d4', fail: '#ef4444', error: '#ef4444' };
  const badgeLabels = { pass: 'Safe', warn: 'Warning', info: 'Info', fail: 'Issue Found', error: 'Error' };
  
  // Set values
  document.getElementById('resultUrl').textContent = checkData.url || 'Unknown URL';
  document.getElementById('resultIcon').innerHTML = statusIcons[checkData.status] || '<svg class="status-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>';
  document.getElementById('resultStatus').textContent = checkData.status?.toUpperCase() || 'UNKNOWN';
  document.getElementById('resultStatus').style.color = statusColors[checkData.status] || '#6b7280';
  
  const badge = document.getElementById('resultBadge');
  badge.textContent = badgeLabels[checkData.status] || 'Unknown';
  badge.className = 'result-badge ' + (checkData.status || 'info');
  
  document.getElementById('resultDescription').textContent = checkData.description || 'No details available.';
}

function createResultCard() {
  const card = document.createElement('section');
  card.id = 'analysisResult';
  card.className = 'analysis-result-card';
  card.style.display = 'none';
  
  card.innerHTML = `
    <div class="result-header">
      <span id="resultIcon" class="result-icon"><svg class="status-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg></span>
      <div class="result-info">
        <h2>Your Analysis Result</h2>
        <p id="resultUrl" class="result-url"></p>
      </div>
      <span id="resultBadge" class="result-badge"></span>
    </div>
    <div class="result-body">
      <div class="result-status">
        <span class="label">Status:</span>
        <span id="resultStatus" class="status-value"></span>
      </div>
      <div class="result-description">
        <span class="label">Finding:</span>
        <p id="resultDescription"></p>
      </div>
    </div>
  `;
  
  return card;
}
