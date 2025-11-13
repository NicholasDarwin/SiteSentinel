const express = require('express');
const path = require('path');
const URLAnalyzer = require('./analyzer');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.static('public'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/api/analyze', async (req, res) => {
  try {
    const { url } = req.body;

    if (!url) {
      return res.status(400).json({
        error: 'URL parameter is required'
      });
    }

    // Simple URL validation
    try {
      new URL(url.startsWith('http') ? url : `https://${url}`);
    } catch (e) {
      return res.status(400).json({
        error: 'Invalid URL format'
      });
    }

    const analyzer = new URLAnalyzer();
    const results = await analyzer.analyze(url);

    res.json(results);
  } catch (error) {
    console.error('Analysis error:', error);
    res.status(500).json({
      error: 'Analysis failed: ' + error.message
    });
  }
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'SiteSentinel API is running' });
});

// Error handling
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({
    error: 'Internal server error'
  });
});

app.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════════════════════╗
║           SiteSentinel - URL Security Analysis          ║
║                     Running on Port ${PORT}                    ║
╠════════════════════════════════════════════════════════╣
║  Visit: http://localhost:${PORT}                           ║
║  API:   http://localhost:${PORT}/api/analyze              ║
╚════════════════════════════════════════════════════════╝
  `);
});

module.exports = app;
