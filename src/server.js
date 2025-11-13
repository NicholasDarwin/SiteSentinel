/**
 * SiteSentinel - Professional Website Security & Analysis Platform
 * Express.js Server
 */

const express = require('express');
const path = require('path');
const logger = require('./utils/logger.util');

const app = express();
const PORT = process.env.PORT || 3000;
const ENV = process.env.NODE_ENV || 'development';

// ─────────────────────────────────────────────────────────────
// MIDDLEWARE
// ─────────────────────────────────────────────────────────────

// Body parser
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

// Static files
app.use(express.static(path.join(__dirname, '../public')));

// Request logging
app.use((req, res, next) => {
  logger.debug(`${req.method} ${req.path}`);
  next();
});

// ─────────────────────────────────────────────────────────────
// ROUTES
// ─────────────────────────────────────────────────────────────

// API Routes
app.use('/api', require('./routes/analyze.route'));

// Root route - serve index.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'operational',
    environment: ENV,
    timestamp: new Date().toISOString(),
    version: '2.0.0'
  });
});

// ─────────────────────────────────────────────────────────────
// ERROR HANDLING
// ─────────────────────────────────────────────────────────────

// 404 - Not Found
app.use((req, res) => {
  res.status(404).json({ 
    error: 'Route not found',
    path: req.path,
    method: req.method
  });
});

// Global error handler
app.use((err, req, res, next) => {
  logger.error('Unhandled error', err);
  res.status(500).json({ 
    error: 'Internal server error',
    message: ENV === 'development' ? err.message : 'An error occurred'
  });
});

// ─────────────────────────────────────────────────────────────
// SERVER STARTUP
// ─────────────────────────────────────────────────────────────

const server = app.listen(PORT, () => {
  console.log('\n');
  console.log('╔════════════════════════════════════════════════════════╗');
  console.log('║                                                        ║');
  console.log('║           🔒 SiteSentinel - URL Security Analysis      ║');
  console.log('║                                                        ║');
  console.log('╠════════════════════════════════════════════════════════╣');
  console.log(`║  Environment: ${ENV.padEnd(43, ' ')}║`);
  console.log(`║  Port: ${PORT}                                              ║`);
  console.log(`║  Status: ✅ Running                                     ║`);
  console.log('╠════════════════════════════════════════════════════════╣');
  console.log(`║  🌐 Web Interface: http://localhost:${PORT}${' '.repeat(23)}║`);
  console.log(`║  📡 API Endpoint: http://localhost:${PORT}/api/analyze${' '.repeat(11)}║`);
  console.log(`║  ❤️  Health Check: http://localhost:${PORT}/health${' '.repeat(14)}║`);
  console.log('╚════════════════════════════════════════════════════════╝');
  console.log('\n');
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM signal received: closing HTTP server');
  server.close(() => {
    logger.info('HTTP server closed');
    process.exit(0);
  });
});

module.exports = app;
