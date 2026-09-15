/**
 * LOGVAULT — Dev Server (Express + API + Static Files)
 * SIH26156 Universal Log Intelligence Platform
 * Air-Gapped Local Architecture
 */

import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import apiRouter from './server/api.js';
import localAI from './server/ai/local-ai.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT || 3000;
const app = express();

// --- Middleware ---
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// --- API Routes ---
app.use('/api', apiRouter);

// --- Static Files (existing frontend) ---
app.use(express.static(__dirname, {
  extensions: ['html', 'css', 'js'],
  setHeaders: (res) => {
    res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
  }
}));

// SPA fallback — serve index.html for unmatched routes
app.get('*', (req, res) => {
  // Don't serve index.html for /api routes that weren't matched
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'API endpoint not found' });
  }
  res.sendFile(path.join(__dirname, 'index.html'));
});

// --- Error handler ---
app.use((err, req, res, next) => {
  console.error('[SERVER] Error:', err.message);
  res.status(err.status || 500).json({
    error: err.message || 'Internal server error'
  });
});

// --- Start Server ---
async function start() {
  // Initialize Local AI (probe for Ollama / llama.cpp)
  console.log('\n╔══════════════════════════════════════════════════════════════╗');
  console.log('║     LOGVAULT — Universal Log Intelligence (SIH26156)       ║');
  console.log('║     Air-Gapped Local Processing Architecture               ║');
  console.log('╚══════════════════════════════════════════════════════════════╝\n');

  console.log('[BOOT] Probing for local AI models...');
  const aiStatus = await localAI.init();

  if (aiStatus.available) {
    console.log(`[BOOT] ✓ AI MODE: LOCAL`);
    console.log(`[BOOT]   Provider: ${aiStatus.provider}`);
    console.log(`[BOOT]   Model: ${aiStatus.model}`);
  } else {
    console.log('[BOOT] ⚠ AI MODE: DETERMINISTIC (No local model detected)');
    console.log('[BOOT]   To enable AI: Install Ollama and run "ollama pull llama3.2"');
  }

  console.log('[BOOT] NETWORK: AIR-GAPPED / OFFLINE CAPABLE');
  console.log('');

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[LIVE] LOGVAULT running at http://localhost:${PORT}/`);
    console.log(`[LIVE] API endpoints at http://localhost:${PORT}/api/`);
    console.log(`[LIVE] Health check: http://localhost:${PORT}/api/health`);
    console.log('');
    console.log('API Endpoints:');
    console.log('  POST /api/normalize    — Normalize raw log(s)');
    console.log('  POST /api/upload       — Upload log file');
    console.log('  POST /api/detect       — Detect log format');
    console.log('  POST /api/ai/analyze   — AI log analysis');
    console.log('  GET  /api/ai/status    — AI model status');
    console.log('  GET  /api/health       — System health');
    console.log('  GET  /api/logs         — Processed log history');
    console.log('');
  });
}

start().catch(err => {
  console.error('[FATAL] Server startup failed:', err);
  process.exit(1);
});
