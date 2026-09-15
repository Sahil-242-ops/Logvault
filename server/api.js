/**
 * LOGVAULT — Express API Routes
 * POST /api/normalize, /api/upload, /api/detect, /api/ai/analyze
 * GET  /api/health
 */

import { Router } from 'express';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { normalize, normalizeBatch } from './normalizer.js';
import { detect, detectBatch } from './parsers/detector.js';
import { detectAnomalies, detectBatchAnomalies } from './anomaly-detector.js';
import localAI from './ai/local-ai.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const router = Router();

// --- File upload config ---
const uploadsDir = path.join(__dirname, '..', 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const uniqueName = `${Date.now()}-${file.originalname}`;
    cb(null, uniqueName);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50 MB max
  fileFilter: (req, file, cb) => {
    // Accept log-like files
    const ext = path.extname(file.originalname).toLowerCase();
    const allowed = ['.log', '.txt', '.csv', '.json', '.xml', '.syslog', '.evtx', '.cef', ''];
    if (allowed.includes(ext) || file.mimetype.startsWith('text/')) {
      cb(null, true);
    } else {
      cb(new Error(`File type ${ext} not supported. Use .log, .txt, .json, .csv, .xml`));
    }
  }
});

// --- In-memory processed log storage (prototype) ---
const processedLogs = [];
const MAX_STORED = 5000;

function storeResult(result) {
  processedLogs.unshift(result);
  if (processedLogs.length > MAX_STORED) {
    processedLogs.length = MAX_STORED;
  }
}

// =============================================================
// GET /api/health
// =============================================================
router.get('/health', async (req, res) => {
  const aiStatus = localAI.getStatus();
  res.json({
    status: 'operational',
    platform: 'LOGVAULT SIH26156',
    version: '1.0.0',
    uptime_seconds: Math.floor(process.uptime()),
    ai: {
      mode: aiStatus.mode,
      provider: aiStatus.provider,
      model: aiStatus.model,
      available: aiStatus.available
    },
    network: 'AIR-GAPPED / LOCAL',
    storage: {
      processed_logs: processedLogs.length,
      max_capacity: MAX_STORED
    },
    timestamp: new Date().toISOString()
  });
});

// =============================================================
// POST /api/normalize
// Body: { raw: "log line" } or { raw: ["line1", "line2", ...] }
// =============================================================
router.post('/normalize', (req, res) => {
  try {
    const { raw, options } = req.body;

    if (!raw) {
      return res.status(400).json({ error: 'Missing "raw" field. Provide a log string or array of strings.' });
    }

    const opts = {
      enablePiiMasking: options?.piiMasking !== false,
      includeRaw: options?.includeRaw !== false
    };

    if (Array.isArray(raw)) {
      const result = normalizeBatch(raw, opts);

      // Run anomaly detection on batch
      const anomalies = detectBatchAnomalies(result.results);

      // Merge anomaly findings into results
      result.results.forEach((r, i) => {
        r.anomaly = anomalies.results[i];
        storeResult(r);
      });

      result.anomaly_summary = anomalies.summary;
      return res.json(result);
    }

    // Single line
    const result = normalize(raw, opts);
    result.anomaly = detectAnomalies(result);
    storeResult(result);
    return res.json(result);
  } catch (err) {
    console.error('[API] /normalize error:', err);
    res.status(500).json({ error: err.message });
  }
});

// =============================================================
// POST /api/upload
// Multipart file upload → parse line by line → normalize
// =============================================================
router.post('/upload', upload.single('logfile'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded. Use field name "logfile".' });
    }

    const filePath = req.file.path;
    const fileContent = fs.readFileSync(filePath, 'utf-8');
    const lines = fileContent.split(/\r?\n/).filter(l => l.trim().length > 0);

    const opts = {
      enablePiiMasking: req.body?.piiMasking !== 'false',
      includeRaw: req.body?.includeRaw !== 'false'
    };

    const result = normalizeBatch(lines, opts);

    // Anomaly detection
    const anomalies = detectBatchAnomalies(result.results);
    result.results.forEach((r, i) => {
      r.anomaly = anomalies.results[i];
      storeResult(r);
    });
    result.anomaly_summary = anomalies.summary;

    // File metadata
    result.file = {
      original_name: req.file.originalname,
      size_bytes: req.file.size,
      total_lines: lines.length,
      mime_type: req.file.mimetype
    };

    // Clean up uploaded file
    try { fs.unlinkSync(filePath); } catch { /* ignore */ }

    return res.json(result);
  } catch (err) {
    console.error('[API] /upload error:', err);
    res.status(500).json({ error: err.message });
  }
});

// =============================================================
// POST /api/detect
// Body: { raw: "log line" } or { raw: ["line1", ...] }
// =============================================================
router.post('/detect', (req, res) => {
  try {
    const { raw } = req.body;

    if (!raw) {
      return res.status(400).json({ error: 'Missing "raw" field.' });
    }

    if (Array.isArray(raw)) {
      const result = detectBatch(raw);
      return res.json(result);
    }

    const result = detect(raw);
    return res.json({
      format: result.format,
      confidence: result.confidence,
      raw: raw.substring(0, 200)
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// =============================================================
// POST /api/ai/analyze
// Body: { raw: "log line", task: "analyze|infer|classify|explain" }
// =============================================================
router.post('/ai/analyze', async (req, res) => {
  try {
    const { raw, task, fields } = req.body;

    if (!raw && !fields) {
      return res.status(400).json({ error: 'Missing "raw" (log string) or "fields" (normalized fields).' });
    }

    const taskType = task || 'analyze';
    let result;

    switch (taskType) {
      case 'analyze':
        result = await localAI.analyzeLog(raw);
        break;
      case 'infer':
        result = await localAI.inferSchema(raw);
        break;
      case 'classify':
        result = await localAI.classifyEvent(fields || { raw_log: raw });
        break;
      case 'explain':
        result = await localAI.explainLog(raw);
        break;
      default:
        return res.status(400).json({ error: `Unknown task: ${taskType}. Use: analyze, infer, classify, explain` });
    }

    return res.json({
      task: taskType,
      ai_status: localAI.getStatus(),
      ...result
    });
  } catch (err) {
    console.error('[API] /ai/analyze error:', err);
    res.status(500).json({ error: err.message });
  }
});

// =============================================================
// GET /api/ai/status
// =============================================================
router.get('/ai/status', (req, res) => {
  res.json(localAI.getStatus());
});

// =============================================================
// GET /api/logs
// Returns stored processed logs
// =============================================================
router.get('/logs', (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  const offset = parseInt(req.query.offset) || 0;
  const severity = req.query.severity;

  let logs = processedLogs;
  if (severity) {
    logs = logs.filter(l => l.severity === severity.toUpperCase());
  }

  res.json({
    total: logs.length,
    limit,
    offset,
    results: logs.slice(offset, offset + limit)
  });
});

export default router;
export { processedLogs };
