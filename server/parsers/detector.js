/**
 * LOGVAULT — Auto Format Detector
 * Runs all parsers' canParse() against input and returns the best-match format
 */

import * as syslogParser from './syslog.js';
import * as cefParser from './cef.js';
import * as jsonParser from './json-log.js';
import * as apacheParser from './apache.js';
import * as windowsParser from './windows.js';
import * as genericKvParser from './generic-kv.js';

const PARSERS = [
  { name: 'cef', module: cefParser },
  { name: 'syslog', module: syslogParser },
  { name: 'json', module: jsonParser },
  { name: 'apache', module: apacheParser },
  { name: 'windows', module: windowsParser },
  { name: 'generic-kv', module: genericKvParser }
];

/**
 * Detect the format of a raw log line.
 * Returns { format, confidence, parser } or null.
 */
export function detect(raw) {
  if (!raw || typeof raw !== 'string' || raw.trim().length === 0) {
    return { format: 'empty', confidence: 0, parser: null };
  }

  const trimmed = raw.trim();
  let bestMatch = { format: 'unknown', confidence: 0, parser: null };

  for (const { name, module } of PARSERS) {
    const score = module.canParse(trimmed);
    if (score > bestMatch.confidence) {
      bestMatch = { format: name, confidence: score, parser: module };
    }
  }

  return bestMatch;
}

/**
 * Parse a raw log line using the best-match parser.
 * Returns structured parse result or null.
 */
export function parseAuto(raw) {
  const detection = detect(raw);
  if (!detection.parser || detection.confidence < 0.10) {
    return null;
  }

  try {
    const result = detection.parser.parse(raw.trim());
    if (result) {
      result.detection_confidence = detection.confidence;
      result.detected_format = detection.format;
    }
    return result;
  } catch (err) {
    console.error(`[DETECTOR] Parser error for format ${detection.format}:`, err.message);
    return null;
  }
}

/**
 * Detect format of a batch of lines and return stats.
 */
export function detectBatch(lines) {
  const stats = {};
  const results = [];

  for (const line of lines) {
    if (!line || line.trim().length === 0) continue;
    const detection = detect(line);
    stats[detection.format] = (stats[detection.format] || 0) + 1;
    results.push({ line: line.substring(0, 100), ...detection, parser: undefined });
  }

  return { stats, results, total: lines.length };
}

export { PARSERS };
