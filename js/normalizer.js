/**
 * LOGVAULT — Log Normalizer & 3D Neural Pipeline Module
 * 60 FPS 3D Holographic Data Refinery Canvas + Hex Disassembler + Entropy Scanner + AI Rule Generator
 */

const Normalizer = {
  currentPreset: 'ssh',
  currentData: null,
  activeOutputTab: 'table', // 'table' | 'json' | 'ast'
  activeRawMode: 'tokens', // 'tokens' | 'hex' | 'entropy'
  animFrameId: null,
  mouseX: 0,
  mouseY: 0,
  targetTiltX: 0,
  targetTiltY: 0,
  currentTiltX: 0,
  currentTiltY: 0,

  // 7 Enterprise Regex Patterns with named capture groups
  formatPatterns: {
    ssh: {
      regex: '^(?<timestamp>\\w+\\s+\\d+\\s+[\\d:]+)\\s+(?<host>\\S+)\\s+sshd\\[(?<pid>\\d+)\\]:\\s+(?<action>Accepted|Failed)\\s+password\\s+for\\s+(?<user>\\S+)\\s+from\\s+(?<src_ip>[\\d.]+)\\s+port\\s+(?<port>\\d+)\\s+(?<protocol>\\w+)$',
      description: 'POSIX PAM authentication failure & success pattern'
    },
    cef: {
      regex: 'CEF:0\\|(?<vendor>[^\\|]+)\\|(?<product>[^\\|]+)\\|(?<version>[^\\|]+)\\|(?<signature_id>[^\\|]+)\\|(?<name>[^\\|]+)\\|(?<severity>\\d+)\\|src=(?<src_ip>[\\d.]+)\\s+dst=(?<dst_ip>[\\d.]+)\\s+spt=(?<src_port>\\d+)\\s+dpt=(?<dst_port>\\d+)\\s+act=(?<action>\\w+)',
      description: 'Common Event Format (CEF v0.1) perimeter security telemetry'
    },
    apache: {
      regex: '^(?<src_ip>[\\d.]+)\\s+-\\s+(?<user>\\S+)\\s+\\[(?<timestamp>[^\\]]+)\\]\\s+"(?<http_method>\\w+)\\s+(?<url>\\S+)\\s+HTTP/(?<http_version>[\\d.]+)"\\s+(?<status_code>\\d+)\\s+(?<bytes>\\d+)',
      description: 'W3C Standard Web Access Log format'
    },
    cloudtrail: {
      regex: '\\{"eventVersion":"(?<version>[^"]+)","userIdentity":\\{"type":"(?<user_type>[^"]+)","userName":"(?<user>[^"]+)"\\},"sourceIPAddress":"(?<src_ip>[^"]+)","eventName":"(?<action>[^"]+)"\\}',
      description: 'AWS CloudTrail multi-region JSON telemetry envelope'
    },
    windows: {
      regex: 'EventID=(?<event_id>\\d+)\\s+AccountName=(?<user>\\S+)\\s+Workstation=(?<host>\\S+)\\s+SourceIP=(?<src_ip>[\\d.]+)\\s+Status=(?<status>[^;]+)',
      description: 'Windows Security Subsystem Event Log (WinEventLog)'
    },
    kubernetes: {
      regex: '^(?<src_ip>[\\d.]+)\\s+-\\s+\\[(?<timestamp>[^\\]]+)\\]\\s+"(?<http_method>\\w+)\\s+(?<url>\\S+)\\s+HTTP/(?<http_version>[\\d.]+)"\\s+(?<status_code>\\d+)\\s+(?<bytes>\\d+)\\s+"(?<ingress>[^"]+)"\\s+"(?<user_agent>[^"]+)"\\s+req_id=(?<request_id>\\S+)',
      description: 'Kubernetes Ingress Controller NGINX Access Telemetry'
    },
    suricata: {
      regex: '\\{"timestamp":"(?<timestamp>[^"]+)","event_type":"(?<event_type>[^"]+)","src_ip":"(?<src_ip>[^"]+)","src_port":(?<src_port>\\d+),"dest_ip":"(?<dst_ip>[^"]+)","dest_port":(?<dst_port>\\d+)',
      description: 'Suricata EVE JSON Network Intrusion & Threat Feed'
    }
  },

  init() {
    this.bindEvents();
    this.initCanvas3D();
  },

  onScreenOpen() {
    this.initCanvas3D();
  },

  bindEvents() {
    // Preset format selector buttons
    document.querySelectorAll('[data-norm-preset]').forEach(btn => {
      btn.addEventListener('click', () => {
        const key = btn.getAttribute('data-norm-preset');
        if (key) {
          this.playHapticBlip(540);
          this.loadPreset(key);
        }
      });
    });

    // Sub-view mode buttons (Tokens | Hex | Entropy)
    document.querySelectorAll('[data-norm-raw-mode]').forEach(btn => {
      btn.addEventListener('click', () => {
        const mode = btn.getAttribute('data-norm-raw-mode');
        this.switchRawMode(mode);
      });
    });

    // Custom Run Button
    const runBtn = document.getElementById('btn-run-normalize-custom');
    if (runBtn) {
      runBtn.addEventListener('click', () => {
        const input = document.getElementById('norm-custom-raw-input');
        if (input && input.value.trim()) {
          this.playHapticBlip(680);
          this.executeCustomPipeline(input.value.trim());
        } else {
          Utils.showToast('Please enter a raw log string first.', 'warning');
        }
      });
    }

    // File Upload Handlers
    const fileInput = document.getElementById('norm-file-upload');
    const fileNameDisplay = document.getElementById('norm-file-name');
    const uploadBtn = document.getElementById('btn-run-upload');
    let selectedFile = null;

    if (fileInput) {
      fileInput.addEventListener('change', (e) => {
        if (e.target.files && e.target.files.length > 0) {
          selectedFile = e.target.files[0];
          if (fileNameDisplay) {
            fileNameDisplay.textContent = `Selected: ${selectedFile.name} (${(selectedFile.size / 1024).toFixed(1)} KB)`;
            fileNameDisplay.style.display = 'block';
          }
          if (uploadBtn) {
            uploadBtn.style.display = 'block';
          }
        }
      });
    }

    if (uploadBtn) {
      uploadBtn.addEventListener('click', async () => {
        if (!selectedFile) return;
        this.playHapticBlip(680);
        await this.executeFileUpload(selectedFile);
        // Allow re-selecting the same file (otherwise 'change' won't fire again)
        if (fileInput) fileInput.value = '';
      });
    }

    // AI Auto-Generate Rule Button
    const aiBtn = document.getElementById('btn-ai-generate-rule');
    if (aiBtn) {
      aiBtn.addEventListener('click', () => {
        this.simulateAiRuleGeneration();
      });
    }

    // Output view tabs (Key-Value Table vs JSON Tree vs AST)
    const tabTable = document.getElementById('norm-tab-table');
    const tabJson = document.getElementById('norm-tab-json');
    const tabAst = document.getElementById('norm-tab-ast');
    if (tabTable) tabTable.addEventListener('click', () => this.switchOutputTab('table'));
    if (tabJson) tabJson.addEventListener('click', () => this.switchOutputTab('json'));
    if (tabAst) tabAst.addEventListener('click', () => this.switchOutputTab('ast'));

    // Copy JSON button
    const copyBtn = document.getElementById('btn-copy-norm-json');
    if (copyBtn) {
      copyBtn.addEventListener('click', () => {
        if (this.currentData && this.currentData.schema) {
          navigator.clipboard.writeText(JSON.stringify(this.currentData.schema, null, 2))
            .then(() => Utils.showToast('OCSF JSON schema copied to clipboard!', 'success'))
            .catch(() => Utils.showToast('Failed to copy to clipboard.', 'error'));
        }
      });
    }

    // Copy Regex button
    const copyRegexBtn = document.getElementById('btn-copy-regex');
    if (copyRegexBtn) {
      copyRegexBtn.addEventListener('click', () => {
        const pat = this.formatPatterns[this.currentPreset] || this.formatPatterns.ssh;
        navigator.clipboard.writeText(pat.regex)
          .then(() => Utils.showToast('Named capture regex copied to clipboard!', 'success'));
      });
    }

    // Download Schema JSON
    const downloadBtn = document.getElementById('btn-download-norm-json');
    if (downloadBtn) {
      downloadBtn.addEventListener('click', () => {
        if (!this.currentData) return;
        const blob = new Blob([JSON.stringify(this.currentData.schema, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `ocsf_${this.currentPreset}_normalized.json`;
        a.click();
        URL.revokeObjectURL(url);
        Utils.showToast('Downloaded OCSF Schema JSON.');
      });
    }

    // Mouse parallax tracking on canvas
    const canvas = document.getElementById('normalizerPipelineCanvas');
    if (canvas) {
      canvas.addEventListener('mousemove', (e) => {
        const rect = canvas.getBoundingClientRect();
        this.targetTiltX = ((e.clientX - rect.left) / rect.width - 0.5) * 16;
        this.targetTiltY = ((e.clientY - rect.top) / rect.height - 0.5) * 10;
      });
      canvas.addEventListener('mouseleave', () => {
        this.targetTiltX = 0;
        this.targetTiltY = 0;
      });
    }
  },

  playHapticBlip(freq = 440) {
    try {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      if (!AudioCtx) return;
      const ctx = new AudioCtx();
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'sine';
      osc.frequency.setValueAtTime(freq, ctx.currentTime);
      gain.gain.setValueAtTime(0.03, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.06);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start();
      osc.stop(ctx.currentTime + 0.06);
    } catch (e) {
      // Audio autoplay policy fallback
    }
  },

  loadPreset(presetKey) {
    this.currentPreset = presetKey;
    const data = window.mockNormalizerPresets[presetKey] || window.mockNormalizerPresets.ssh;
    if (!data) return;

    // Update preset pills
    document.querySelectorAll('[data-norm-preset]').forEach(btn => {
      btn.classList.toggle('active', btn.getAttribute('data-norm-preset') === presetKey);
    });

    // Populate custom input textarea
    const input = document.getElementById('norm-custom-raw-input');
    if (input) {
      input.value = data.raw;
    }

    this.animateAndRenderPipeline(data);
  },

  switchRawMode(mode) {
    this.activeRawMode = mode;
    document.querySelectorAll('[data-norm-raw-mode]').forEach(btn => {
      btn.classList.toggle('active', btn.getAttribute('data-norm-raw-mode') === mode);
    });

    const tokensBox = document.getElementById('norm-raw-tokens-box');
    const hexBox = document.getElementById('norm-raw-hex-box');
    const entropyBox = document.getElementById('norm-raw-entropy-box');

    if (tokensBox) tokensBox.style.display = mode === 'tokens' ? 'block' : 'none';
    if (hexBox) hexBox.style.display = mode === 'hex' ? 'block' : 'none';
    if (entropyBox) entropyBox.style.display = mode === 'entropy' ? 'block' : 'none';
  },

  async executeCustomPipeline(rawText) {
    this.setPipelineStageLoading(true);

    try {
      const parsedResult = await window.LogVaultAPI.normalizeLog(rawText);

      const tokens = rawText.split(/[\s,]+/).map(t => {
        let type = 'generic';
        let mappedField = null;
        if (t.includes(':') && !t.startsWith('http')) { type = 'process'; mappedField = 'process'; }
        if (t.includes('=')) { type = 'keyval'; mappedField = 'metadata'; }
        if (/\d+\.\d+\.\d+\.\d+/.test(t)) { type = 'src_ip'; mappedField = 'source_ip'; }
        if (/\d{2}:\d{2}:\d{2}/.test(t)) { type = 'timestamp'; mappedField = 'timestamp'; }
        return { text: t, type, mappedField };
      });

      const enriched = {
        name: 'Real Log Input',
        raw: rawText,
        tokens,
        ...parsedResult
      };

      this.setPipelineStageLoading(false);
      this.animateAndRenderPipeline(enriched);
      Utils.showToast('✓ Real Log Processed — AI Analysis & OCSF Normalized.', 'success');

      // Refresh real live logs & dashboard stats
      if (window.LogStream && LogStream.fetchLogs) LogStream.fetchLogs();
      if (window.App && App.renderDashboardElements) App.renderDashboardElements();
    } catch (err) {
      this.setPipelineStageLoading(false);
      Utils.showToast(`Pipeline execution failed: ${err.message}`, 'error');
    }
  },

  async executeFileUpload(file) {
    this.setPipelineStageLoading(true);

    try {
      const response = await window.LogVaultAPI.uploadFile(file);
      
      // If we got batch results, show the first one in the UI
      if (response && response.results && response.results.length > 0) {
        const firstResult = response.results[0];
        
        const rawText = firstResult.raw_log || firstResult.message || JSON.stringify(firstResult);
        
        let tokens = firstResult.tokens;
        if (!tokens && rawText && typeof rawText === 'string') {
          tokens = rawText.split(/[\s,]+/).map(t => {
            let type = 'generic'; let mappedField = null;
            if (t.includes(':') && !t.startsWith('http')) { type = 'process'; mappedField = 'process'; }
            if (t.includes('=')) { type = 'keyval'; mappedField = 'metadata'; }
            if (/\d+\.\d+\.\d+\.\d+/.test(t)) { type = 'src_ip'; mappedField = 'source_ip'; }
            if (/\d{2}:\d{2}:\d{2}/.test(t)) { type = 'timestamp'; mappedField = 'timestamp'; }
            return { text: t, type, mappedField };
          });
        }
        
        const enriched = {
          name: `Batch File: ${file.name}`,
          raw: rawText,
          tokens: tokens || [],
          format: firstResult.detected_format || 'Unknown',
          parser: firstResult.parser_name || 'Backend Parser',
          parserType: firstResult.parser_type || 'DETERMINISTIC',
          latency: (firstResult.processing_latency_ms || 0).toFixed(2) + ' ms',
          confidence: firstResult.parse_confidence || firstResult.detection_confidence || 0,
          ocsf_class: firstResult.ocsf_class_name || null,
          ocsf_class_uid: firstResult.ocsf_class_uid || null,
          anomaly: firstResult.anomaly || null,
          pii_masked: firstResult.pii_masked || false,
          ai_provider: firstResult.ai_provider || 'none',
          ai_model: firstResult.ai_model || 'none',
          ai_reasoning: firstResult.ai_reasoning || firstResult.ai_threat_reasoning || '',
          ai_threat_score: firstResult.ai_threat_score !== undefined ? firstResult.ai_threat_score : (firstResult.anomaly?.threat_score || 0),
          ai_mitre_techniques: firstResult.ai_mitre_techniques || [],
          ai_is_suspicious: firstResult.ai_is_suspicious || false,
          schema: {
            event_type: firstResult.event_type || 'GENERIC_EVENT',
            user: firstResult.user || 'unknown',
            status: firstResult.status || firstResult.action || 'RECORDED',
            source_ip: firstResult.source_ip || null,
            source_port: firstResult.source_port || null,
            destination_ip: firstResult.destination_ip || null,
            destination_port: firstResult.destination_port || null,
            host: firstResult.host || null,
            process: firstResult.process || null,
            protocol: firstResult.protocol || null,
            timestamp: firstResult.timestamp || new Date().toISOString(),
            severity: firstResult.severity || 'INFO',
            category: firstResult.category || 'general_telemetry',
            message: firstResult.message || null
          },
          _raw_backend: firstResult
        };

        this.setPipelineStageLoading(false);
        this.animateAndRenderPipeline(enriched);
        Utils.showToast(`Processed ${response.file.total_lines} real log records from ${file.name}.`, 'success');
        
        // Refresh live logs and dashboard
        if (window.LogStream && LogStream.fetchLogs) LogStream.fetchLogs();
        if (window.App && App.renderDashboardElements) App.renderDashboardElements();

        // Alert anomalies if found
        if (response.anomaly_summary && response.anomaly_summary.anomalous > 0) {
          setTimeout(() => {
            Utils.showToast(`⚠ Detected ${response.anomaly_summary.anomalous} anomalous events.`, 'warning');
          }, 1500);
        }
      } else {
        this.setPipelineStageLoading(false);
        Utils.showToast('No valid logs extracted from file.', 'warning');
      }
    } catch (err) {
      this.setPipelineStageLoading(false);
      Utils.showToast(`Upload failed: ${err.message}`, 'error');
    }
  },

  async simulateAiRuleGeneration() {
    this.playHapticBlip(720);
    const input = document.getElementById('norm-custom-raw-input');
    const text = input ? input.value.trim() : '';
    if (!text) {
      Utils.showToast('Please enter a raw log string first to analyze with Ollama AI.', 'warning');
      return;
    }
    Utils.showToast('Querying local Ollama model for log intelligence...', 'info');
    try {
      const res = await window.LogVaultAPI.aiAnalyze(text);
      if (res && res.response) {
        Utils.showToast(`AI (${res.model || 'Ollama'}): ${res.response.slice(0, 80)}...`, 'success');
      }
    } catch (err) {
      Utils.showToast(`AI analysis error: ${err.message}`, 'error');
    }
  },

  setPipelineStageLoading(isLoading) {
    const badge = document.getElementById('norm-pipeline-status-badge');
    if (badge) {
      badge.innerHTML = isLoading
        ? '<span class="pulse-dot"></span> PARSING TELEMETRY...'
        : '<span class="status-dot green-dot"></span> PIPELINE SYNCHRONIZED';
    }
  },

  animateAndRenderPipeline(data) {
    this.currentData = data;

    // 1. Stage 1: Raw Log Box with Laser Scanner & Interactive Tokens
    const rawContainer = document.getElementById('norm-raw-tokens-box');
    if (rawContainer) {
      const laserHtml = '<div class="laser-scan-bar"></div>';
      if (data.tokens && data.tokens.length > 0) {
        const tokensHtml = data.tokens.map(tok => {
          const fieldKey = tok.mappedField || tok.type;
          return `<span class="raw-token token-${tok.type}" data-tok-field="${fieldKey}" onmouseenter="Normalizer.highlightField('${fieldKey}')" onmouseleave="Normalizer.clearHighlight()" onclick="Normalizer.inspectToken('${Utils.escapeHtml(tok.text)}', '${tok.type}')">${Utils.escapeHtml(tok.text)}</span>`;
        }).join(' ');
        rawContainer.innerHTML = laserHtml + tokensHtml;
      } else {
        rawContainer.innerHTML = laserHtml + Utils.escapeHtml(data.raw);
      }
    }

    // Render Hex Disassembler Dump
    this.renderHexDump(data.raw || '');

    // Render Shannon Entropy
    this.renderEntropyRating(data.raw || '');

    // 2. Stage 2: Format & Confidence Animation
    const formatName = document.getElementById('norm-format-name');
    const formatConf = document.getElementById('norm-format-confidence');
    if (formatName) formatName.innerText = data.format;
    if (formatConf) {
      const pct = Math.round((data.confidence || 1.0) * 100);
      formatConf.innerText = `${pct}% Confidence`;
      formatConf.className = pct >= 95 ? 'badge-pill green-pill' : 'badge-pill warn-pill';
    }

    // 3. Stage 3: Parser Selected & Latency
    const parserName = document.getElementById('norm-parser-name');
    const parserLatency = document.getElementById('norm-parser-latency');
    const parserTypeBadge = document.getElementById('norm-parser-type-badge');
    if (parserName) parserName.innerText = data.parser;
    if (parserLatency) parserLatency.innerText = data.latency || '0.04 ms';
    if (parserTypeBadge) {
      parserTypeBadge.innerText = data.parserType || 'DETERMINISTIC';
      parserTypeBadge.className = data.parserType === 'AI_HEURISTIC' ? 'badge-pill cherry-pill' : 'badge-pill gold-pill';
    }

    // 4. Update Regex Pattern Breakdown
    this.renderRegexPattern(this.currentPreset);

    // 5. Stage 4: Common Log Schema Output (OCSF 1.1)
    this.renderSchemaOutput(data.schema);
    this.renderAstTree(data);

    // 6. Real Log Result Card
    this.renderRealLogResultCard(data);

    if (window.lucide) lucide.createIcons();
  },

  renderRealLogResultCard(data) {
    const card = document.getElementById('real-log-result-card');
    if (!card) return;

    card.style.display = 'block';

    const rawEl = document.getElementById('res-raw-log');
    const fmtEl = document.getElementById('res-detected-format');
    const parserEl = document.getElementById('res-parser');
    const ocsfEl = document.getElementById('res-ocsf-class');
    const eventTypeEl = document.getElementById('res-event-type');
    const sevEl = document.getElementById('res-severity');
    const threatScoreEl = document.getElementById('res-threat-score');
    const modelEl = document.getElementById('res-ai-model');
    const mitreEl = document.getElementById('res-mitre');
    const piiEl = document.getElementById('res-pii-status');
    const analysisEl = document.getElementById('res-ai-analysis');
    const badgeEl = document.getElementById('res-ollama-badge');

    const raw = data.raw || data.raw_log || '';
    if (rawEl) rawEl.innerText = raw;
    if (fmtEl) fmtEl.innerText = (data.format || data.detected_format || 'UNKNOWN').toUpperCase();
    if (parserEl) parserEl.innerText = data.parser || data.parser_name || 'Generic Parser';
    if (ocsfEl) {
      const ocsfLabel = data.ocsf_class || (data.ocsf_class_uid ? 'Class ' + data.ocsf_class_uid : null);
      ocsfEl.innerText = ocsfLabel && ocsfLabel !== 'Unknown' ? ocsfLabel : '—';
    }
    if (eventTypeEl) eventTypeEl.innerText = data.schema?.event_type || data.event_type || 'GENERIC_EVENT';
    
    const sev = (data.schema?.severity || data.severity || 'INFO').toUpperCase();
    if (sevEl) {
      sevEl.innerText = sev;
      sevEl.className = 'badge-pill ' + (sev === 'CRITICAL' ? 'crit-pill' : (sev === 'HIGH' ? 'high-pill' : (sev === 'MEDIUM' ? 'warn-pill' : 'green-pill')));
    }

    const threatScore = data.ai_threat_score !== undefined ? data.ai_threat_score : (data.anomaly?.threat_score || 0);
    if (threatScoreEl) threatScoreEl.innerText = `${threatScore} / 100`;

    const aiModel = data.ai_model || data._raw_backend?.ai_model || null;
    const hasModel = aiModel && aiModel !== 'none';
    if (modelEl) modelEl.innerText = hasModel ? aiModel : '—';
    if (badgeEl) {
      badgeEl.innerText = hasModel ? `Ollama: ${aiModel}` : 'No Local AI';
      badgeEl.className = hasModel ? 'badge-pill green-pill' : 'badge-pill warn-pill';
    }

    let mitre = 'None';
    if (data.ai_mitre_techniques && data.ai_mitre_techniques.length > 0 && data.ai_mitre_techniques[0] !== 'null') {
      mitre = data.ai_mitre_techniques.join(', ');
    } else if (data.anomaly?.findings) {
      const f = data.anomaly.findings.find(x => x.mitre_technique);
      if (f) mitre = f.mitre_technique;
    }
    if (mitreEl) {
      mitreEl.innerText = mitre;
      mitreEl.className = mitre !== 'None' ? 'badge-pill high-pill' : 'badge-pill';
    }

    if (piiEl) {
      const isMasked = data.pii_masked || data._raw_backend?.pii_masked;
      piiEl.innerText = isMasked ? 'PII Detected & Masked' : 'Clean (No PII)';
      piiEl.className = isMasked ? 'badge-pill warn-pill' : 'badge-pill green-pill';
    }

    const aiAnalysis = data.ai_reasoning || data._raw_backend?.ai_threat_reasoning || data.anomaly?.findings?.find(f => f.description)?.description || 'No analysis available.';
    if (analysisEl) analysisEl.innerText = aiAnalysis;

    if (window.lucide) lucide.createIcons();
  },

  renderHexDump(rawText) {
    const hexContainer = document.getElementById('norm-raw-hex-box');
    if (!hexContainer) return;

    let rowsHtml = '';
    const bytes = Array.from(new TextEncoder().encode(rawText));
    const chunkSize = 16;

    for (let i = 0; i < Math.min(bytes.length, 64); i += chunkSize) {
      const chunk = bytes.slice(i, i + chunkSize);
      const offset = i.toString(16).padStart(4, '0').toUpperCase();
      const hexStr = chunk.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
      const asciiStr = chunk.map(b => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.')).join('');

      rowsHtml += `
        <div class="hex-dump-row">
          <span class="hex-offset">0x${offset}</span>
          <span class="hex-bytes">${hexStr.padEnd(48, ' ')}</span>
          <span class="hex-ascii">${Utils.escapeHtml(asciiStr)}</span>
        </div>
      `;
    }

    hexContainer.innerHTML = rowsHtml;
  },

  renderEntropyRating(rawText) {
    const entropyValEl = document.getElementById('norm-entropy-score-val');
    const entropyFillEl = document.getElementById('norm-entropy-bar-fill');
    if (!entropyValEl || !entropyFillEl) return;

    // Calculate Shannon Entropy
    const map = {};
    for (let i = 0; i < rawText.length; i++) {
      const c = rawText[i];
      map[c] = (map[c] || 0) + 1;
    }

    let entropy = 0;
    const len = rawText.length || 1;
    for (const c in map) {
      const p = map[c] / len;
      entropy -= p * Math.log2(p);
    }

    const entropyScore = Math.min(8.0, entropy).toFixed(2);
    const pct = Math.min(100, Math.round((entropy / 6.0) * 100));

    entropyValEl.innerText = `${entropyScore} / 8.0 (Normal Telemetry)`;
    entropyFillEl.style.width = `${pct}%`;
  },

  renderRegexPattern(presetKey) {
    const patternBox = document.getElementById('norm-regex-pattern-display');
    if (!patternBox) return;

    const pat = this.formatPatterns[presetKey] || this.formatPatterns.ssh;
    patternBox.innerHTML = Utils.escapeHtml(pat.regex).replace(/\?&lt;([^&]+)&gt;/g, '<span style="color:#C47A16; font-weight:800;">?&lt;$1&gt;</span>');
  },

  renderSchemaOutput(schema) {
    const tableBody = document.getElementById('norm-schema-tbody');
    const jsonPre = document.getElementById('norm-schema-json-code');

    if (jsonPre) {
      jsonPre.innerHTML = this.syntaxHighlightJson(JSON.stringify(schema, null, 2));
    }

    if (tableBody) {
      const fieldIcons = {
        timestamp: 'clock',
        time: 'clock',
        activity_id: 'shield',
        event_type: 'shield',
        severity: 'alert-triangle',
        status: 'check-circle',
        action: 'zap',
        actor: 'user',
        user: 'user',
        target_user: 'user-check',
        source_ip: 'globe',
        src_ip: 'globe',
        destination_ip: 'server',
        dest_ip: 'server',
        source_port: 'radio',
        destination_port: 'radio',
        host: 'laptop',
        process: 'cpu',
        protocol: 'share-2',
        category: 'folder',
        ocsf_class_uid: 'hash'
      };

      const fieldTypes = {
        timestamp: 'TIMESTAMP_ISO',
        activity_id: 'INTEGER_ID',
        event_type: 'EVENT_CLASS',
        severity: 'SEV_LEVEL',
        status: 'STATUS_ENUM',
        action: 'ACTION_STR',
        user: 'IDENTITY_STR',
        target_user: 'IDENTITY_STR',
        source_ip: 'IP_V4',
        src_ip: 'IP_V4',
        destination_ip: 'IP_V4',
        dest_ip: 'IP_V4',
        source_port: 'PORT_NUM',
        destination_port: 'PORT_NUM',
        host: 'HOSTNAME_STR',
        process: 'PROCESS_NAME',
        protocol: 'PROTOCOL_STR',
        category: 'OCSF_CAT_ENUM',
        ocsf_class_uid: 'UID_INT'
      };

      const rows = Object.entries(schema)
        .filter(([k, v]) => v !== null && v !== undefined && v !== '')
        .map(([k, v]) => {
        const displayVal = typeof v === 'object' ? JSON.stringify(v) : String(v);
        let badgeType = 'neutral';
        if (k === 'status') {
          badgeType = (displayVal === 'SUCCESS' || displayVal === 'OK') ? 'green' : 'critical';
        } else if (k === 'severity') {
          badgeType = displayVal === 'CRITICAL' ? 'critical' : displayVal === 'HIGH' ? 'amber' : (displayVal === 'WARNING' ? 'amber' : 'green');
        }

        const iconName = fieldIcons[k.toLowerCase()] || 'tag';
        const typeLabel = fieldTypes[k.toLowerCase()] || 'STRING';

        return `
          <tr data-schema-row="${k.toLowerCase()}">
            <td class="schema-key-cell">
              <span style="display:inline-flex; align-items:center; gap:6px;">
                <i data-lucide="${iconName}" style="width:13px; color:var(--cherry-primary);"></i>
                <code>${k}</code>
                <span class="schema-type-pill">${typeLabel}</span>
              </span>
            </td>
            <td class="schema-val-cell">
              <span class="schema-value-tag ${badgeType}">${Utils.escapeHtml(displayVal)}</span>
            </td>
          </tr>
        `;
      }).join('');

      tableBody.innerHTML = rows;
      if (window.lucide) lucide.createIcons();
    }
  },

  renderAstTree(data) {
    const astBox = document.getElementById('norm-view-ast');
    if (!astBox || !data.schema) return;

    astBox.innerHTML = `
      <div style="padding:14px; font-family:var(--font-mono); font-size:0.75rem; line-height:1.6;">
        <div style="color:var(--cherry-primary); font-weight:800; margin-bottom:8px;">Root::OCSF_Event_Envelope [Class UID: ${data.schema.ocsf_class_uid || 3001}]</div>
        <div style="padding-left:14px; border-left:2px solid var(--border-card);">
          <div style="color:var(--text-muted);">&bull; Metadata::Header &rarr; <span style="color:var(--status-green);">Deterministic (0.04ms)</span></div>
          <div style="color:var(--text-muted);">&bull; EventClass &rarr; <strong style="color:var(--text-ink);">${data.schema.event_type}</strong></div>
          <div style="color:var(--text-muted);">&bull; Network::SourceEndpoint &rarr; <strong style="color:var(--cherry-primary);">${data.schema.source_ip || data.schema.src_ip || 'N/A'}</strong></div>
          <div style="color:var(--text-muted);">&bull; Identity::Subject &rarr; <strong style="color:var(--text-ink);">${data.schema.user || data.schema.target_user || 'system'}</strong></div>
          <div style="color:var(--text-muted);">&bull; Status::Resolution &rarr; <span class="badge-pill ${data.schema.status === 'SUCCESS' ? 'green-pill' : 'crit-pill'}">${data.schema.status || 'OK'}</span></div>
        </div>
      </div>
    `;
  },

  highlightField(fieldKey) {
    if (!fieldKey) return;
    const targetRow = document.querySelector(`[data-schema-row="${fieldKey.toLowerCase()}"]`);
    if (targetRow) {
      targetRow.classList.add('highlight-row');
    }
  },

  clearHighlight() {
    document.querySelectorAll('.schema-table tr.highlight-row').forEach(r => {
      r.classList.remove('highlight-row');
    });
  },

  inspectToken(text, type) {
    this.playHapticBlip(620);
    Utils.showToast(`Inspecting Lexical Token: "${text}" (Inferred Type: ${type.toUpperCase()})`);
  },

  syntaxHighlightJson(jsonStr) {
    return jsonStr
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, (match) => {
        let cls = 'color:#3D2B2E;';
        if (/^"/.test(match)) {
          if (/:$/.test(match)) {
            cls = 'color:#B4233C; font-weight:700;'; // Key
          } else {
            cls = 'color:#25855A; font-weight:600;'; // String
          }
        } else if (/true|false/.test(match)) {
          cls = 'color:#2B6CB0; font-weight:700;'; // Boolean
        } else if (/null/.test(match)) {
          cls = 'color:#756568;';
        } else {
          cls = 'color:#C47A16; font-weight:700;'; // Number
        }
        return `<span style="${cls}">${match}</span>`;
      });
  },

  switchOutputTab(tab) {
    this.activeOutputTab = tab;
    const tabTable = document.getElementById('norm-tab-table');
    const tabJson = document.getElementById('norm-tab-json');
    const tabAst = document.getElementById('norm-tab-ast');
    const viewTable = document.getElementById('norm-view-table');
    const viewJson = document.getElementById('norm-view-json');
    const viewAst = document.getElementById('norm-view-ast');

    if (tabTable) tabTable.classList.toggle('active', tab === 'table');
    if (tabJson) tabJson.classList.toggle('active', tab === 'json');
    if (tabAst) tabAst.classList.toggle('active', tab === 'ast');

    if (viewTable) viewTable.style.display = tab === 'table' ? 'block' : 'none';
    if (viewJson) viewJson.style.display = tab === 'json' ? 'block' : 'none';
    if (viewAst) viewAst.style.display = tab === 'ast' ? 'block' : 'none';
  },

  // 60 FPS 3D Holographic Canvas Loop with Parallax Perspective
  initCanvas3D() {
    if (this.animFrameId) cancelAnimationFrame(this.animFrameId);

    const canvas = document.getElementById('normalizerPipelineCanvas');
    if (!canvas) return;

    const loop = () => {
      if (Navigation.activeScreen === 'normalizer') {
        this.currentTiltX += (this.targetTiltX - this.currentTiltX) * 0.08;
        this.currentTiltY += (this.targetTiltY - this.currentTiltY) * 0.08;
        this.draw3DPipelineCanvasFrame(canvas);
      }
      this.animFrameId = requestAnimationFrame(loop);
    };

    this.animFrameId = requestAnimationFrame(loop);
  },

  draw3DPipelineCanvasFrame(canvas) {
    const rect = canvas.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    const w = rect.width || 800;
    const h = rect.height || 140;

    if (canvas.width !== w * dpr || canvas.height !== h * dpr) {
      canvas.width = w * dpr;
      canvas.height = h * dpr;
    }

    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, w, h);

    const now = Date.now();
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    const tiltX = this.currentTiltX;
    const tiltY = this.currentTiltY;

    // 4 Visual Stages with 3D Holographic Perspective
    const stages = [
      { name: 'RAW INGEST', sub: 'Telemetry Stream', x: w * 0.12 + tiltX * 0.4, y: h * 0.52 + tiltY * 0.4, color: '#C47A16', type: 'vortex' },
      { name: 'REGEX PRISM', sub: 'Lexical Crystal', x: w * 0.38 + tiltX * 0.2, y: h * 0.52 + tiltY * 0.2, color: '#FF6B7A', type: 'crystal' },
      { name: 'FIELD EXTRACTOR', sub: 'Orbital Type-Cast', x: w * 0.64 - tiltX * 0.2, y: h * 0.52 - tiltY * 0.2, color: '#B4233C', type: 'sphere' },
      { name: 'OCSF 1.1 MATRIX', sub: 'Unified Data Stack', x: w * 0.88 - tiltX * 0.4, y: h * 0.52 - tiltY * 0.4, color: '#25855A', type: 'stack' }
    ];

    // 1. Draw 3D Isometric Ground Grid lines
    ctx.strokeStyle = isDark ? 'rgba(232, 160, 170, 0.05)' : 'rgba(116, 21, 42, 0.04)';
    ctx.lineWidth = 1;
    for (let x = 0; x < w; x += 40) {
      ctx.beginPath();
      ctx.moveTo(x + tiltX * 0.2, 10);
      ctx.lineTo(x - tiltX * 0.2, h - 10);
      ctx.stroke();
    }

    // 2. Draw 3D Parabolic Curved Arcs between stages
    for (let i = 0; i < stages.length - 1; i++) {
      const src = stages[i];
      const dst = stages[i + 1];
      const midX = (src.x + dst.x) / 2;
      const midY = (src.y + dst.y) / 2 - 24;

      ctx.beginPath();
      ctx.moveTo(src.x, src.y);
      ctx.quadraticCurveTo(midX, midY, dst.x, dst.y);
      ctx.strokeStyle = isDark ? 'rgba(232, 160, 170, 0.22)' : 'rgba(116, 21, 42, 0.18)';
      ctx.lineWidth = 2.5;
      ctx.stroke();

      // Traveling Glowing Energy Comets
      const cometCount = 3;
      for (let c = 0; c < cometCount; c++) {
        const t = ((now / 1400) + (c / cometCount)) % 1;
        // Quadratic bezier position
        const px = (1 - t) * (1 - t) * src.x + 2 * (1 - t) * t * midX + t * t * dst.x;
        const py = (1 - t) * (1 - t) * src.y + 2 * (1 - t) * t * midY + t * t * dst.y;

        ctx.beginPath();
        ctx.arc(px, py, 3.6, 0, Math.PI * 2);
        ctx.fillStyle = '#FFFFFF';
        ctx.shadowColor = src.color;
        ctx.shadowBlur = 12;
        ctx.fill();
        ctx.shadowBlur = 0;
      }
    }

    // 3. Render 3D Volumetric Nodes
    stages.forEach((st, idx) => {
      const pulse = Math.sin(now / 260 + idx * 1.2) * 2;
      const r = 21 + pulse;

      // Base footprint shadow
      ctx.beginPath();
      ctx.ellipse(st.x, st.y + 20, r * 1.2, r * 0.45, 0, 0, Math.PI * 2);
      ctx.fillStyle = isDark ? 'rgba(0,0,0,0.45)' : 'rgba(116, 21, 42, 0.12)';
      ctx.fill();

      // Outer Rotating Halo Ring
      const rotAngle = (now / 1800) * (idx % 2 === 0 ? 1 : -1);
      ctx.beginPath();
      ctx.ellipse(st.x, st.y, r * 1.6, r * 0.7, rotAngle, 0, Math.PI * 2);
      ctx.strokeStyle = `rgba(${idx === 3 ? '37, 133, 90' : '180, 35, 60'}, 0.35)`;
      ctx.lineWidth = 1.6;
      ctx.stroke();

      // 3D Shaded Center Core
      const grad = ctx.createRadialGradient(st.x - 5, st.y - 5, 2, st.x, st.y, r);
      grad.addColorStop(0, '#FFFFFF');
      grad.addColorStop(0.35, st.color);
      grad.addColorStop(1, idx === 3 ? '#0D3320' : '#4A0814');

      ctx.beginPath();
      ctx.arc(st.x, st.y, r, 0, Math.PI * 2);
      ctx.fillStyle = grad;
      ctx.shadowColor = st.color;
      ctx.shadowBlur = 16;
      ctx.fill();
      ctx.shadowBlur = 0;

      ctx.strokeStyle = '#FFF8F0';
      ctx.lineWidth = 2;
      ctx.stroke();

      // Labels below Node
      ctx.font = '800 11px JetBrains Mono, monospace';
      ctx.fillStyle = isDark ? '#FFF8F0' : '#24191B';
      ctx.textAlign = 'center';
      ctx.fillText(`[${st.name}]`, st.x, st.y + 36);

      ctx.font = '600 9px JetBrains Mono, monospace';
      ctx.fillStyle = isDark ? '#E8A0AA' : '#756568';
      ctx.fillText(st.sub, st.x, st.y + 48);
    });
  }
};

window.Normalizer = Normalizer;
