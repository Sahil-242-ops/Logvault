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
      this.setPipelineStageLoading(false);

      if (!response || !response.results || response.results.length === 0) {
        Utils.showToast('No valid logs extracted from file.', 'warning');
        return;
      }

      // Show threats first, then the rest in file order
      const results = response.results.map((r, i) => ({ ...r, _pos: i + 1 }));
      this.batch = { file, response, results, filter: 'all', selectedId: null, aiInFlight: {} };
      this.renderBatchResults();
      const firstThreat = results.find(r => r.anomaly && r.anomaly.is_anomalous);
      this.showBatchRecord((firstThreat || results[0]).id, true);

      const s = response.stats;
      Utils.showToast(`Processed ${s.total_records} records from ${file.name} in ${Math.round(response.processing_time_ms)} ms.`, 'success');

      // Refresh live logs and dashboard
      if (window.LogStream && LogStream.fetchLogs) LogStream.fetchLogs();
      if (window.App && App.renderDashboardElements) App.renderDashboardElements();

      if (response.anomaly_summary && response.anomaly_summary.anomalous > 0) {
        setTimeout(() => {
          Utils.showToast(`⚠ Detected ${response.anomaly_summary.anomalous} anomalous events. AI is investigating them in the Alert Center.`, 'warning');
        }, 1500);
      }
    } catch (err) {
      this.setPipelineStageLoading(false);
      Utils.showToast(`Upload failed: ${err.message}`, 'error');
    }
  },

  // Backend record -> the view model used by animateAndRenderPipeline / renderRealLogResultCard
  toViewModel(r, label) {
    const rawText = r.raw_log || r.message || JSON.stringify(r);
    const tokens = rawText.split(/[\s,]+/).map(t => {
      let type = 'generic'; let mappedField = null;
      if (t.includes(':') && !t.startsWith('http')) { type = 'process'; mappedField = 'process'; }
      if (t.includes('=')) { type = 'keyval'; mappedField = 'metadata'; }
      if (/\d+\.\d+\.\d+\.\d+/.test(t)) { type = 'src_ip'; mappedField = 'source_ip'; }
      if (/\d{2}:\d{2}:\d{2}/.test(t)) { type = 'timestamp'; mappedField = 'timestamp'; }
      return { text: t, type, mappedField };
    });
    return {
      name: label,
      raw: rawText,
      tokens,
      format: r.detected_format || 'Unknown',
      parser: r.parser_name || 'Backend Parser',
      parserType: r.parser_type || 'DETERMINISTIC',
      latency: (r.processing_latency_ms || 0).toFixed(2) + ' ms',
      confidence: r.parse_confidence || r.detection_confidence || 0,
      ocsf_class: r.ocsf_class_name || null,
      ocsf_class_uid: r.ocsf_class_uid || null,
      anomaly: r.anomaly || null,
      pii_masked: r.pii_masked || false,
      ai_provider: r.ai_provider || 'none',
      ai_model: r.ai_model || 'none',
      ai_reasoning: r.ai_reasoning || r.ai_threat_reasoning || '',
      ai_threat_score: r.ai_threat_score,
      ai_mitre_techniques: r.ai_mitre_techniques || [],
      ai_is_suspicious: r.ai_is_suspicious || false,
      schema: {
        event_type: r.event_type || 'GENERIC_EVENT',
        user: r.user || 'unknown',
        status: r.status || r.action || 'RECORDED',
        source_ip: r.source_ip || null,
        source_port: r.source_port || null,
        destination_ip: r.destination_ip || null,
        destination_port: r.destination_port || null,
        host: r.host || null,
        process: r.process || null,
        protocol: r.protocol || null,
        timestamp: r.timestamp || new Date().toISOString(),
        severity: r.severity || 'INFO',
        category: r.category || 'general_telemetry',
        message: r.message || null
      },
      _raw_backend: r
    };
  },

  showBatchRecord(id, animate = false) {
    if (!this.batch) return;
    const r = this.batch.results.find(x => x.id === id);
    if (!r) return;
    this.batch.selectedId = id;
    const vm = this.toViewModel(r, `Record ${r._pos} of ${this.batch.response.stats.total_records}: ${this.batch.file.name}`);
    if (animate) {
      this.animateAndRenderPipeline(vm);
    } else {
      this.currentData = vm;
      this.renderRealLogResultCard(vm);
      this.renderSchemaOutput(vm.schema);
    }
    document.querySelectorAll('.batch-row').forEach(row => row.classList.toggle('selected', row.dataset.id === id));
    this.requestRecordAi(r);
  },

  // Local AI runs per viewed record in the background, so uploads stay instant
  async requestRecordAi(r) {
    const stateEl = document.getElementById('res-ai-state');
    const analysisEl = document.getElementById('res-ai-analysis');
    if (r.ai_provider === 'ollama' || !r.id) {
      if (stateEl) stateEl.innerText = 'LOCAL OLLAMA INFERENCE';
      return;
    }
    if (stateEl) stateEl.innerText = 'ANALYSING…';
    if (analysisEl) analysisEl.innerText = 'Local AI is analysing this record. Parsing, rules and OCSF mapping above are already complete.';

    const batch = this.batch;
    if (!batch.aiInFlight[r.id]) {
      batch.aiInFlight[r.id] = LogVaultAPI._postJSON(`/api/events/${encodeURIComponent(r.id)}/ai-analyze`, {}, 60000)
        .catch(err => ({ _error: err.message }));
    }
    const enriched = await batch.aiInFlight[r.id];
    if (this.batch !== batch) return;  // a new file was uploaded meanwhile

    if (enriched && !enriched._error) {
      const idx = batch.results.findIndex(x => x.id === r.id);
      if (idx >= 0) batch.results[idx] = { ...enriched, _pos: batch.results[idx]._pos };
      this.renderBatchResults();
    } else {
      delete batch.aiInFlight[r.id];
    }

    if (batch.selectedId !== r.id) return;  // user moved on to another record
    const current = batch.results.find(x => x.id === r.id);
    this.currentData = this.toViewModel(current, `Record ${current._pos}: ${batch.file.name}`);
    this.renderRealLogResultCard(this.currentData);
    this.renderSchemaOutput(this.currentData.schema);
    if (stateEl) stateEl.innerText = current.ai_provider === 'ollama' ? 'LOCAL OLLAMA INFERENCE' : 'AI UNAVAILABLE';
    if (enriched && enriched._error && analysisEl) {
      analysisEl.innerText = `Local AI analysis failed (${enriched._error}). Deterministic results above are complete.`;
    }
  },

  renderBatchResults() {
    const card = document.getElementById('batch-results-card');
    const list = document.getElementById('batch-results-list');
    if (!card || !list || !this.batch) return;
    const { response, results, filter, selectedId } = this.batch;
    const s = response.stats;
    card.hidden = false;

    const layoutLabel = {
      'json-document': 'JSON document', 'json-lines': 'JSON Lines',
      'csv-with-header': 'CSV with header', 'line-per-record': 'one record per line'
    }[response.file.layout] || response.file.layout;
    const setText = (id, text) => { const el = document.getElementById(id); if (el) el.innerText = text; };
    setText('batch-results-title', response.file.filename.toUpperCase());
    setText('batch-results-meta',
      `${s.total_records} records (${layoutLabel}) • ${s.successful_records} parsed • ${s.failed_records} unparsed • ` +
      `${s.threats_found} threats • ${Math.round(response.processing_time_ms)} ms`);

    const chips = document.getElementById('batch-format-chips');
    if (chips) {
      chips.innerHTML = Object.entries(s.detected_formats)
        .map(([fmt, n]) => `<span class="badge-pill ${fmt === 'unknown' ? 'warn-pill' : 'neutral-pill'}">${Utils.escapeHtml(fmt.toUpperCase())} × ${n}</span>`)
        .join('');
    }

    const visible = results.filter(r => filter === 'all'
      || (filter === 'threats' && r.anomaly && r.anomaly.is_anomalous)
      || (filter === 'unparsed' && r.detected_format === 'unknown'));

    const sevPill = (sev) => ({ CRITICAL: 'crit-pill', HIGH: 'high-pill', MEDIUM: 'warn-pill', LOW: 'green-pill' })[sev] || 'neutral-pill';
    list.innerHTML = visible.length ? visible.map(r => {
      const threat = Math.max(r.ai_threat_score || 0, (r.anomaly && r.anomaly.threat_score) || 0);
      const anomalous = r.anomaly && r.anomaly.is_anomalous;
      return `
        <div class="batch-row${r.id === selectedId ? ' selected' : ''}${anomalous ? ' is-threat' : ''}" data-id="${Utils.escapeHtml(r.id)}" role="button" tabindex="0">
          <span class="batch-pos">#${r._pos}</span>
          <span class="badge-pill ${r.detected_format === 'unknown' ? 'warn-pill' : 'gold-pill'} batch-fmt">${Utils.escapeHtml((r.detected_format || '?').toUpperCase())}</span>
          <span class="batch-type">${Utils.escapeHtml(r.event_type || 'GENERIC_EVENT')}</span>
          <span class="badge-pill ${sevPill(r.severity)}">${Utils.escapeHtml(r.severity || 'INFO')}</span>
          <span class="batch-threat${threat >= 50 ? ' hot' : ''}">${threat}</span>
          <span class="batch-ai" title="${r.ai_provider === 'ollama' ? 'Analysed by local AI' : 'Not yet analysed by AI'}">${r.ai_provider === 'ollama' ? '<i data-lucide="brain"></i>' : ''}</span>
          <span class="batch-raw">${Utils.escapeHtml(String(r.raw_log || '').substring(0, 140))}</span>
        </div>`;
    }).join('') : '<div class="kanban-empty">No records match this filter.</div>';

    list.querySelectorAll('.batch-row').forEach(row => {
      row.addEventListener('click', () => this.showBatchRecord(row.dataset.id));
      row.addEventListener('keydown', (e) => { if (e.key === 'Enter') this.showBatchRecord(row.dataset.id); });
    });

    card.querySelectorAll('[data-batch-filter]').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.batchFilter === filter);
      btn.onclick = () => { this.batch.filter = btn.dataset.batchFilter; this.renderBatchResults(); };
    });

    setText('batch-results-foot', response.results_truncated
      ? `Showing the first ${results.length} of ${s.total_records} records. All ${s.total_records} are stored; see Live Log Stream.`
      : 'Click a record to inspect it. Local AI analyses the record you open.');
    if (window.lucide) lucide.createIcons();
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

    const threatScore = Math.max(data.ai_threat_score || 0, data.anomaly?.threat_score || 0);
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

    // Rule findings first (deterministic evidence), then the local model's opinion
    const reasoning = /^AI skipped for bulk upload/.test(data.ai_reasoning || '') ? '' : data.ai_reasoning;
    const ruleFindings = (data.anomaly?.findings || []).filter(f => f.rule_name && !/^Ollama AI/.test(f.rule_name));
    const parts = [];
    if (ruleFindings.length) {
      parts.push('Detection rules: ' + ruleFindings.map(f => f.rule_name + (f.mitre_technique ? ` (${f.mitre_technique})` : '')).join('; ') + '.');
    }
    if (reasoning) parts.push((ruleFindings.length ? 'Local AI: ' : '') + reasoning);
    const aiAnalysis = parts.join('\n') || 'No threat indicators found by detection rules or local AI.';
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
