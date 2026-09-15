/**
 * LOGVAULT — Local AI Model Adapter
 * Provider abstraction for local AI models (Ollama, llama.cpp, etc.)
 * NEVER calls cloud APIs. All inference is local.
 */

import http from 'http';

/**
 * Supported local AI backends.
 * Each adapter must implement: isAvailable(), generate(prompt, options)
 */

// --- Ollama Adapter ---
class OllamaAdapter {
  constructor(config = {}) {
    this.name = 'ollama';
    this.host = config.host || '127.0.0.1';
    this.port = config.port || 11434;
    this.model = config.model || 'llama3.2';
    this.timeout = config.timeout || 30000;
  }

  async isAvailable() {
    try {
      const response = await this._request('GET', '/api/tags', null, 3000);
      if (response && response.models) {
        const modelNames = response.models.map(m => m.name.split(':')[0]);
        const hasModel = modelNames.some(n =>
          n === this.model || n.startsWith(this.model)
        );
        return {
          available: true,
          hasModel,
          models: response.models.map(m => m.name),
          selectedModel: this.model
        };
      }
      return { available: false, hasModel: false, models: [], selectedModel: this.model };
    } catch {
      return { available: false, hasModel: false, models: [], selectedModel: this.model };
    }
  }

  async generate(prompt, options = {}) {
    const model = options.model || this.model;
    const body = {
      model,
      prompt,
      stream: false,
      options: {
        temperature: options.temperature || 0.1,
        num_predict: options.maxTokens || 1024,
        top_p: 0.9,
        stop: options.stop || []
      },
      format: 'json'
    };

    const response = await this._request('POST', '/api/generate', body, this.timeout);

    if (response && response.response) {
      return {
        text: response.response,
        model: response.model || model,
        eval_count: response.eval_count,
        eval_duration: response.eval_duration,
        total_duration: response.total_duration,
        provider: 'ollama'
      };
    }

    throw new Error('Empty response from Ollama');
  }

  _request(method, path, body, timeout) {
    return new Promise((resolve, reject) => {
      const options = {
        hostname: this.host,
        port: this.port,
        path,
        method,
        headers: { 'Content-Type': 'application/json' },
        timeout: timeout || this.timeout
      };

      const req = http.request(options, (res) => {
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end', () => {
          try {
            resolve(JSON.parse(data));
          } catch {
            resolve({ raw: data });
          }
        });
      });

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Request timeout'));
      });

      if (body) {
        req.write(JSON.stringify(body));
      }
      req.end();
    });
  }
}

// --- LlamaCpp HTTP Adapter (llama.cpp server mode) ---
class LlamaCppAdapter {
  constructor(config = {}) {
    this.name = 'llama.cpp';
    this.host = config.host || '127.0.0.1';
    this.port = config.port || 8080;
    this.timeout = config.timeout || 30000;
  }

  async isAvailable() {
    try {
      const response = await this._request('GET', '/health', null, 3000);
      return {
        available: response && response.status === 'ok',
        hasModel: true,
        models: ['local-gguf'],
        selectedModel: 'local-gguf'
      };
    } catch {
      return { available: false, hasModel: false, models: [], selectedModel: 'local-gguf' };
    }
  }

  async generate(prompt, options = {}) {
    const body = {
      prompt,
      temperature: options.temperature || 0.1,
      n_predict: options.maxTokens || 1024,
      top_p: 0.9,
      stop: options.stop || ['```', '\n\n\n'],
      stream: false
    };

    const response = await this._request('POST', '/completion', body, this.timeout);

    if (response && response.content) {
      return {
        text: response.content,
        model: 'local-gguf',
        tokens_predicted: response.tokens_predicted,
        provider: 'llama.cpp'
      };
    }

    throw new Error('Empty response from llama.cpp');
  }

  _request(method, path, body, timeout) {
    return new Promise((resolve, reject) => {
      const options = {
        hostname: this.host,
        port: this.port,
        path,
        method,
        headers: { 'Content-Type': 'application/json' },
        timeout: timeout || this.timeout
      };

      const req = http.request(options, (res) => {
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end', () => {
          try {
            resolve(JSON.parse(data));
          } catch {
            resolve({ raw: data });
          }
        });
      });

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Request timeout'));
      });

      if (body) {
        req.write(JSON.stringify(body));
      }
      req.end();
    });
  }
}

// --- Model Adapter Manager ---
class ModelAdapterManager {
  constructor() {
    this.adapters = [];
    this.activeAdapter = null;
    this.status = {
      mode: 'DETERMINISTIC',
      provider: null,
      model: null,
      available: false
    };
  }

  /**
   * Register a local AI adapter.
   */
  registerAdapter(adapter) {
    this.adapters.push(adapter);
  }

  /**
   * Probe all registered adapters and select the first available one.
   */
  async probe() {
    for (const adapter of this.adapters) {
      try {
        const check = await adapter.isAvailable();
        if (check.available && check.hasModel) {
          this.activeAdapter = adapter;
          this.status = {
            mode: 'LOCAL_AI',
            provider: adapter.name,
            model: check.selectedModel || check.models[0],
            available: true,
            models: check.models
          };
          console.log(`[AI] Local AI active: ${adapter.name} (model: ${this.status.model})`);
          return this.status;
        } else if (check.available && !check.hasModel) {
          console.log(`[AI] ${adapter.name} is running but model '${check.selectedModel}' not found. Available: ${check.models.join(', ')}`);
        }
      } catch (err) {
        console.log(`[AI] ${adapter.name} not available: ${err.message}`);
      }
    }

    this.activeAdapter = null;
    this.status = {
      mode: 'DETERMINISTIC',
      provider: null,
      model: null,
      available: false
    };
    console.log('[AI] No local AI available — falling back to deterministic parsing');
    return this.status;
  }

  /**
   * Generate a response using the active adapter.
   * Returns null if no adapter is available.
   */
  async generate(prompt, options = {}) {
    if (!this.activeAdapter) return null;

    try {
      return await this.activeAdapter.generate(prompt, options);
    } catch (err) {
      console.error(`[AI] Generation error: ${err.message}`);
      return null;
    }
  }

  getStatus() {
    return { ...this.status };
  }

  isAvailable() {
    return this.status.available;
  }
}

// --- Singleton instance ---
const manager = new ModelAdapterManager();

// Register default adapters (Ollama first, then llama.cpp)
manager.registerAdapter(new OllamaAdapter({
  model: process.env.LOGVAULT_AI_MODEL || 'llama3.2'
}));
manager.registerAdapter(new LlamaCppAdapter());

export default manager;
export { OllamaAdapter, LlamaCppAdapter, ModelAdapterManager };
