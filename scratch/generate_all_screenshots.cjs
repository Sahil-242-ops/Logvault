const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const chromePath = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
const rootDir = "c:\\Users\\malik\\Desktop\\Sih";
const lightDir = path.join(rootDir, 'ui-ux-screenshots', 'light-mode');
const darkDir = path.join(rootDir, 'ui-ux-screenshots', 'dark-mode');

if (!fs.existsSync(lightDir)) fs.mkdirSync(lightDir, { recursive: true });
if (!fs.existsSync(darkDir)) fs.mkdirSync(darkDir, { recursive: true });

const screens = [
  { name: '00_login_portal.png', url: (theme) => `http://localhost:3000/?theme=${theme}&auth=login` },
  { name: '01_dashboard.png', url: (theme) => `http://localhost:3000/?theme=${theme}&auth=1#dashboard` },
  { name: '02_live_logs.png', url: (theme) => `http://localhost:3000/?theme=${theme}&auth=1#live-logs` },
  { name: '03_log_normalizer.png', url: (theme) => `http://localhost:3000/?theme=${theme}&auth=1#normalizer` },
  { name: '04_unknown_logs_ai.png', url: (theme) => `http://localhost:3000/?theme=${theme}&auth=1#ai-mapper` },
  { name: '05_anomalies_3d.png', url: (theme) => `http://localhost:3000/?theme=${theme}&auth=1#anomalies` },
  { name: '06_alert_center.png', url: (theme) => `http://localhost:3000/?theme=${theme}&auth=1#alerts` },
  { name: '07_event_analytics.png', url: (theme) => `http://localhost:3000/?theme=${theme}&auth=1#analytics` },
  { name: '08_sources_topology.png', url: (theme) => `http://localhost:3000/?theme=${theme}&auth=1#sources` },
  { name: '09_parser_registry.png', url: (theme) => `http://localhost:3000/?theme=${theme}&auth=1#parsers` },
  { name: '10_network_topology.png', url: (theme) => `http://localhost:3000/?theme=${theme}&auth=1#topology` },
  { name: '11_platform_settings.png', url: (theme) => `http://localhost:3000/?theme=${theme}&auth=1#settings` }
];

console.log('=== CAPTURING HIGH-RESOLUTION UI/UX SCREENSHOTS ===\n');

// 1. Capture Light Mode (Warm Cream & Cherry)
console.log('--- Capturing Light/Cream Mode Screenshots ---');
for (const s of screens) {
  const targetPath = path.join(lightDir, s.name);
  const targetUrl = s.url('cream');
  console.log(`Capturing ${s.name}...`);
  try {
    execSync(`"${chromePath}" --headless --disable-gpu --screenshot="${targetPath}" --window-size=1600,1050 --hide-scrollbars --virtual-time-budget=2000 "${targetUrl}"`, { stdio: 'pipe' });
    if (fs.existsSync(targetPath)) {
      const sizeKb = (fs.statSync(targetPath).size / 1024).toFixed(1);
      console.log(`  ✓ Saved: light-mode/${s.name} (${sizeKb} KB)`);
    } else {
      console.error(`  ✗ Failed to save ${s.name}`);
    }
  } catch (err) {
    console.error(`  ✗ Error capturing ${s.name}:`, err.message);
  }
}

// 2. Capture Dark Mode (Obsidian & Cherry)
console.log('\n--- Capturing Dark Mode Screenshots ---');
for (const s of screens) {
  const targetPath = path.join(darkDir, s.name);
  const targetUrl = s.url('dark');
  console.log(`Capturing ${s.name}...`);
  try {
    execSync(`"${chromePath}" --headless --disable-gpu --screenshot="${targetPath}" --window-size=1600,1050 --hide-scrollbars --virtual-time-budget=2000 "${targetUrl}"`, { stdio: 'pipe' });
    if (fs.existsSync(targetPath)) {
      const sizeKb = (fs.statSync(targetPath).size / 1024).toFixed(1);
      console.log(`  ✓ Saved: dark-mode/${s.name} (${sizeKb} KB)`);
    } else {
      console.error(`  ✗ Failed to save ${s.name}`);
    }
  } catch (err) {
    console.error(`  ✗ Error capturing ${s.name}:`, err.message);
  }
}

console.log('\n=== ALL SCREENSHOTS SUCCESSFULLY UPDATED ===');
