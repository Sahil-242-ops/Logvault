const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const chromePath = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
const outDir = path.join(__dirname, 'test_out');
if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

const targetFile = path.join(outDir, 'shot.png');
console.log('Testing chrome screenshot to:', targetFile);

try {
  execSync(`"${chromePath}" --headless --disable-gpu --screenshot="${targetFile}" --window-size=1600,1000 "http://localhost:3000/?theme=cream#dashboard"`, { stdio: 'inherit' });
  console.log('Done. Exists:', fs.existsSync(targetFile));
  if (fs.existsSync(targetFile)) {
    console.log('File size:', fs.statSync(targetFile).size);
  }
} catch (e) {
  console.error('Error:', e);
}
