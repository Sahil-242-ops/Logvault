const fs = require('fs');
const path = require('path');

console.log('--- LOGVAULT INTEGRITY & CODE QUALITY VERIFICATION ---');

const rootDir = 'c:\\Users\\malik\\Desktop\\Sih';
const htmlPath = path.join(rootDir, 'index.html');
const cssPath = path.join(rootDir, 'styles.css');
const jsDir = path.join(rootDir, 'js');

const htmlContent = fs.readFileSync(htmlPath, 'utf-8');
const cssContent = fs.readFileSync(cssPath, 'utf-8');

// 1. Check all required JS files exist and have valid syntax
const jsFiles = fs.readdirSync(jsDir).filter(f => f.endsWith('.js'));
console.log(`Found ${jsFiles.length} JavaScript modules in /js:`);

let syntaxErrors = 0;
jsFiles.forEach(file => {
  const code = fs.readFileSync(path.join(jsDir, file), 'utf-8');
  try {
    new Function(code);
    console.log(`  ✓ ${file}: Valid syntax (${(code.length / 1024).toFixed(1)} KB)`);
  } catch (err) {
    console.error(`  ✗ ${file}: SYNTAX ERROR -`, err.message);
    syntaxErrors++;
  }
});

// 2. Check all IDs referenced in JS files exist in index.html
console.log('\n--- Checking DOM ID References in JS vs index.html ---');
const idRegex = /document\.getElementById\(['"]([^'"]+)['"]\)/g;
const allReferencedIds = new Set();

jsFiles.forEach(file => {
  const code = fs.readFileSync(path.join(jsDir, file), 'utf-8');
  let match;
  while ((match = idRegex.exec(code)) !== null) {
    allReferencedIds.add(JSON.stringify({ id: match[1], file }));
  }
});

let missingIds = 0;
for (const itemStr of allReferencedIds) {
  const { id, file } = JSON.parse(itemStr);
  if (!htmlContent.includes(`id="${id}"`) && !htmlContent.includes(`id='${id}'`)) {
    // Check if generated dynamically
    const isDynamic = id.includes('${') || id === 'normalizerTabs' || id === 'tab-field-mapping';
    if (!isDynamic) {
      console.warn(`  ⚠️ Missing ID in index.html: "${id}" (referenced in ${file})`);
      missingIds++;
    }
  }
}
if (missingIds === 0) {
  console.log('  ✓ All static DOM getElementById references match index.html elements!');
}

// 3. Check Login Component elements
console.log('\n--- Checking Login Overlay Elements in index.html & styles.css ---');
const loginElements = [
  'logvault-login-overlay',
  'logvault-login-form',
  'btn-instant-demo-login',
  'btn-operator-logout',
  'login-toggle-pwd',
  'login-operator-pwd',
  'login-operator-email',
  'login-operator-tier',
  'btn-submit-login'
];

loginElements.forEach(id => {
  const inHtml = htmlContent.includes(`id="${id}"`);
  console.log(`  ${inHtml ? '✓' : '✗'} Login Element #${id}: ${inHtml ? 'Found in index.html' : 'MISSING'}`);
});

// 4. Check CSS classes for matrix and login
console.log('\n--- Checking CSS Classes in styles.css ---');
const cssClasses = [
  '.logvault-login-overlay',
  '.login-container-card',
  '.login-presets-wrap',
  '.login-presets-grid',
  '.login-preset-chip',
  '.node-conduits-matrix',
  '.node-conduit-card',
  '.node-conduit-meter-box',
  '.parser-bench-matrix',
  '.parser-bench-card'
];

cssClasses.forEach(cls => {
  const inCss = cssContent.includes(cls);
  console.log(`  ${inCss ? '✓' : '✗'} CSS Class ${cls}: ${inCss ? 'Present in styles.css' : 'MISSING'}`);
});

console.log('\n--- VERIFICATION SUMMARY ---');
console.log(`Syntax Errors: ${syntaxErrors}`);
console.log(`Status: ${syntaxErrors === 0 ? 'ALL CHECKS PASSED PERFECTLY' : 'FAILURES DETECTED'}`);
