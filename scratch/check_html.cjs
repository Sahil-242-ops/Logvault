const fs = require('fs');
const path = require('path');

const html = fs.readFileSync('c:\\Users\\malik\\Desktop\\Sih\\index.html', 'utf-8');

// Find all screen IDs
const screenMatches = [...html.matchAll(/<section[^>]+id="([^"]+)"[^>]*>/g)];
console.log('--- ALL SCREENS IN index.html ---');
screenMatches.forEach(m => console.log('Screen:', m[1]));

// Find all canvas IDs
const canvasMatches = [...html.matchAll(/<canvas[^>]+id="([^"]+)"[^>]*>/g)];
console.log('\n--- ALL CANVASES IN index.html ---');
canvasMatches.forEach(m => console.log('Canvas:', m[1]));

// Check sources section specifically
const sourcesIndex = html.indexOf('screen-sources');
console.log('\nFound screen-sources at index:', sourcesIndex);
if (sourcesIndex !== -1) {
  console.log(html.slice(sourcesIndex, sourcesIndex + 600));
}
