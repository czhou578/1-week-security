import fs from 'fs';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';

// Get __dirname equivalent in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log('🔒 Adding SRI to your HTML...');

const distDir = path.join(__dirname, '../dist');
const indexPath = path.join(distDir, 'index.html');

if (!fs.existsSync(indexPath)) {
  console.error('❌ dist/index.html not found. Run npm run build first');
  process.exit(1);
}

let html = fs.readFileSync(indexPath, 'utf8');
let changes = 0;

// Function to generate SRI hash
function generateSRI(filePath) {
  const content = fs.readFileSync(filePath);
  const hash = crypto.createHash('sha384').update(content).digest('base64');
  return `sha384-${hash}`;
}

// Add SRI to script tags
html = html.replace(/<script([^>]*) src="([^"]*)"([^>]*)>/g, (match, before, src, after) => {
  if (!match.includes('integrity=')) {
    const filePath = path.join(distDir, src);
    if (fs.existsSync(filePath)) {
      const integrity = generateSRI(filePath);
      changes++;
      console.log(`✅ Added SRI to script: ${src}`);
      return `<script${before} src="${src}"${after} integrity="${integrity}" crossorigin="anonymous">`;
    }
  }
  return match;
});

// Add SRI to CSS link tags  
html = html.replace(/<link([^>]*) href="([^"]*\.css)"([^>]*)>/g, (match, before, href, after) => {
  if (!match.includes('integrity=')) {
    const filePath = path.join(distDir, href);
    if (fs.existsSync(filePath)) {
      const integrity = generateSRI(filePath);
      changes++;
      console.log(`✅ Added SRI to CSS: ${href}`);
      return `<link${before} href="${href}"${after} integrity="${integrity}" crossorigin="anonymous">`;
    }
  }
  return match;
});

// Write the updated HTML
if (changes > 0) {
  fs.writeFileSync(indexPath, html);
  console.log(`🎉 SRI added to ${changes} files!`);
  console.log('📋 Your HTML is now protected against tampering');
} else {
  console.log('ℹ️ No changes needed - SRI already present');
}
