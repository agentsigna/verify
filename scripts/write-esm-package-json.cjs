const { mkdirSync, writeFileSync } = require('node:fs');
const { join } = require('node:path');

const esmDir = join(__dirname, '..', 'dist', 'esm');
mkdirSync(esmDir, { recursive: true });
writeFileSync(join(esmDir, 'package.json'), JSON.stringify({ type: 'module' }, null, 2) + '\n');
