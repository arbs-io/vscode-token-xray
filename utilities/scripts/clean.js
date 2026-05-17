const fs = require('node:fs');
const path = require('node:path');

const folders = [
  '../../dist',
  '../../out',
  '../../node_modules',
];

folders.forEach((folder) => {
  const dir = path.join(__dirname, folder);
  if (fs.existsSync(dir)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
