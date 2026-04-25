#!/usr/bin/env node
'use strict';

// GRC Assessment Platform — CLI entry point
// Launched when user runs: npx grc-assessment-server
// or: grc-assessment-server (if globally installed)

const path = require('path');
const fs   = require('fs');

// Ensure data and uploads directories exist in the working directory
const cwd = process.cwd();
['data', 'uploads'].forEach(dir => {
  const p = path.join(cwd, dir);
  if (!fs.existsSync(p)) {
    fs.mkdirSync(p, { recursive: true });
    console.log(`[grc] Created directory: ${dir}/`);
  }
});

// Set working directory context for server.js to resolve paths correctly
process.env.GRC_DATA_DIR    = process.env.GRC_DATA_DIR    || path.join(cwd, 'data');
process.env.GRC_UPLOADS_DIR = process.env.GRC_UPLOADS_DIR || path.join(cwd, 'uploads');

// Print startup info
const pkg = require('./package.json');
console.log(`\nGRC Assessment Platform v${pkg.version}`);
console.log(`Starting server — open http://localhost:${process.env.PORT || 3000} in your browser\n`);

// Boot the server
require('./server.js');
