#!/usr/bin/env node
/** tsc -> dist (ESM + .d.ts). tsc does not copy hand-written/generated .d.ts files, so
 * src/schema.d.ts is copied next to the emitted declarations afterwards. */
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
fs.rmSync(path.join(root, 'dist'), { recursive: true, force: true });
const tsc = path.join(root, 'node_modules', 'typescript', 'bin', 'tsc');
execFileSync(process.execPath, [tsc, '-p', path.join(root, 'tsconfig.build.json')], { stdio: 'inherit' });
fs.copyFileSync(path.join(root, 'src/schema.d.ts'), path.join(root, 'dist/schema.d.ts'));
console.log('built dist/');
