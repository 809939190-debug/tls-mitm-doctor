#!/usr/bin/env node
// tls-mitm-doctor — export the local root CA(s) that intercept TLS, as a PEM bundle
// suitable for NODE_EXTRA_CA_CERTS.
//
// The repository never embeds certificates: the file is generated on the user's machine.
//
// Exit codes: 0 = written / nothing to do, 1 = usage/runtime error.

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { classifyTarget, hostsFrom, makeT, parseArgs, positiveInt } from './lib/common.mjs';

const opt = parseArgs(process.argv.slice(2));
const lang = opt.lang === 'zh' ? 'zh' : 'en';
const t = makeT(lang);

if (opt.help) {
  console.log(t('export.usage'));
  process.exit(0);
}

const hosts = hostsFrom(opt);
if (hosts.length === 0) {
  console.error(t('error.unknownHost'));
  process.exit(1);
}
const port = positiveInt(opt.port, 443, 1, 65535);
const rounds = positiveInt(opt.rounds, 10, 1, 200);
const timeout = positiveInt(opt.timeout, 8000, 1000, 60000);
const out = path.resolve(String(opt.out && opt.out !== true ? opt.out : 'local-roots.pem'));

const roots = new Map();
for (const host of hosts) {
  const result = await classifyTarget({ host, port, rounds, timeout });
  for (const root of result.roots) {
    if (!root.pem || !root.fingerprint256) continue;
    roots.set(root.fingerprint256, root);
  }
}

console.log('');
console.log(t('export.title'));
console.log('='.repeat(68));

if (roots.size === 0) {
  console.log(t('export.none'));
  console.log('');
  console.log(t('export.noneDetail'));
  process.exitCode = 0;
} else {
  const parts = [];
  for (const root of roots.values()) {
    const pem = root.pem.endsWith('\n') ? root.pem : root.pem + '\n';
    parts.push(pem);
  }
  fs.writeFileSync(out, parts.join(''), { encoding: 'utf8' });
  console.log(t('export.found', { count: roots.size, file: out }));
  for (const root of roots.values()) {
    console.log(t('export.entry', { subject: root.subject, fingerprint: root.fingerprint256 }));
  }
  console.log('');
  console.log(t('export.next', { file: out, host: hosts[0], lang }));
  process.exitCode = 0;
}
