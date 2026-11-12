#!/usr/bin/env node
// tls-mitm-doctor — detect local TLS interception (security software / corporate proxy)
// that breaks Node.js & Electron apps, and tell the user how to fix it.
//
// Exit codes: 0 = clean, 2 = interception detected, 1 = usage/runtime error.

import process from 'node:process';
import {
  VERSION,
  classifyTarget,
  hostsFrom,
  makeT,
  parseArgs,
  positiveInt,
  processTrustHints,
} from './lib/common.mjs';

const opt = parseArgs(process.argv.slice(2));
const lang = opt.lang === 'zh' ? 'zh' : 'en';
const t = makeT(lang);

if (opt.help) {
  console.log(t('doctor.usage'));
  process.exit(0);
}

const hosts = hostsFrom(opt);
if (hosts.length === 0) {
  console.error(t('error.unknownHost'));
  process.exit(1);
}
const port = positiveInt(opt.port, 443, 1, 65535);
const rounds = positiveInt(opt.rounds, 12, 1, 200);
const timeout = positiveInt(opt.timeout, 8000, 1000, 60000);
const json = Boolean(opt.json);

const report = { version: VERSION, generatedAt: new Date().toISOString(), hosts: [] };
let detected = false;

for (const host of hosts) {
  const result = await classifyTarget({ host, port, rounds, timeout });
  report.hosts.push(result);
  detected = detected || result.intercepted > 0;

  if (json) continue;

  const hints = processTrustHints();
  console.log('');
  console.log(t('doctor.title', { version: VERSION }));
  console.log('='.repeat(68));
  console.log(t('doctor.target', { host, port, rounds }));
  console.log(
    t('doctor.counts', {
      clean: result.clean,
      intercepted: result.intercepted,
      verifyFailed: result.verifyFailed,
      errors: result.handshakeErrors,
    }),
  );

  if (result.systemRootCount === 0) {
    console.log('');
    console.log(t('doctor.noStore'));
  }

  if (result.intercepted > 0) {
    console.log('');
    console.log(t('doctor.detected'));
    console.log('');
    console.log(t('doctor.explain'));
    console.log('');
    console.log(t('doctor.rootsHeader'));
    for (const root of result.roots) {
      if (!root.fingerprint256) continue;
      console.log(
        t('doctor.rootLine', {
          subject: root.subject,
          fingerprint: root.fingerprint256,
          count: root.count,
          rounds: result.rounds,
        }),
      );
    }
    if (result.interceptedButTrusted && hints.length > 0) {
      console.log(t('doctor.trustedNote', { hints: hints.join(', ') }));
    }
    if (result.verifyErrors.length > 0) {
      console.log('');
      console.log(t('doctor.verifyErrorsHeader'));
      for (const item of result.verifyErrors) {
        console.log(t('doctor.verifyErrorLine', { code: item.code, count: item.count }));
      }
    }
    console.log('');
    console.log(t('doctor.fixHeader'));
    console.log('');
    console.log(t('doctor.fix1'));
    console.log('');
    console.log(t('doctor.fix2', { host }));
    console.log('');
    console.log(t('doctor.fix3'));
    console.log('');
    console.log(t('doctor.warning'));
  } else {
    console.log('');
    console.log(t('doctor.clean'));
    if (result.verifyFailed > 0 || result.handshakeErrors > 0) {
      console.log('');
      console.log(t('doctor.verifyErrorsHeader'));
      for (const item of result.verifyErrors) {
        console.log(t('doctor.verifyErrorLine', { code: item.code, count: item.count }));
      }
    }
  }
  console.log('');
}

if (json) console.log(JSON.stringify(report, null, 2));
process.exitCode = detected ? 2 : 0;
