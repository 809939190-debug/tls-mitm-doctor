// Shared helpers for tls-mitm-doctor.
// No third-party dependencies: Node's tls / crypto / child_process only.

import tls from 'node:tls';
import crypto from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import process from 'node:process';

const execFileAsync = promisify(execFile);

export const VERSION = '0.1.0';

/** Minimal argv parser: supports `--key value`, `--key=value` and boolean flags. */
export function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-h' || a === '--help') { out.help = true; continue; }
    if (!a.startsWith('--')) { out._.push(a); continue; }
    const eq = a.indexOf('=');
    let key;
    let value;
    if (eq !== -1) {
      key = a.slice(2, eq);
      value = a.slice(eq + 1);
    } else {
      key = a.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith('--')) { value = next; i++; }
      else value = true;
    }
    out[key] = value;
  }
  return out;
}

export function hostsFrom(opt, fallback = 'example.com') {
  const raw = opt.host === undefined || opt.host === true ? fallback : String(opt.host);
  return raw.split(',').map((s) => s.trim()).filter(Boolean);
}

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function positiveInt(value, fallback, min, max) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < min || n > max) return fallback;
  return n;
}

/** Walk the peer certificate chain returned by `tls.TLSSocket#getPeerCertificate(true)`. */
export function walkChain(peer) {
  const out = [];
  const seen = new Set();
  let cur = peer;
  while (cur && Buffer.isBuffer(cur.raw)) {
    const fp = cur.fingerprint256;
    if (fp && seen.has(fp)) break;
    if (fp) seen.add(fp);
    out.push(cur.raw);
    cur = cur.issuerCertificate;
  }
  return out;
}

/**
 * One TLS handshake. Returns { ok, chain?, error? }.
 * `chain` is an array of DER buffers (leaf → root).
 */
export function probeOnce({ host, port = 443, timeout = 8000, verify = false }) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };
    let socket;
    try {
      socket = tls.connect({ host, port, servername: host, rejectUnauthorized: verify, timeout });
    } catch (error) {
      finish({ ok: false, error });
      return;
    }
    socket.once('secureConnect', () => {
      let chain = [];
      try {
        chain = walkChain(socket.getPeerCertificate(true));
      } catch {
        chain = [];
      }
      socket.end();
      finish({ ok: true, chain });
    });
    socket.once('error', (error) => finish({ ok: false, error }));
    socket.once('timeout', () => {
      socket.destroy();
      const error = new Error('TLS handshake timed out');
      error.code = 'ETIMEDOUT';
      finish({ ok: false, error });
    });
  });
}

function pemFromDer(der) {
  const b64 = der.toString('base64').replace(/(.{64})/g, '$1\n').replace(/\n$/, '');
  return `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`;
}

/** Read the Windows "Trusted Root Certification Authorities" store via PowerShell. */
async function readWindowsRootStore() {
  const script = [
    '[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;',
    '$list = Get-ChildItem Cert:\\LocalMachine\\Root | ForEach-Object {',
    '  [PSCustomObject]@{ raw = [Convert]::ToBase64String($_.RawData) }',
    '};',
    'ConvertTo-Json -InputObject @($list) -Compress',
  ].join(' ');
  const { stdout } = await execFileAsync(
    'powershell.exe',
    ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script],
    { timeout: 20000, maxBuffer: 16 * 1024 * 1024, windowsHide: true },
  );
  const text = stdout.trim().replace(/^\uFEFF/, '');
  if (!text) return [];
  const parsed = JSON.parse(text);
  const entries = Array.isArray(parsed) ? parsed : [parsed];
  return entries
    .map((entry) => entry && entry.raw)
    .filter((raw) => typeof raw === 'string' && raw.length > 0)
    .map((raw) => pemFromDer(Buffer.from(raw, 'base64')));
}

/**
 * Locally installed root CAs (the Windows store, or the platform store Node can read).
 * Returns Map<sha256Fingerprint, { subject, issuer, selfSigned, pem }>.
 */
export async function loadSystemRoots() {
  const map = new Map();
  const pems = [];
  if (typeof tls.getCACertificates === 'function') {
    try {
      pems.push(...tls.getCACertificates('system'));
    } catch {
      // fall through to platform fallback
    }
  }
  if (pems.length === 0 && process.platform === 'win32') {
    try {
      pems.push(...(await readWindowsRootStore()));
    } catch {
      // leave empty; caller reports the limitation
    }
  }
  for (const pem of pems) {
    try {
      const x = new crypto.X509Certificate(pem);
      map.set(x.fingerprint256, {
        subject: x.subject,
        issuer: x.issuer,
        selfSigned: x.subject === x.issuer,
        pem,
      });
    } catch {
      // ignore unparseable entries
    }
  }
  return map;
}

/** Fingerprints of the CAs Node.js trusts out of the box (bundled Mozilla roots).
 *  Uses the `bundled` list, NOT `default` — `default` also contains certificates
 *  injected through NODE_EXTRA_CA_CERTS / NODE_USE_SYSTEM_CA, which would hide the
 *  very interception this tool is looking for. */
export function loadBundledRootFingerprints() {
  const set = new Set();
  let pems = [];
  if (typeof tls.getCACertificates === 'function') {
    try {
      pems = tls.getCACertificates('bundled');
    } catch {
      pems = [];
    }
  }
  if (pems.length === 0) pems = crypto.rootCertificates ?? [];
  for (const pem of pems) {
    try {
      set.add(new crypto.X509Certificate(pem).fingerprint256);
    } catch {
      // ignore
    }
  }
  return set;
}

/** True when the current process has been told to trust extra roots. */
export function processTrustHints() {
  const hints = [];
  if (process.env.NODE_EXTRA_CA_CERTS) hints.push('NODE_EXTRA_CA_CERTS');
  if (process.env.NODE_USE_SYSTEM_CA) hints.push('NODE_USE_SYSTEM_CA');
  if (process.env.NODE_OPTIONS && /use-system-ca/u.test(process.env.NODE_OPTIONS)) hints.push('NODE_OPTIONS=--use-system-ca');
  return hints;
}

function certificateInfo(der, systemRoots, bundled) {
  try {
    const x = new crypto.X509Certificate(der);
    const fp = x.fingerprint256;
    const oneLine = (name) => name.replace(/\n/g, ', ');
    return {
      subject: oneLine(x.subject),
      issuer: oneLine(x.issuer),
      selfSigned: x.subject === x.issuer,
      fingerprint256: fp,
      inSystemStore: systemRoots.has(fp),
      inBundled: bundled.has(fp),
      pem: systemRoots.get(fp)?.pem,
    };
  } catch {
    return null;
  }
}

/**
 * Probe one host `rounds` times and classify every connection:
 *  - intercepted: the chain contains a self-signed root that is installed on this
 *    machine but is NOT one of Node's bundled roots (i.e. local TLS inspection);
 *  - clean: genuine chain, verification passes;
 *  - verify-failed: verification failed but the culprit root could not be matched.
 */
export async function classifyTarget({
  host,
  port = 443,
  rounds = 12,
  timeout = 8000,
  delay = 30,
}) {
  const systemRoots = await loadSystemRoots();
  const bundled = loadBundledRootFingerprints();
  const roots = new Map();
  const verifyErrors = new Map();
  let clean = 0;
  let intercepted = 0;
  let verifyFailed = 0;
  let handshakeErrors = 0;
  let interceptedButTrusted = false;

  for (let i = 0; i < rounds; i++) {
    const plain = await probeOnce({ host, port, timeout, verify: false });
    const verified = await probeOnce({ host, port, timeout, verify: true });

    if (!plain.ok) {
      handshakeErrors++;
      const code = plain.error?.code ?? plain.error?.message ?? 'unknown';
      verifyErrors.set(code, (verifyErrors.get(code) ?? 0) + 1);
    } else {
      const chain = plain.chain
        .map((der) => certificateInfo(der, systemRoots, bundled))
        .filter(Boolean);
      // A self-signed root that Node does not bundle is either a locally installed
      // CA (system store readable: match it) or an unknown root we can still flag
      // when verification fails (store unreadable, Node < 24 on Windows).
      const localRoots = chain.filter(
        (c) => c.selfSigned && !c.inBundled && (c.inSystemStore || !verified.ok),
      );
      if (localRoots.length > 0) {
        intercepted++;
        if (verified.ok) interceptedButTrusted = true;
        for (const root of localRoots) {
          const known = roots.get(root.fingerprint256) ?? {
            subject: root.subject,
            fingerprint256: root.fingerprint256,
            pem: root.pem,
            count: 0,
          };
          known.count++;
          roots.set(root.fingerprint256, known);
        }
      } else if (verified.ok) {
        clean++;
      } else {
        verifyFailed++;
        const code = verified.error?.code ?? verified.error?.message ?? 'unknown';
        verifyErrors.set(code, (verifyErrors.get(code) ?? 0) + 1);
        const leafIssuer = chain.length > 0 ? chain[chain.length - 1] : undefined;
        if (leafIssuer && !roots.has('unmatched')) {
          roots.set('unmatched', {
            subject: leafIssuer.subject,
            fingerprint256: leafIssuer.fingerprint256,
            pem: undefined,
            count: 0,
          });
        }
      }
    }

    if (delay > 0) await sleep(delay);
  }

  return {
    host,
    port,
    rounds,
    clean,
    intercepted,
    verifyFailed,
    handshakeErrors,
    interceptedButTrusted,
    roots: [...roots.values()].sort((a, b) => b.count - a.count),
    verifyErrors: [...verifyErrors.entries()].map(([code, count]) => ({ code, count })),
    systemRootCount: systemRoots.size,
    bundledCount: bundled.size,
  };
}

const MESSAGES = {
  en: {
    'doctor.title': 'TLS MITM Doctor v{version}',
    'doctor.target': 'Target: {host}:{port}    probes: {rounds}',
    'doctor.counts': '  [{clean}] clean    [{intercepted}] intercepted    [{verifyFailed}] verify-failed    [{errors}] handshake error',
    'doctor.detected': 'RESULT: TLS interception detected.',
    'doctor.clean': 'RESULT: No local TLS interception detected.',
    'doctor.explain':
      'Connections to this host are being terminated by a locally-installed root CA (listed below),\n' +
      'but Node.js / Electron only trust their bundled CA list by default. That is why Node-based apps\n' +
      'fail with SELF_SIGNED_CERT_IN_CHAIN / "fetch failed" / provider-level transport errors, while\n' +
      'browsers and Python (which use the OS store) keep working.',
    'doctor.rootsHeader': 'Local root CA(s) observed in the chain, not trusted by Node.js by default:',
    'doctor.rootLine': '  - {subject}\n    sha256 {fingerprint}    observed in {count}/{rounds} probes',
    'doctor.trustedNote':
      '  note: the current process already trusts it ({hints}); other processes may not.',
    'doctor.verifyErrorsHeader': 'Verification errors observed:',
    'doctor.verifyErrorLine': '  - {code}: {count}',
    'doctor.fixHeader': 'Suggested fixes (in order):',
    'doctor.fix1':
      '1) Prefer telling your security software / corporate proxy to stop inspecting this host,\n' +
      '   or add it as an exclusion there. Note: with some products (tested with Kaspersky Free 21.26)\n' +
      '   the "trusted addresses" exclusion does NOT cover non-browser processes.',
    'doctor.fix2':
      '2) Make the Node/Electron app trust the local root CA (no security downgrade beyond what the\n' +
      '   machine already does):\n' +
      '     node export-ca.mjs --host {host} --out local-roots.pem\n' +
      '     setx NODE_EXTRA_CA_CERTS "%CD%\\local-roots.pem"        (Windows, then fully restart the app)\n' +
      '     export NODE_EXTRA_CA_CERTS="$PWD/local-roots.pem"       (macOS / Linux)',
    'doctor.fix3':
      '3) Node 22.15+/24 can use the OS store directly: run with --use-system-ca (or NODE_USE_SYSTEM_CA=1).\n' +
      '   Electron apps can call tls.setDefaultCACertificates([...tls.getCACertificates("default"),\n' +
      '   ...tls.getCACertificates("system")]) in the main process before creating network clients.',
    'doctor.warning':
      'Never use NODE_TLS_REJECT_UNAUTHORIZED=0 and never disable the security software globally.',
    'doctor.noStore':
      'Could not read the local certificate store automatically (Node < 24 on Windows).\n' +
      'Detection is limited: verification errors are reported, but the culprit CA may stay unmatched.',
    'doctor.usage': 'Usage: node doctor.mjs [--host a.com[,b.com]] [--port 443] [--rounds 12] [--timeout 8000] [--lang en|zh] [--json]',
    'export.title': 'TLS MITM Doctor — local root CA export',
    'export.found': 'Exported {count} local root CA(s) to {file}:',
    'export.entry': '  - {subject}\n    sha256 {fingerprint}',
    'export.none': 'No local root CA was observed being used for these hosts.',
    'export.noneDetail':
      'If the app still fails with SELF_SIGNED_CERT_IN_CHAIN, the root may not be in the local store\n' +
      'or the store could not be read (Node < 24 on Windows). Export the root manually:\n' +
      '  PowerShell: Get-ChildItem Cert:\\LocalMachine\\Root | Where-Object { $_.Subject -match "<vendor>" }\n' +
      '  Then export its DER/PEM and point NODE_EXTRA_CA_CERTS at the file.',
    'export.next':
      'Next steps:\n' +
      '  1) Fully quit the target application (tray icon → Quit, not just close the window).\n' +
      '  2) Point NODE_EXTRA_CA_CERTS at this file and relaunch:\n' +
      '       setx NODE_EXTRA_CA_CERTS "{file}"        (Windows; new processes only)\n' +
      '  3) Verify: node doctor.mjs --host {host} --lang {lang}',
    'export.usage': 'Usage: node export-ca.mjs [--host a.com] [--out local-roots.pem] [--rounds 10] [--lang en|zh]',
    'error.unknownHost': 'No host given.',
  },
  zh: {
    'doctor.title': 'TLS MITM Doctor v{version}',
    'doctor.target': '目标: {host}:{port}    探测次数: {rounds}',
    'doctor.counts': '  [正常] {clean}    [被拦截] {intercepted}    [校验失败] {verifyFailed}    [握手失败] {errors}',
    'doctor.detected': '结论：检测到 TLS 中间人拦截。',
    'doctor.clean': '结论：未检测到本地 TLS 中间人拦截。',
    'doctor.explain':
      '到该站点的连接被本机安装的根证书接管（见下），而 Node.js / Electron 默认只信任自带的根证书列表，\n' +
      '所以基于 Node 的应用会报 SELF_SIGNED_CERT_IN_CHAIN / “fetch failed” / 传输层错误，\n' +
      '而浏览器和 Python（走系统证书库）却正常。',
    'doctor.rootsHeader': '在证书链中观察到、Node.js 默认不信任的本地根证书：',
    'doctor.rootLine': '  - {subject}\n    sha256 {fingerprint}    在 {count}/{rounds} 次探测中出现',
    'doctor.trustedNote': '  注：当前进程已经信任它（{hints}），其他进程未必。',
    'doctor.verifyErrorsHeader': '观察到的校验错误：',
    'doctor.verifyErrorLine': '  - {code}: {count} 次',
    'doctor.fixHeader': '建议的修复（按推荐顺序）：',
    'doctor.fix1':
      '1) 首选让杀软/公司代理不要检查该站点，或在其设置里把该域名加入排除项。\n' +
      '   注意：某些产品（实测卡巴斯基免费版 21.26）的「受信任地址」排除对非浏览器进程不生效。',
    'doctor.fix2':
      '2) 让 Node/Electron 应用信任本机根证书（不额外降低安全性——系统本来就已经信任它）：\n' +
      '     node export-ca.mjs --host {host} --out local-roots.pem\n' +
      '     setx NODE_EXTRA_CA_CERTS "%CD%\\local-roots.pem"        （Windows，设置后要完全退出应用再启动）\n' +
      '     export NODE_EXTRA_CA_CERTS="$PWD/local-roots.pem"       （macOS / Linux）',
    'doctor.fix3':
      '3) Node 22.15+/24 可以直接使用系统证书库：加 --use-system-ca 参数（或 NODE_USE_SYSTEM_CA=1）。\n' +
      '   Electron 应用可以在主进程启动时调用 tls.setDefaultCACertificates([...tls.getCACertificates("default"),\n' +
      '   ...tls.getCACertificates("system")])。',
    'doctor.warning':
      '不要使用 NODE_TLS_REJECT_UNAUTHORIZED=0，也不要为了绕过问题而全局关闭杀软。',
    'doctor.noStore':
      '无法自动读取本机证书库（Windows 上需要 Node 24+）。检测能力受限：会报告校验错误，\n' +
      '但可能匹配不到具体的根证书。',
    'doctor.usage': '用法: node doctor.mjs [--host a.com[,b.com]] [--port 443] [--rounds 12] [--timeout 8000] [--lang en|zh] [--json]',
    'export.title': 'TLS MITM Doctor — 导出本机根证书',
    'export.found': '已导出 {count} 个本机根证书到 {file}：',
    'export.entry': '  - {subject}\n    sha256 {fingerprint}',
    'export.none': '没有观察到这些站点被本地根证书接管。',
    'export.noneDetail':
      '如果应用仍然报 SELF_SIGNED_CERT_IN_CHAIN，可能根证书不在本机证书库、或证书库读取失败\n' +
      '（Windows 上需要 Node 24+）。可以手动导出：\n' +
      '  PowerShell: Get-ChildItem Cert:\\LocalMachine\\Root | Where-Object { $_.Subject -match "<厂商>" }\n' +
      '  导出 DER/PEM 后，让 NODE_EXTRA_CA_CERTS 指向该文件。',
    'export.next':
      '后续步骤：\n' +
      '  1) 完全退出目标应用（托盘图标 → 退出，而不是只关窗口）。\n' +
      '  2) 把 NODE_EXTRA_CA_CERTS 指向该文件并重新启动：\n' +
      '       setx NODE_EXTRA_CA_CERTS "{file}"        （Windows；只对之后新启动的进程生效）\n' +
      '  3) 复验：node doctor.mjs --host {host} --lang {lang}',
    'export.usage': '用法: node export-ca.mjs [--host a.com] [--out local-roots.pem] [--rounds 10] [--lang en|zh]',
    'error.unknownHost': '没有指定主机名。',
  },
};

/** Returns a formatter: t(key, vars) → localized string. */
export function makeT(lang) {
  const dict = MESSAGES[lang] ?? MESSAGES.en;
  return (key, vars = {}) => {
    let text = dict[key] ?? MESSAGES.en[key] ?? key;
    for (const [name, value] of Object.entries(vars)) {
      text = text.replaceAll(`{${name}}`, String(value));
    }
    return text;
  };
}
