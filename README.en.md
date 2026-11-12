# TLS MITM Doctor

> A tiny, dependency-free diagnostic tool that **detects TLS interception by local security software / corporate proxies** and helps Node.js & Electron apps trust the locally installed root CA.
> No network calls beyond the TLS handshakes you ask for, no data collection, no system settings changed.

## Does this sound like you?

A Node.js / Electron app suddenly fails with errors like these — while browsers and Python work fine:

```
Error: self-signed certificate in certificate chain   (code: SELF_SIGNED_CERT_IN_CHAIN)
TypeError: fetch failed
Error: socket hang up / ECONNRESET
app-level: transport failed / connection error
```

The usual culprit is local security software (Kaspersky, ESET, 360, Sophos, …) or a corporate proxy that decrypts HTTPS:

- it terminates TLS with a **root CA installed on the machine**;
- browsers and Python (on Windows) use the OS certificate store, so they keep working;
- **Node.js / Electron only trust their bundled Mozilla root list by default** → they reject the local root CA.

## Quick start

Requires Node.js ≥ 20 (Node ≥ 24 is recommended for automatic Windows certificate-store access).

```bash
# Probe one host (12 attempts by default)
node doctor.mjs --host api.deepseek.com

# Several hosts, more attempts
node doctor.mjs --host api.deepseek.com,github.com --rounds 20

# Machine-readable
node doctor.mjs --host api.deepseek.com --json

# Export the intercepting local root CA as PEM (for NODE_EXTRA_CA_CERTS)
node export-ca.mjs --host api.deepseek.com --out local-roots.pem
```

Use `--lang zh` for Chinese output. Exit codes: `0` clean, `2` interception detected, `1` usage/runtime error.

How it works: perform repeated TLS handshakes to the same host and check whether the chain contains a self-signed root that is installed in the OS store but is **not** in Node's bundled list. Some products (Kaspersky, as tested) intercept only ~50–70% of new connections, so several attempts are needed.

> Sample output
>
> ```
> Target: api.deepseek.com:443    probes: 8
>   [4] clean    [4] intercepted    [0] verify-failed    [0] handshake error
>
> RESULT: TLS interception detected.
> Local root CA(s) observed in the chain, not trusted by Node.js by default:
>   - O=AO Kaspersky Lab, CN=Kaspersky Anti-Virus Personal Root Certificate
>     sha256 C7:88:6F:...D8    observed in 4/8 probes
> ```

## Fixes (in order of preference)

### 1. Tell the security software not to inspect this host

Add the domain to the product's exclusions / trusted addresses, or adjust its encrypted-connection scanning. Example (Kaspersky): `Settings → Security → Advanced → Network settings → Encrypted connections scan → Trusted addresses → add <domain>`.

**Gotcha (tested 2026-11, Kaspersky Free 21.26)**: the "trusted addresses" exclusion does **not** cover non-browser processes (Node/Electron); the interception continues. In that case use fix 2, or disable encrypted-connection scanning (reduces HTTPS protection — your call).

### 2. Make the app trust the local root CA (best for end users)

```bash
node export-ca.mjs --host api.deepseek.com --out local-roots.pem
```

Point `NODE_EXTRA_CA_CERTS` at that file (read by Node at process start):

```bat
:: Windows (user scope; only new processes)
setx NODE_EXTRA_CA_CERTS "%CD%\local-roots.pem"
```

```bash
# macOS / Linux
export NODE_EXTRA_CA_CERTS="$PWD/local-roots.pem"
```

**Important**: fully quit the Electron app (tray icon → Quit, not just closing the window) and relaunch it, otherwise the process keeps its old environment.

One-off launch:

```powershell
$env:NODE_EXTRA_CA_CERTS = 'C:\path\local-roots.pem'
& 'C:\Program Files\YourApp\YourApp.exe'
```

### 3. Fix it in the app (developers / product teams)

- Node 22.15+ / 24: launch with `--use-system-ca` or set `NODE_USE_SYSTEM_CA=1`.
- Any Node process, early at startup:

  ```js
  import tls from 'node:tls';
  const bundled = tls.getCACertificates('bundled');   // Node 24+
  const system  = tls.getCACertificates('system');    // Node 24+
  tls.setDefaultCACertificates([...bundled, ...system]);
  ```

- Electron main process: same, when the bundled Node supports these APIs; otherwise fall back to `NODE_EXTRA_CA_CERTS` or `tls.createSecureContext({ ca })`.
- Product-level: **trust the OS certificate store by default**, and surface the underlying TLS error (certificate code) to the UI instead of a generic "transport failed".

## Security notes

- `NODE_EXTRA_CA_CERTS` only makes Node accept roots the OS already trusts; it does not weaken certificate validation or route traffic through a third party.
- Never use `NODE_TLS_REJECT_UNAUTHORIZED=0`; never disable your security software globally to "fix" this.
- Local root CAs are sensitive: do not commit your own PEM. This tool ships **no certificates**; PEM files are generated locally only.

## Limitations

- Automatic system-store access: native on Windows with Node ≥ 24; older Node falls back to PowerShell (`Cert:\LocalMachine\Root`). On macOS/Linux only handshake probing is performed (no export).
- Interception is probabilistic; too few attempts can miss it. Use `--rounds 12` or more.
- Detects "local root CA replaces the real certificate" only. Hard blocks (RST/timeout) show up as handshake errors.
- Does not attribute a root CA to a vendor; the subject is printed for you to identify.

## Verified environment

- Windows 11 + Kaspersky Free 21.26: 13–18 of 25 TLS handshakes to `api.deepseek.com` were replaced by the Kaspersky root CA; Node 24 `fetch()` failed accordingly.
- After pointing `NODE_EXTRA_CA_CERTS` at the exported Kaspersky root: 12/12 real API requests succeeded (before the fix: 7 of 10 failed).
- Real-world victim: DSH desktop (Electron) reported `DeepSeek Messages transport failed` during tool-heavy steps — actually a TLS verification failure mapped to a transport error.

## Layout

```
doctor.mjs         # detection entry point
export-ca.mjs      # export local root CA(s) to PEM
lib/common.mjs     # shared logic (handshake, store access, X509 parsing, i18n)
docs/dsh-issue.md  # draft issue for DSH (an example product-side fix request)
```

## Repository

- GitHub: https://github.com/809939190-debug/tls-mitm-doctor
- Issues: https://github.com/809939190-debug/tls-mitm-doctor/issues

## License

MIT. Not affiliated with Kaspersky, DeepSeek, or any other vendor mentioned; trademarks belong to their owners.
