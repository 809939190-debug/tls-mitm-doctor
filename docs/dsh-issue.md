# DSH issue 草稿：桌面版不信任 Windows 证书库，导致卡巴斯基等 HTTPS 扫描环境下模型请求报 “DeepSeek Messages transport failed”

> 用途：向 DSH（DeepSeek Harness）官方提交问题/建议。可按实际渠道（应用内反馈 / 仓库 issue / 官方社区）调整格式；中文正文可直接用，末尾附英文摘要。

## 标题建议

`[desktop] Trust the OS certificate store by default — Kaspersky/enterprise TLS inspection makes model requests fail as "DeepSeek Messages transport failed" (TRANSPORT)`

## 环境

- 系统：Windows 11（25H2）
- DSH：桌面版 0.2.2-rc.1（Electron，内置 Node）
- 安全软件：卡巴斯基免费版 21.26.4.406（`KAVKISKTS`），开启「加密连接扫描」
- 模型：deepseek-flash（DSH 默认路由）

## 现象

- 会话中频繁出现「已重试模型请求 (n/5)」→ `本轮运行失败 DeepSeek Messages transport failed`（错误码 `TRANSPORT`）。
- 重试偶尔成功、偶尔连续 5 次失败；**工具调用密集的轮次**更容易出现（每次新 TLS 连接都有概率中招）。
- 同一网络下浏览器、Python 请求 `api.deepseek.com` 完全正常。
- 新建会话同样复现；重装/重启 DSH 不解决。DSH 日志中只有顶层 `TRANSPORT`，没有底层原因。

## 复现与证据

1. **抓握手**：对 `api.deepseek.com` 连续 25 次 TLS 握手，**13~18 次**收到的证书链被替换为：

   ```
   subject: CN=api.deepseek.com
   issuer : O=AO Kaspersky Lab, CN=Kaspersky Anti-Virus Personal Root Certificate
   ```

   其余 7~12 次是真实证书（TrustAsia DV TLS RSA CA 2025）。三个解析 IP 轮流出现，与具体 IP 无关。

2. **Node/Electron 视角**：同样的请求用 Node 24 的 `fetch` / `https` 发，直接抛

   ```
   TypeError: fetch failed
     cause: Error: self signed certificate in certificate chain (SELF_SIGNED_CERT_IN_CHAIN)
   ```

   浏览器/Python 正常，是因为它们走 Windows 证书库；Node 默认只信任自带的 Mozilla 根证书列表。

3. **修复验证**：把卡巴斯基根证书导出为 PEM，环境变量

   ```
   NODE_EXTRA_CA_CERTS=C:\Users\<user>\.dsh\certs\kaspersky-root-ca.pem
   ```

   后完全退出并重启 DSH：25 次握手 0 失败；真实 Messages 请求 12/12 成功（修复前强制新连接 10 次中 7 次失败）；会话内模型请求重试从“每 2 轮 16 次”降为 0。

4. **排除项不可行**：卡巴斯基「设置 → 安全设置 → 高级设置 → 网络设置 → 加密连接扫描 → 受信任地址」加入 `api.deepseek.com` 后，**非浏览器进程仍被 MITM**（等待 20 秒、重启 DSH 后复测依旧），说明该排除项不覆盖此类进程。卡巴论坛也有类似反馈：https://forum.kaspersky.com/topic/trusted-address-settings-ignored-23568/?page=2

## 根因

DSH 桌面版运行在 Electron 主进程里，其模型请求使用 Node 的 TLS 栈。Node 默认不读取 Windows 系统证书库，因此本机安全软件/企业代理安装的根证书不被信任，请求在 TLS 握手阶段失败；DSH 把它归类为 `TRANSPORT` 并重试，重试仍可能继续落在被拦截的连接上，最终整轮失败。

这不是 DSH 的 bug，但 DSH 可以做得更好（见下）。

## 建议修复（产品侧，任一即可）

1. **默认信任系统证书库**（推荐）。DSH 启动早期在主进程执行：

   ```js
   import tls from 'node:tls';
   const bundled = tls.getCACertificates('bundled');
   const system  = tls.getCACertificates('system');
   tls.setDefaultCACertificates([...bundled, ...system]);
   ```

   或者在启动参数中启用 `--use-system-ca`（需 Electron 内置 Node 支持）。这样所有处于杀软/企业代理环境的用户无需手工配置环境变量。

2. **把底层错误透出到 UI/日志**：目前只显示 `DeepSeek Messages transport failed`。如果错误详情（`cause.code`，如 `SELF_SIGNED_CERT_IN_CHAIN` / `ECONNRESET`）可见，用户和排查者能立刻定位，而不是怀疑工具或插件。建议在「重试模型请求」详情里显示 `failure.cause` 的 code/message。

3. **文档/FAQ**：在“网络问题”文档中说明杀软 HTTPS 扫描、`NODE_EXTRA_CA_CERTS`、`--use-system-ca` 三种解法。

## 临时绕过（用户侧，已验证）

```bat
:: 导出卡巴根证书为 PEM（可用本仓库的 tls-mitm-doctor：node export-ca.mjs --host api.deepseek.com --out kaspersky-root-ca.pem）
:: 然后：
setx NODE_EXTRA_CA_CERTS "C:\path\kaspersky-root-ca.pem"
:: 完全退出 DSH（托盘 → 退出）后重新启动
```

## 附：诊断工具

整理了一个零依赖小工具，可一键判断“是不是本机 TLS 拦截”并导出根证书：`tls-mitm-doctor`（doctor.mjs / export-ca.mjs）。检测输出示例：

```
目标: api.deepseek.com:443    探测次数: 8
  [正常] 4    [被拦截] 4    [校验失败] 0    [握手失败] 0
结论：检测到 TLS 中间人拦截。
  - O=AO Kaspersky Lab, CN=Kaspersky Anti-Virus Personal Root Certificate
    sha256 C7:88:6F:...D8    在 4/8 次探测中出现
```

---

## English summary (for an English issue tracker)

**Title**: Trust the OS certificate store by default — local TLS inspection makes model requests fail as "DeepSeek Messages transport failed" (TRANSPORT)

**Environment**: Windows 11, DSH desktop 0.2.2-rc.1 (Electron), Kaspersky Free 21.26 with encrypted-connection scanning enabled.

**Symptom**: model requests intermittently fail after 5 retries with `TRANSPORT / DeepSeek Messages transport failed`; more frequent on tool-heavy turns; new sessions affected too; browsers and Python work fine.

**Evidence**: 13–18 of 25 TLS handshakes to `api.deepseek.com` received a chain signed by `AO Kaspersky Lab / Kaspersky Anti-Virus Personal Root Certificate`; Node's `fetch` fails with `SELF_SIGNED_CERT_IN_CHAIN` (Node ignores the Windows store, browsers/Python use it). Setting `NODE_EXTRA_CA_CERTS` to the exported Kaspersky root (then fully restarting DSH) makes 12/12 requests succeed and retries drop to zero. The Kaspersky "trusted addresses" exclusion does not cover non-browser processes (tested).

**Suggested fix**: call `tls.setDefaultCACertificates([...tls.getCACertificates('bundled'), ...tls.getCACertificates('system')])` at host startup, or launch with `--use-system-ca`; surface the underlying TLS error code in the retry UI; add an FAQ entry.
