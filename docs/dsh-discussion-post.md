# DSH Discussions 待提交帖子

> deepseek-ai/deepseek-harness **已禁用 Issues，只开 Discussions**。
> 通过 GitHub API（GraphQL `createDiscussion`）自动发帖返回 `FORBIDDEN`：存储的 OAuth token 没有该权限，需要手动粘贴提交。
>
> - 提交入口：<https://github.com/deepseek-ai/deepseek-harness/discussions/new?category=general>
> - 分类：**General**（若想归到问答也可选 Q&A）
> - 标题与正文见下方，直接整段复制即可。

## 标题

```
[反馈] 建议默认信任系统证书库：卡巴斯基等 HTTPS 扫描环境下模型请求报 "DeepSeek Messages transport failed"（TRANSPORT）
```

## 正文（从下一行开始整段复制）

### 环境

- 系统：Windows 11（25H2）
- DSH：桌面版 0.2.2-rc.1（Electron，内置 Node）
- 安全软件：卡巴斯基免费版 21.26.4.406，开启「加密连接扫描」
- 模型路由：deepseek-official / deepseek-flash

### 现象

- 会话中频繁出现「已重试模型请求 (n/5)」→ `本轮运行失败 DeepSeek Messages transport failed`（`TRANSPORT`）。
- 重试偶尔成功、偶尔连续 5 次失败；工具调用密集的轮次更容易出现。
- 同一网络下浏览器、Python 请求 `api.deepseek.com` 完全正常；新建会话同样复现。
- 重试详情里只有顶层 `TRANSPORT`，看不到底层原因。

### 复现与证据

1. 对 `api.deepseek.com` 连续 25 次 TLS 握手，**13~18 次**收到的证书链被替换为：

   ```
   subject: CN=api.deepseek.com
   issuer : O=AO Kaspersky Lab, CN=Kaspersky Anti-Virus Personal Root Certificate
   ```

   其余为真实证书（TrustAsia DV TLS RSA CA 2025）。
2. Node 24 直接请求同样接口，抛 `fetch failed -> self signed certificate in certificate chain (SELF_SIGNED_CERT_IN_CHAIN)`。
   浏览器/Python 正常是因为它们走系统证书库；Node 默认只信任自带的 Mozilla 根证书列表。
3. 导出卡巴根证书并设置 `NODE_EXTRA_CA_CERTS` 后**完全退出并重启 DSH**：25 次握手 0 失败；真实 Messages 请求 12/12 成功（修复前强制新连接 10 次中 7 次失败）；会话内模型请求重试从每 2 轮 16 次降为 0。
4. 卡巴「加密连接扫描 → 受信任地址」加入 `api.deepseek.com` 后，**非浏览器进程仍被 MITM**（等待、重启 DSH 后复测依旧）。

### 根因

DSH 桌面版运行在 Electron 主进程，模型请求使用 Node 的 TLS 栈；Node 默认不读 Windows 证书库，因此本机安全软件/企业代理安装的根证书不被信任，请求在 TLS 握手阶段失败，被归类为 `TRANSPORT` 并重试。不是 DSH 的 bug，但可以做得更好。

### 建议

1. **默认信任系统证书库**：启动早期执行 `tls.setDefaultCACertificates([...tls.getCACertificates('bundled'), ...tls.getCACertificates('system')])`，或启动参数启用 `--use-system-ca`。
2. **把底层错误透出到 UI/日志**：在「重试模型请求」详情里显示 `failure.cause` 的 code/message（如 `SELF_SIGNED_CERT_IN_CHAIN`）。
3. 文档补充杀软 HTTPS 扫描相关 FAQ。

### 临时绕过（用户侧，已验证）

```bat
node export-ca.mjs --host api.deepseek.com --out kaspersky-root-ca.pem
setx NODE_EXTRA_CA_CERTS "C:\path\kaspersky-root-ca.pem"
:: 完全退出 DSH（托盘 → 退出）后重新启动
```

### 附：诊断工具

零依赖小工具（检测本机 TLS 是否被拦截、导出根证书、给出修复建议）：https://github.com/809939190-debug/tls-mitm-doctor

---

### English summary

**Environment**: Windows 11, DSH desktop 0.2.2-rc.1 (Electron), Kaspersky Free 21.26 with encrypted-connection scanning.

**Symptom**: model requests intermittently fail after 5 retries with `TRANSPORT / DeepSeek Messages transport failed`; browsers and Python work fine.

**Evidence**: 13–18 of 25 TLS handshakes to `api.deepseek.com` were signed by the Kaspersky root CA; Node's `fetch` fails with `SELF_SIGNED_CERT_IN_CHAIN`; setting `NODE_EXTRA_CA_CERTS` to the exported root (then fully restarting DSH) makes 12/12 requests succeed and retries drop to zero.

**Suggested fix**: trust the OS certificate store by default (`tls.setDefaultCACertificates([...bundled, ...system])` or `--use-system-ca`), and surface the underlying TLS error code in the retry UI.

**Tool**: https://github.com/809939190-debug/tls-mitm-doctor
