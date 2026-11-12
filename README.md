# TLS MITM Doctor

> 一个 100 行的诊断小工具：**检测本机安全软件 / 公司代理是否在做 TLS 中间人拦截**，并帮助 Node.js、Electron 应用信任本机根证书。
> 零依赖，不需要联网上传任何数据，不修改系统设置。

## 你中招了吗？

如果 Node.js / Electron 应用（各类 CLI、桌面客户端、VS Code/Cursor 插件、自研工具）突然出现下面这些错误，而**浏览器和 Python 却一切正常**：

```
Error: self-signed certificate in certificate chain   (code: SELF_SIGNED_CERT_IN_CHAIN)
TypeError: fetch failed
Error: socket hang up / ECONNRESET
应用自己抛出的：transport failed / connection error / 网络异常
```

那大概率就是本机安全软件（卡巴斯基、ESET、360、火绒、Sophos…）或公司代理在解密 HTTPS：

- 它用一个**本机安装的根证书**替换了真实证书；
- 浏览器、Python（Windows 上）走系统证书库，所以正常工作；
- **Node.js / Electron 默认只信任自带的 Mozilla 根证书列表**，不认这个本地根证书 → 直接报错。

## 快速开始

要求：Node.js ≥ 20（想自动读取 Windows 证书库请用 Node ≥ 24）。

```bash
# 检测某个站点（默认探测 example.com 12 次）
node doctor.mjs --host api.deepseek.com --lang zh

# 一次检测多个站点
node doctor.mjs --host api.deepseek.com,github.com --rounds 20 --lang zh

# 机器可读输出
node doctor.mjs --host api.deepseek.com --json

# 把拦截用的本机根证书导出成 PEM（供 NODE_EXTRA_CA_CERTS 使用）
node export-ca.mjs --host api.deepseek.com --out local-roots.pem --lang zh
```

退出码：`0` = 未检测到拦截，`2` = 检测到拦截，`1` = 用法/运行错误。

检测原理（一句话）：对同一域名反复握手，看证书链里是否出现「自签名、装在系统证书库、但不在 Node 自带列表里」的根证书，并统计出现比例。部分杀软（实测卡巴斯基）大约 50%~70% 的新连接会被拦截，所以需要多探测几次。

> 输出示例
>
> ```
> 目标: api.deepseek.com:443    探测次数: 8
>   [正常] 4    [被拦截] 4    [校验失败] 0    [握手失败] 0
>
> 结论：检测到 TLS 中间人拦截。
> 在证书链中观察到、Node.js 默认不信任的本地根证书：
>   - O=AO Kaspersky Lab, CN=Kaspersky Anti-Virus Personal Root Certificate
>     sha256 C7:88:6F:...D8    在 4/8 次探测中出现
> ```

## 修复方案（按推荐顺序）

### 方案 1：让安全软件不要检查这个域名（推荐，最干净）

在杀软里把域名加入排除项，或调整加密连接扫描设置。各家路径不同，例如卡巴斯基：

`设置 → 安全设置 → 高级设置 → 网络设置 → 加密连接扫描 → 受信任地址 → 添加 <域名>`

**实测坑（2026-11，卡巴斯基免费版 21.26）**：这条「受信任地址」排除对**非浏览器进程**（Node/Electron）并不生效，仍然会被 MITM。如果加了没用，只能退回方案 2，或直接关闭「加密连接扫描」（会降低 HTTPS 防护，自行权衡）。

### 方案 2：让应用信任本机根证书（普通用户最稳）

```bash
node export-ca.mjs --host api.deepseek.com --out local-roots.pem
```

然后用环境变量 `NODE_EXTRA_CA_CERTS` 指向这个文件（Node 进程启动时读取）：

```bat
:: Windows（用户级；只对之后新启动的进程生效）
setx NODE_EXTRA_CA_CERTS "%CD%\local-roots.pem"
```

```bash
# macOS / Linux
export NODE_EXTRA_CA_CERTS="$PWD/local-roots.pem"
```

**重要**：Electron 应用必须**完全退出**（托盘图标 → 退出，而不是只关窗口）再重新启动，否则进程仍是旧环境变量。

不想永久设置？临时启动：

```powershell
$env:NODE_EXTRA_CA_CERTS = 'C:\path\local-roots.pem'
& 'C:\Program Files\YourApp\YourApp.exe'
```

### 方案 3：让应用自己修复（开发者/产品方）

- Node 22.15+ / 24：启动参数加 `--use-system-ca`，或设置 `NODE_USE_SYSTEM_CA=1`；
- 任意 Node 进程：启动早期执行

  ```js
  import tls from 'node:tls';
  const bundled = tls.getCACertificates('bundled');   // Node 24+
  const system  = tls.getCACertificates('system');    // Node 24+
  tls.setDefaultCACertificates([...bundled, ...system]);
  ```

- Electron 主进程：同上（需要 Electron 内置 Node 支持这两个 API，版本不够时退回 `NODE_EXTRA_CA_CERTS` 或 `tls.createSecureContext({ ca })`）。
- 产品侧更彻底的做法：**默认信任系统证书库**，并在网络错误里把底层 TLS 原因（证书错误码）透出到 UI，而不是只显示「传输失败」。

## 安全说明

- `NODE_EXTRA_CA_CERTS` 只是让 Node **接受系统本来就已经信任的根证书**，不会放宽 TLS 校验，也不会让流量经过第三方。
- 不要用 `NODE_TLS_REJECT_UNAUTHORIZED=0`（相当于关闭所有证书校验）。
- 不要为了绕过问题全局关闭杀毒软件。
- 本地根证书是敏感凭据：不要把自己的 PEM 提交到仓库；本工具**不内置任何证书**，PEM 只在你自己的机器上生成。

## 局限

- 自动读取系统证书库：Windows 上 Node 24+ 原生支持；更老的 Node 会尝试 PowerShell 兜底（读 `Cert:\LocalMachine\Root`）。macOS/Linux 只做握手探测，不导出系统根证书。
- 拦截比例是概率性的，探测次数太少可能漏报；建议 `--rounds 12` 以上。
- 只检测「本机根证书替换真实证书」这一类拦截；如果代理直接阻断连接（RST / 超时），会显示为握手失败，需要结合其他工具判断。
- 不判断根证书具体属于哪个厂商（输出里给出 subject，自行识别）。

## 实测环境

- Windows 11 + 卡巴斯基免费版 21.26：对 `api.deepseek.com` 的 25 次握手中 13~18 次被替换成卡巴根证书；Node 24 直接 `fetch` 失败。
- 同一台机器用 `NODE_EXTRA_CA_CERTS` 指向导出的卡巴根证书后：12/12 次真实请求成功（修复前 10 次里 7 次失败）。
- 典型受影响对象：DSH 桌面版（Electron）在工具密集步骤报 `DeepSeek Messages transport failed`，实为 TLS 证书校验失败被上层归类为 TRANSPORT。

## 目录结构

```
doctor.mjs         # 检测入口
export-ca.mjs      # 导出本机根证书到 PEM
lib/common.mjs     # 共享逻辑（握手、证书库读取、证书解析、i18n）
docs/dsh-issue.md  # 给 DSH 的 issue 草稿（可作为产品侧修复建议的范例）
```

## License

MIT。本工具与 Kaspersky、DeepSeek 等厂商无隶属关系，相关商标归各自所有者。
