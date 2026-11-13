# claude-egress-guard

**让发往 Claude / Anthropic 的每一个字节都只从你选定的代理出口出去；代理出问题时宁可断网，也不退回真实 IP。**

[English](README.en.md) · [各代理软件配置](docs/proxies.md) · [踩坑记录](docs/pitfalls.md)

适用于 Claude Code（CLI）及其后台流量（模型调用、OAuth、MCP、遥测、更新），覆盖 macOS 与 Windows；
代理端支持 mihomo/Clash（Clash Verge Rev、ClashX Meta、FlClash）、sing-box、xray/v2rayN、Surge，以及任何提供本地 HTTP 代理端口的客户端。

> 本项目是一个“出口控制 + 失败关闭”的网络防护工具。请遵守你所在地的法律法规以及服务条款，使用风险自负。

---

## 为什么需要它：真实 IP 会从哪里漏出去

只“开个代理”远远不够。下面每一条都是在真实环境里实测出来的泄漏路径：

| # | 泄漏路径 | 现象 |
|---|---|---|
| 1 | 终端里“探测到代理端口才 export 代理变量” | 开终端时代理还没起来（开机恢复窗口很常见），该终端及其中启动的 Claude Code **整个生命周期直连** |
| 2 | Claude Code **不读系统代理** | 从 IDE、GUI、launchd/计划任务启动、或 `proxy_off` 之后启动，没有 `*_PROXY` 变量就直连 |
| 3 | 供应商切换工具重写 `~/.claude/settings.json` 的 `env` | 写进用户设置的代理变量被悄悄覆盖 |
| 4 | Node 原生 `fetch` 无视 `*_PROXY` | 基于 Node 的 MCP、脚本、工具直接直连 |
| 5 | 代理客户端被切到“直连/全局模式”，或策略组里有 `DIRECT`，或用“黑名单/GFW 列表”模式 | 代理内核自己用真实 IP 连 Anthropic；黑名单模式下“未被墙”的遥测域名直连 |
| 6 | Claude 的第三方遥测（Datadog、GrowthBook…）不在 geosite 分类里 | 只能靠“本地 DNS + GEOIP”分流，DNS 一旦返回国内节点就直连 |
| 7 | QUIC / WebRTC 等 UDP 流量绕过 HTTP 代理 | 浏览器、系统服务直连境外 |
| 8 | 以系统账户运行的服务不读用户的代理设置 | 例如某些桌面应用的后台/虚拟机服务 |
| 9 | 代理节点的落地 IP 变了而客户端没同步 | 节点全部不可用，或出口变成别的 IP |

## 设计：四层防护 + 监测

| 层 | 作用 | macOS | Windows |
|---|---|---|---|
| **L1 代理变量** | Claude Code 永远拿得到代理变量 | 终端片段（失败关闭）+ 用户设置 + **托管设置**（最高优先级，工具改不掉） | 用户环境变量 + **托管设置** |
| **L2 代理规则** | Claude 相关域名固定走一个只含你固定出口的策略组，绝不含 `DIRECT` | `tools/gen_proxy_rules.py` 生成各客户端规则片段 | 同左 |
| **L3 断网保护** | 代理出问题时断网而不是直连 | pf：①**所有进程**禁止直连 Anthropic 网段；②完整模式：你的用户直连境外一律拒绝 | 防火墙：①**所有程序**禁止直连 Anthropic 网段；②`claude.exe` 只准连本机/局域网/Tailscale |
| **L4 提问前门禁** | 发消息前确认 Anthropic 看到的出口是预期 IP（60 秒内测过就复用结果），确认不了就拦 | `UserPromptSubmit` 钩子 | 同左 |
| **监测** | 随时看到出口 IP 与异常次数 | 状态栏 + 常驻采样（Claude Code 进程树的直连）+ pf 拦截计数 | 门禁 + 状态栏文字 |

关键原则：

- **失败关闭**：任何一层失效，结果都是“请求失败”，而不是“改走直连”。
- **只信实测**：出口 IP 用 `https://api.anthropic.com/cdn-cgi/trace` 测——与 API 同一个域名、同一条代理规则，Cloudflare 回显的就是 Anthropic 看到的 IP。
- **没有代理变量时绝不碰境外**：守卫脚本此时只会请求“真实 IP 回显服务”（默认 `http://ip.3322.net`，一个境内服务，见[配置项](#配置项)）。

---

## 快速开始

```bash
git clone https://github.com/<you>/claude-egress-guard.git ~/claude-egress-guard
cd ~/claude-egress-guard
bash tests/run_all.sh            # 离线自检（可选，macOS/Linux）
```

Windows 的 PowerShell 不会展开原生命令参数里的 `~`，请写成 `git clone https://github.com/<you>/claude-egress-guard.git "$HOME\claude-egress-guard"`。

### 第 1 步（所有平台）：代理规则

```bash
python3 tools/gen_proxy_rules.py --target mihomo    # 或 singbox / xray / surge / all
```

（Windows 上用 python.org 安装的 Python 时，把本文的 `python3` 换成 `py -3`。）

把输出贴进你的代理客户端：规则放在任何 `GEOIP`/`GEOSITE,cn`/`MATCH` 之前，并建一个**只含固定出口节点**的策略组（不要放 `DIRECT`，也不要在一大堆节点里自动测速切换——出口 IP 跳来跳去本身就是风险信号）。各客户端的细节与注意事项见 [docs/proxies.md](docs/proxies.md)。

### 第 2 步（所有平台）：声明预期出口

这是第一次经代理访问 Anthropic。先确认第 1 步的规则已在客户端生效，并且客户端处于规则模式（不是“直连”或“全局直连”）。

```bash
# macOS / Linux：经代理看 Anthropic 线路的出口
curl -s -x http://127.0.0.1:7890 https://api.anthropic.com/cdn-cgi/trace | grep -E '^(ip|loc)='
mkdir -p ~/.config/claude-egress-guard
cp config/expected-egress.example.txt ~/.config/claude-egress-guard/expected-egress.txt
# 把示例 IP 改成上面看到的出口
```

```powershell
# Windows PowerShell（5.1 里 curl 是 Invoke-WebRequest 的别名，所以写 curl.exe）
curl.exe -s -x http://127.0.0.1:10808 https://api.anthropic.com/cdn-cgi/trace | Select-String '^(ip|loc)='
New-Item -ItemType Directory -Force "$HOME\.config\claude-egress-guard" | Out-Null
Copy-Item config\expected-egress.example.txt "$HOME\.config\claude-egress-guard\expected-egress.txt"
notepad "$HOME\.config\claude-egress-guard\expected-egress.txt"   # 改成上面看到的出口
```

### macOS

```bash
# 1) 终端：失败关闭的代理变量（把端口换成你的）
echo 'CEG_PROXY_URL=http://127.0.0.1:7890; source ~/claude-egress-guard/macos/shell/proxy.zsh' >> ~/.zshrc

# 2) 判断能不能用"完整模式"：监听代理端口的内核必须不是你的用户（USER 列应为 root）
lsof -nP -iTCP:7890 -sTCP:LISTEN
#    是 root → 可以用 full；是你的用户名 → 先把代理切到服务/TUN 服务模式，或用 anthropic-only
#    （安装脚本会自动做这项检查，并检查以你的身份运行的 VPN 网络扩展）

# 3a) 只封 Anthropic（不依赖代理内核以谁的身份运行）
sudo sh macos/pf/install.sh --mode anthropic-only --proxy-url http://127.0.0.1:7890

# 3b) 完整模式：额外拒绝你的用户直连一切境外 IP（国内、局域网、Tailscale、苹果放行）
python3 tools/gen_cn_ipv4.py                     # 生成国内 IPv4 表（以你自己的身份运行）
sudo sh macos/pf/install.sh --mode full --proxy-url http://127.0.0.1:7890
```

然后把 [macos/claude/settings.example.json](macos/claude/settings.example.json) 里的 `hooks` 与 `statusLine` 合并进 `~/.claude/settings.json`，**重开 Claude Code 会话**（钩子与托管设置只在启动时加载）。

### Windows

```powershell
claude install                       # 换成原生版 claude.exe（npm 版跑在 node.exe 里，无法单独设防火墙规则）
# 以“管理员身份”打开 PowerShell（用你自己的账户登录）
Set-ExecutionPolicy -Scope Process Bypass    # 仅对当前窗口放开脚本执行（Windows 默认禁止运行 .ps1）
cd "$HOME\claude-egress-guard\windows"
.\install.ps1 -ProxyUrl http://127.0.0.1:10808      # v2rayN 默认 10808；claude.exe 不在默认位置时加 -ClaudeExe <路径>
.\test-firewall.ps1 -ProxyUrl http://127.0.0.1:10808
```

门禁钩子（`settings.json` 里写 Python 的完整路径，用正斜杠）：

```json
{"hooks": {"UserPromptSubmit": [{"hooks": [{"type": "command", "timeout": 20,
  "command": "\"C:/Users/<you>/AppData/Local/Programs/Python/Python311/python.exe\" -X utf8 \"C:/Users/<you>/claude-egress-guard/guard/egress_guard.py\" gate"}]}]}}
```

> Windows 防火墙只能按程序、不能按用户过滤，所以没有 macOS 完整模式那种“拦住整个用户的境外直连”。“Claude Code only local”规则只匹配 `claude.exe` 这个程序本身：它启动的子进程（Node 写的 MCP、git、Bash 工具里跑的 curl/python 等）不受这条规则约束——它们直连 Anthropic 网段仍会被“Block Anthropic”规则拦下，但直连其它境外主机只能靠代理变量。其它程序不受影响。

### Linux（未内置脚本）

思路相同：`nftables` 用 `meta skuid` 按用户过滤，`ip daddr` 用 Anthropic 网段做全进程封禁；Claude Code 托管设置在 `/etc/claude-code/managed-settings.json`。欢迎 PR。

---

## 验证

按顺序做：**先确认规则已生效，再做直连测试**。规则没生效时，直连测试本身就会用真实 IP 连上 Anthropic。

| 检查 | 命令 | 预期 |
|---|---|---|
| 1. pf 已启用 | `sudo pfctl -s info \| head -1` | `Status: Enabled` |
| 2. 主规则集挂着 `com.apple/*` 钩子（被别的工具替换掉的话，本项目的规则不会被执行） | `sudo pfctl -sr \| grep '^anchor "com.apple/\*"'` | `anchor "com.apple/*" all` |
| 3. Anthropic 网段已在表里 | `sudo pfctl -a com.apple/250.ClaudeEgressGuard -t ceg_anthropic -T test 160.79.104.10` | `1/1 addresses match` |
| 4. 直连 Anthropic 被拦（1–3 都通过后再做） | `curl -s -o /dev/null -w '%{http_code}\n' --noproxy '*' -m 5 https://160.79.104.10/` | 立即返回 `000` |
| 5. 完整模式：直连境外被拦 | `curl -s -o /dev/null -w '%{http_code}\n' --noproxy '*' -m 5 https://github.com` | 立即返回 `000` |
| 6. 经代理的出口 | `curl -s -x <代理> https://api.anthropic.com/cdn-cgi/trace` | `ip=` 是你的出口 |
| 7. 门禁 | `python3 guard/egress_guard.py gate; echo $?` | 正常 `0`；`env -u HTTPS_PROXY -u https_proxy -u HTTP_PROXY -u http_proxy python3 guard/egress_guard.py gate; echo $?` 为 `2` |
| 8. 状态栏 | `python3 guard/egress_guard.py status` | `exit 203.0.113.10 US \| anomalies today 0` |
| 9. Claude Code 走了哪些主机 | `python3 tools/probe_hosts.py`（零泄漏探针，见脚本说明） | 全部在域名清单或 Anthropic 网段内 |

Windows 上 `test-firewall.ps1` 会先确认规则存在、已启用、防火墙各配置文件都开着，才做直连测试，并核对规则里的 `claude.exe` 路径是否就是你在用的那个。

状态栏的含义：

- `exit <IP> <国家>`：Anthropic 当前看到的出口；`(provider …)` 表示模型调用发往第三方供应商。
- `! proxy down` / `! no proxy` / `! exit node down` / `! exit == real IP`：告警态。
- `! pf kill switch inactive`：pf 被关闭，或主规则集被别的工具替换、本项目的规则没在执行（守护进程每 60 秒检查一次）。
- `! NO_PROXY bypasses Claude hosts`：`NO_PROXY` 里有条目会让 Claude 相关域名直连。
- `anomalies today N`：当天异常次数——`anthropic-blocked`（有进程想直连 Anthropic 被 pf 拦下）、`direct`（Claude Code 进程树里出现直连境外，或主进程直连）、`exit`（出口不是预期 IP）。
- `host blocked N`：pf 拦下的全机包数（含与 Claude 无关的程序，不计入告警）。
- 明细在 `~/.cache/claude-egress-guard/events.jsonl`。

## 卸载

```bash
sudo sh macos/pf/uninstall.sh                 # macOS：停守护、清规则、把托管设置还原到首次安装前
```
```powershell
# Windows：管理员 PowerShell
Set-ExecutionPolicy -Scope Process Bypass
cd "$HOME\claude-egress-guard\windows"
.\uninstall.ps1                 # 加 -RemoveUserEnv 可同时删除用户环境变量
```
再删掉 `~/.zshrc` 里的那一行和 `settings.json` 里的钩子即可。

## 常见问题

**门禁把我拦了，但我确认网络没问题？** 看提示里的原因（出口不在列表、测不到出口等）。临时关闭：`touch ~/.config/claude-egress-guard/gate-off`，删掉即恢复。

**界面上出现 `503 credential validation failed`？** 这是 Anthropic 服务端返回的（凭证校验服务故障），与本项目无关——本项目拦截的结果是“连接被拒”，拿不到任何 HTTP 状态码；本地代理失败通常是 502。先看 status.claude.com。

**为什么直连国内网站不算异常？** 国内服务按设计直连（代理规则里的 `GEOSITE,cn`/`GEOIP,CN`）。异常只统计“直连境外”或“Claude Code 主进程直连”。

**为什么不直接开 TUN 模式？** TUN 能接管不读代理变量的程序，但代理内核一退出，路由随之消失，流量就回到直连。与本项目叠加时要知道：pf 的出站规则同样作用于 TUN 的 utun 接口——

- anthropic-only 模式：没开 fake-IP 时，发往 Anthropic 真实 IP 的包在进入 TUN 前就被拦，只靠 TUN、没有代理变量的程序连不上 Anthropic（这正是失败关闭）；Claude Code 走 L1 的代理变量，不受影响。
- 完整模式：你的用户发往 fake-IP（198.18.0.0/15）和真实境外 IP 的包都会被拒，TUN 对你的用户等于失效，一切境外访问都要走代理端口。

断网保护（L3）与门禁（L4）仍然是必要的。

**节点出口换了怎么办？** 更新 `expected-egress.txt`，否则门禁会把每条消息都拦下（这正是它该做的）。

## 配置项

守卫脚本 `guard/egress_guard.py` 读取以下环境变量（都可选）：

| 变量 | 默认值 | 作用 |
|---|---|---|
| `CEG_CONFIG_DIR` | `~/.config/claude-egress-guard` | 放 `expected-egress.txt`、`domestic-ipv4.txt`、`gate-off` |
| `CEG_CACHE_DIR` | `~/.cache/claude-egress-guard` | 测量缓存、当日计数、事件日志 |
| `CEG_TRACE_URL` | `https://api.anthropic.com/cdn-cgi/trace` | 测出口用；与 API 同域名，所以命中同一条代理规则 |
| `CEG_REAL_IP_URL` | `http://ip.3322.net` | 查真实 IP 的回显服务，**你的代理规则必须让它直连**。默认是境内服务（明文 HTTP）；不在中国大陆的话，换成你所在地区的回显服务并给它加一条 `DIRECT` 规则，否则测到的“真实 IP”就是出口，门禁会以“出口 == 真实 IP”拦下每条消息 |
| `CEG_GATE_FRESH` | `60` | 门禁复用测量结果的最长秒数 |
| `CEG_PF_STATS` | `/Library/Application Support/ClaudeEgressGuard/stats.json` | macOS pf 拦截计数 |

`macos/shell/proxy.zsh` 读取 `CEG_PROXY_URL`（默认 `http://127.0.0.1:7890`）与 `CEG_NO_PROXY`。

## 局限

- 只处理网络出口。时区、系统语言、支付方式、账号行为等非 IP 信号不在范围内。
- Anthropic 网段需要定期更新：`HTTPS_PROXY=<代理> python3 tools/update_anthropic_ranges.py --write`（它也会提示哪些端点不在网段内、只能依赖代理规则）。**更新后要重新运行 `install.sh` / `install.ps1`**，防火墙才会用上新网段。
- 常驻采样器按 0.5 秒采样，存活时间更短的连接可能漏掉；被 pf 拦下的直连尝试只体现在计数里。
- macOS 完整模式要求代理内核与 VPN 扩展不以你的用户身份运行（安装脚本会检查监听代理端口的进程属主与 VPN 网络扩展，不满足就拒绝）。
- 门禁钩子只在退出码为 2 时拦截。钩子命令本身配错（例如找不到 `python3`，退出码 127）会被 Claude Code 当作普通错误而**放行**。装好后请按“验证”第 7 步确认去掉代理变量时门禁返回 `2`。钩子的 `timeout` 不要低于 20 秒：门禁自身最长要 15 秒，而钩子超时很可能也按非阻断处理、直接放行。

## 许可证

MIT
