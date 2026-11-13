# 各代理软件的配置要点

[English](proxies.en.md) · [返回 README](../README.md)

## 通用要求（任何客户端都必须满足）

1. **本地 HTTP（或 mixed）端口**：填进 `CEG_PROXY_URL`（终端）、`--proxy-url`（macOS 安装脚本）、`-ProxyUrl`（Windows）。
2. **Claude 域名规则**：`python3 tools/gen_proxy_rules.py --target <客户端>` 生成；放在任何 `GEOIP` / `GEOSITE,cn` 直连规则**之前**。
3. **专用策略组只含固定出口**：不放 `DIRECT`，不在一大堆节点里自动测速。出口 IP 跳变本身就是风险信号。
4. **未匹配流量默认走代理**（白名单思路：“国内直连、其余代理”）。**不要用“黑名单 / GFW 列表”模式**：在这种模式下，没被墙的境外域名（例如 Claude 的遥测）会直连。
5. **搞清代理内核以谁的身份运行**：它决定 macOS 能不能用完整模式（见下）。
6. **出口节点的落地 IP 变了，所有设备都要同步**：包括各客户端的节点地址和 `expected-egress.txt`。

### 判断内核的运行身份

```bash
# macOS / Linux：真正干活的是“监听代理端口的那个进程”（GUI 前端的身份无关紧要）
lsof -nP -iTCP:7890 -sTCP:LISTEN          # 看 USER 列；端口换成你的
# 以你的身份运行的 VPN / 包隧道网络扩展（不监听端口，上面那条看不到）
ps -axo user,comm | grep -i -E 'IPNExtension|PacketTunnel|NetworkExtension' | grep -v grep
```
```powershell
# Windows
Get-CimInstance Win32_Process | Where-Object Name -match 'mihomo|clash|sing-box|xray|v2ray' |
  ForEach-Object { "$($_.Name) owner=$((Invoke-CimMethod -InputObject $_ -MethodName GetOwner).User)" }
```

| 内核身份 | macOS 可用模式 | 原因 |
|---|---|---|
| root（系统服务 / 特权助手） | `full` 或 `anthropic-only` | 完整模式只限制你的用户，内核连节点不受影响 |
| 你的用户 | 只能 `anthropic-only` | 完整模式会把内核自己连节点的流量也拦掉，导致全面断网（安装脚本会检查监听 `--proxy-url` 端口的进程属主，是你的用户就拒绝） |
| Windows 上任意身份 | 防火墙两条规则都可用 | Windows 版按程序过滤，不按用户 |

---

## mihomo / Clash 系（Clash Verge Rev、ClashX Meta、FlClash、mihomo-party…）

- **规则**：`gen_proxy_rules.py --target mihomo`。
  - 远程订阅会覆盖规则，所以要写进客户端的“扩展配置 / Merge / 规则增强（prepend）”。
  - prepend 会把规则放到最前面，对 Claude 域名没有问题（它们不在 `cn` 分类里）。
- **Clash Verge Rev 的两种运行模式**：
  - **服务模式**：内核以 root 运行，可以用完整模式。安装服务可以在设置里点，也可以运行应用包内的 `Contents/Resources/resources/clash-verge-service-install`（需要 root；用环境变量 `CLASH_VERGE_SERVICE_GID` 指定你的组 ID，通常是 staff=20），之后按正确顺序重启 Clash Verge。
  - **Sidecar 模式**：内核以你的用户身份运行，只能用 `anthropic-only`。
- **托盘里的“直连 / 全局”模式会绕过所有规则**。有两层兜底：
  - L3①：任何进程（包括内核自己）都直连不了 Anthropic 网段，请求直接失败；
  - L4：门禁会发现出口等于真实 IP，拦下消息。
- **DNS**：`GEOIP` 规则会让内核在本地解析域名。把已知境外域名放在 GEOIP 之前（`DOMAIN-SUFFIX` 或 `GEOSITE,geolocation-!cn`）可以减少本地 DNS 查询。
- **重启的坑（Sidecar）**：界面退出后，内核可能还占着端口，这时立刻启动的新实例会换一个端口（比如 7900），系统代理也跟着改。正确做法是等界面和内核都退出、端口空出来，再启动。

## sing-box（SFM / SFA / Hiddify / GUI.for.SingBox）

- **规则**：`gen_proxy_rules.py --target singbox`。
  - 生成的是 `route.rules` 里的一条规则，加一个只含固定出口的 `selector`。
  - `route.final` 指向代理出站。
- **DNS**：给 Claude 域名配置经代理的远端 DNS 或 fakeip，避免在本地解析。
- **TUN**：`strict_route: true`。macOS 客户端通过网络扩展运行，先用上面的 `ps` 确认它的运行身份，再决定能不能用完整模式。

## xray / v2rayN（Windows 上常见）

- **规则**：`gen_proxy_rules.py --target xray`。
  - 在 v2rayN 里选“绕过大陆（白名单）”这类方案，把生成的规则加为**第 1 条**。
  - **不要用“黑名单”方案**，建议直接删掉，免得误切过去。
- **身份**：内核以你的用户身份运行。Windows 用本项目的程序级规则（`windows/install.ps1`），不要尝试按用户封。
- **节点地址不会自动更新**：落地 IP 换了之后，手动或从订阅更新，否则所有流量都出不了境（门禁会报“测不到出口”）。
- **直接改配置文件时**：改 v2rayN 数据库（`guiConfigs/guiNDB.db`）之前先退出 v2rayN，否则它退出时会把内存里的旧配置写回去。

## Surge for Mac

- **规则**：`gen_proxy_rules.py --target surge`，`FINAL` 指向你的代理组。
- **只能用 `anthropic-only`**：Surge 主程序以你的用户身份运行（监听代理端口的就是它，安装脚本会拒绝完整模式），Enhanced Mode 同理。

## 其它客户端（ShadowsocksX-NG、NekoRay、Hiddify、Qv2ray…）

只要满足两点就能用：有本地 HTTP 端口，能写按域名的规则。内核以你的用户身份运行时：macOS 用 `anthropic-only`，Windows 用程序级规则。

## 第三方模型供应商（`ANTHROPIC_BASE_URL`）

模型请求发给供应商，走不走直连由你的规则决定。但 **Claude Code 仍然会把遥测和设置请求发给 Anthropic**，所以门禁照样检查 Anthropic 线路的出口。状态栏会显示 `(provider <主机>)`。
