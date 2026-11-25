# ArmWall

面向 Armbian / Debian 单板计算机的轻量级局域网代理与透明网关管理系统。  
基于 **Go 单二进制（内置 Web UI）+ sing-box 1.14+ + NaiveProxy + SQLite WAL + nftables TProxy**，低内存开销，开箱即用。

## 核心特性

### 代理内核与智能分流
- **多协议支持**：手动添加、分享链接导入与 HTTPS 订阅刷新，支持 `VLESS`（含 Reality）、`VMess`、`Trojan`、`Shadowsocks`、`Hysteria2`、`AnyTLS` 与 `NaiveProxy`（支持中转节点独立 SNI 与 `host-resolver-rules` 映射）。
- **分流模式与规则集**：支持「绕过国内（`bypass_cn`）」「GFW 模式（`gfw`）」「全局代理（`global`）」，内置 4 套离线 SRS 规则包（`geoip-cn`、`geosite-ads`、`geosite-cn`、`geosite-proxy`），支持纯离线首次引导与内容哈希比对免重启更新。
- **强制代理与节点防回环**：内置 Google Play / Google APIs / 连通性检测域名后缀强制代理（支持自定义扩充）；自动为已启用节点的公网服务器地址与 NaiveProxy 中转 SNI 插入 `direct` 绕过规则，防止全局或旁路模式下流量自回环。
- **全天候 DNS 架构**：始终生成 `sing-box` 内置 `dns` 块（远程 DoH/DoT + 国内直连 DNS 分流），不依赖宿主机 `systemd-resolved`；`hijack-dns` 采用 `logical and` 规则自动放行发往公共 DNS 的查询；代理节点出站自身域名走 `direct-dns`，避免主节点故障时测活死锁。
- **NaiveProxy UDP 兜底**：当有效 UDP 出站无法中继 UDP（如纯 NaiveProxy）时自动阻断境外 UDP，让 QUIC 快速回落 TCP，不再黑洞超时。

### 高可用、故障转移与策略管理
- **全局自动故障转移（v0.8.0）**：后台常驻协程周期性对在用节点执行 Clash API URLTest；连续失败达阈值后按顺序探测「备用 1 → 备用 2 → …」，跳过不可用节点并通过本地 Clash API **零重启热切**至首个可用备用节点；支持开关控制「原主节点恢复后自动切回」，并在「概览」页实时展示熔断状态与切换记录。
- **策略组与 ACL**：支持 `Selector`（手动切换）与 `URLTest`（自动测速择优）策略组；TCP/UDP 出站可独立指定节点或策略组；支持按源 IP/CIDR、MAC、协议与目标端口分流的 ACL（MAC ACL 通过独立 TProxy 入口分流）。
- **多维度测速与拖拽排序**：支持并发批量 `Ping`（`-n -c 3` 平均 RTT）、`TCP`、`URLTest` 节点测速与临时按延迟排序；支持鼠标/触屏拖拽调整节点顺序且不中断现有连接。

### 安全、诊断与低损耗运维
- **按需作用域重启**：独立比对 `sing-box` 与 `NaiveProxy` 配置指纹，仅重启实际变更的进程；故障转移切流与节点排序等操作零重启。
- **一键连通性诊断**：在「系统管理」页实测代理端口、域名/IP（含 SNI）模式探测、SOCKS5 UDP ASSOCIATE 往返、主机解析器及最近日志连接/错误汇总。
- **安全加固**：管理面板默认 `lan` 私网白名单 + Bearer Token 鉴权（支持面板在线热修改 Token）、严格 CSP、静态目录禁止列表、HTTPS 下载重定向校验、配置导入导出与自动备份回滚、核心在线更新与手动上传（ELF 架构 + SHA256 严格校验）。
- **NaiveProxy 守护与自愈**：独立进程监督器按 PID 管理实例、错峰并发健康探活与指数退避自愈，配合 `LimitNOFILE=65535` 防止高并发 FD 耗尽。

---

## 快速安装

在目标 Armbian / Debian 设备上执行一键安装脚本（默认安装最新正式 Release，自动匹配架构并校验 `SHA256SUMS`）：

```bash
curl -fsSL https://github.com/rainsmen/armwall/releases/latest/download/one-click-install.sh | sudo sh
```

全新安装默认启用 `lan` 模式，监听 `0.0.0.0:8080`，仅放行回环与常见私网地址（`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`）。首次登录请使用安装器输出的管理 Token（保存在权限 `0600` 的 `/etc/armwall/armwall.env`）。

### 自定义安装选项

```bash
# 仅允许本机回环访问
curl -fsSL https://github.com/rainsmen/armwall/releases/latest/download/one-click-install.sh |
  sudo env ARMWALL_WEB_ACCESS=local sh

# 自定义监听端口与允许访问网段
curl -fsSL https://github.com/rainsmen/armwall/releases/latest/download/one-click-install.sh |
  sudo env ARMWALL_WEB_ACCESS=custom \
    ARMWALL_LISTEN=0.0.0.0:9000 \
    ARMWALL_WEB_ALLOWED_CIDRS=192.168.50.0/24 sh

# 安装指定版本
curl -fsSL https://github.com/rainsmen/armwall/releases/latest/download/one-click-install.sh |
  sudo env ARMWALL_RELEASE=v0.8.0 sh

# 开发测试：从源码分支安装（生产环境不推荐）
curl -fsSL https://github.com/rainsmen/armwall/releases/latest/download/one-click-install.sh |
  sudo env ARMWALL_INSTALL_CHANNEL=source ARMWALL_REF=main sh
```

升级会完整保留现有 Web 访问配置、`/etc/armwall/armwall.env`、SQLite 数据库与配置备份；核心升级前在 `/var/lib/armwall/backups/` 保留最近 3 份旧核心。

### 离线安装

将对应架构二进制与 `armwall-install-files.tar.gz` 解压至同一目录后执行：

```bash
sudo ./install.sh
# 或显式指定二进制路径
sudo ./install.sh ./armwall-linux-armv7
```

---

## 支持架构

| 架构 | 构建文件 | sing-box 在线更新 | NaiveProxy 在线更新 |
| --- | --- | --- | --- |
| ARMv6 | `armwall-linux-armv6` | 手动上传兼容版本 | 手动上传兼容版本 |
| ARMv7 / armhf | `armwall-linux-armv7` | 支持 | 支持 |
| ARM64 / aarch64 | `armwall-linux-arm64` | 支持 | 支持 |
| AMD64 / x86_64 | `armwall-linux-amd64` | 支持 | 支持 |

---

## 使用指南

### 自动故障转移
1. 打开 Web 面板「概览 → 自动故障转移」，按优先级顺序添加「备用 1、备用 2…」节点。
2. 设置探测间隔（默认 `30s`）、连续失败切换次数（默认 `3` 次）、主节点恢复确认次数（默认 `2` 次）以及是否勾选「原主节点恢复后自动切回」。
3. 勾选「启用自动故障转移」并保存。
4. **生效条件与说明**：
   - 仅当「分流与 DNS → TCP 默认出站」为「当前运行节点」时自动接管（避免与手动指定的策略组冲突）。
   - 启用后会在 `sing-box` 中生成托管 `failover-auto` 出站，`remote-dns` 也会跟随切流；切换与回切均通过本地 Clash API 热执行，**不重启 `sing-box`**。
   - 若主/备节点混用 NaiveProxy 与支持 UDP 的节点（如 VLESS / Hysteria2），建议按需单独配置「UDP 默认出站」。

### 客户端接入
- **Mixed 代理（推荐，零侵入）**：客户端 SOCKS5 / HTTP 代理指向 `<Armbian IP>:11080`（可在概览页修改端口）。
- **透明网关（TProxy）**：
  1. 在「分流与 DNS」配置代理模式与内置 DNS（监听地址填本机局域网 IP）。
  2. 在页面底部启用透明网关（LAN/WAN 留空自动检测；`gateway.sh` 默认同时接管 `tailscale0`，可通过 `ARMWALL_EXTRA_IFS` 调整或置空）。
  3. 将客户端 IPv4 网关与 DNS 设为本机局域网 IP（MAC ACL 仅适用于同一二层网段，跨网段请使用 IP/CIDR ACL）。

---

## 端口、文件与安全

| 用途 | 默认地址/端口 | 说明 |
| --- | --- | --- |
| Web 管理面板 | `0.0.0.0:8080` | `lan` 模式仅放行私网；需 Bearer Token，禁止公网直接暴露 |
| Mixed SOCKS5 / HTTP | `0.0.0.0:11080` | 局域网代理入口 |
| 透明代理 TProxy | `0.0.0.0:11081` | 供 nftables 透明网关规则重定向（MAC ACL 依次递增端口） |
| Clash API | `127.0.0.1:9090` | 仅本地监听，带随机 `clash.secret`，供测速与故障转移热切使用 |
| NaiveProxy 本地桥接 | `127.0.0.1:12000+` | 每个已启用 Naive 节点独立分配持久端口 |

- **Token 管理**：可在「系统管理 → 管理 Token」在线修改（≥8 位，原子写入 `/etc/armwall/armwall.env`，立即生效无需重启）。
- **公网访问**：管理面板使用明文 HTTP，请勿将 `0.0.0.0/0` 加入白名单；如需远程管理，请使用 VPN（如 Tailscale）或带 HTTPS 的反向代理。
- **主要路径**：`/usr/local/bin/armwall`、`/etc/armwall/sing-box.json`、`/etc/armwall/naive/`、`/var/lib/armwall/armwall.db`、`/var/lib/armwall/rules/`、`/var/log/armwall/`。

### 服务与卸载

```bash
systemctl status armwall.service armwall-sing-box.service armwall-naive.service armwall-gateway.service
systemctl list-timers 'armwall-*'

# 卸载（保留数据）
sudo armwall-uninstall
# 彻底卸载（含数据库、Token、配置与备份，不可恢复）
sudo armwall-uninstall --purge
```

---

## 代码结构与本地构建

| 文件 | 职责 |
| --- | --- |
| `main.go` | CLI 入口、HTTP 服务与后台故障转移协程启动 |
| `models.go` | `Store`、`Node`、`StrategyGroup`、`FailoverSettings` 等数据模型 |
| `failover.go` | 全局自动故障转移状态机、后台探活协程与 API |
| `config.go` / `naive.go` | `sing-box` 配置生成与原子写入、节点绕过、NaiveProxy 端口与 SNI 映射 |
| `state.go` / `storage.go` / `migrations.go` | 文件锁、`persistStore` 事务与按需重载、SQLite WAL 持久化与迁移 |
| `subscription.go` / `rules.go` / `download.go` | 订阅抓取与节点对齐、规则集更新回滚、强制 HTTPS 下载 |
| `validate.go` / `ports.go` | 节点、策略组、故障转移、ACL、DNS 与端口冲突校验 |
| `webserver.go` / `auth_token.go` / `api.go` / `api_*.go` | HTTP 安全头与鉴权、Token 热更新、分领域 REST API |
| `diagnostics.go` / `management.go` / `strategy_runtime.go` / `clash.go` / `runtime.go` | 连通性诊断、备份与核心上传、Clash API、systemd 生命周期控制 |
| `web/index.html` / `web/styles.css` / `web/js/*.js` | 内嵌无框架 Web 控制台（零内联脚本/样式，严格 CSP） |

本地开发需要 Go 1.26+ 与 Node.js（用于 JS 语法校验）：

```bash
make test
make release VERSION=0.8.0
```

---

## 文档索引

- [更新日志（CHANGELOG.md）](CHANGELOG.md)
- [安全策略（SECURITY.md）](SECURITY.md)
- [全局架构与综合改进计划（v0.4–v0.8 演进）](docs/CONSOLIDATED-IMPROVEMENT-PLAN-2026-10-29.md)
- [后台自动故障转移设计提案与实施记录](docs/PROPOSAL-BACKGROUND-FAILOVER.md)
- [深度复评与功能演进（2026-11-03：路由/DNS/诊断/前端加固）](docs/REVIEW-2026-11-03.md)
- [中转节点 SNI 与 Ping 排查报告（2026-11-09）](docs/REVIEW-2026-11-09.md)
- [线上故障复盘记录](docs/)（[2026-10-29](docs/INCIDENT-REPORT-2026-10-29.md) · [2026-11-17](docs/INCIDENT-REPORT-2026-11-17.md) · [2026-11-19](docs/INCIDENT-REPORT-2026-11-19.md) · [2026-11-25](docs/INCIDENT-REPORT-2026-11-25.md)）
