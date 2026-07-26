# ArmWall

ArmWall 是面向 Armbian/Debian 设备的局域网代理网关。它使用 sing-box 处理 mixed SOCKS5/HTTP、透明代理、DNS 和分流规则，并通过 Web 页面管理节点、订阅、策略组、ACL、规则集、日志与核心程序。

## 功能

- 手动节点、分享链接和 HTTPS 订阅导入，支持 VLESS、VMess、Trojan、Shadowsocks、Hysteria2、AnyTLS 与 NaiveProxy。
- 绕过国内、GFW 规则和全局代理模式，TCP/UDP 可分别选择节点或策略组。
- Selector、URLTest、Fallback 策略组，显示实际运行成员与最近延迟。
- Ping、TCP、URLTest 节点测速，以及常用国内外网站连通测试。
- sing-box DNS、DNS 劫持、FakeIP、GeoSite/GeoIP 规则与广告阻止规则；规则支持逐项备用地址、自动更新间隔与手动更新。
- 按源 IP/CIDR、MAC、协议和目标端口设置 ACL。MAC ACL 由 nftables 分流到独立 TProxy 入口。
- sing-box、NaiveProxy 在线更新和手动上传，更新前自动保留旧二进制。
- SQLite 持久化、配置导入导出、服务器端备份和恢复。

## 支持架构

| ArmWall 架构 | 构建文件 | sing-box 在线更新 | NaiveProxy 在线更新 |
| --- | --- | --- | --- |
| ARMv6 | `armwall-linux-armv6` | 手动上传兼容版本 | 手动上传兼容版本 |
| ARMv7/armhf | `armwall-linux-armv7` | 支持 | 支持 |
| ARM64/aarch64 | `armwall-linux-arm64` | 支持 | 支持 |
| AMD64/x86_64 | `armwall-linux-amd64` | 支持 | 支持 |

ArmWall 本身四种架构均为静态二进制。上游 sing-box 不发布 ARMv6 官方构建，因此 ARMv6 设备需要手动上传可用核心。

## 构建

需要 Go 1.22 或更高版本和 Node.js（用于 JavaScript 语法检查）。

```bash
make test
make release VERSION=0.1.0
```

## 安装

在目标 Armbian/Debian 设备上执行一键安装命令：

```bash
curl -fsSL https://raw.githubusercontent.com/rainsmen/armwall/main/one-click-install.sh | sudo sh
```

脚本会下载完整安装包，根据 `uname -m` 自动选择 ARMv6、ARMv7、ARM64 或 AMD64 架构的 ArmWall 程序，并安装、启用所需服务。安装完成后打开 `http://设备IP:8080`，首次访问输入安装器输出的管理 Token；Token 保存在权限为 `0600` 的 `/etc/armwall/armwall.env`。

### 离线安装

无法联网下载项目时，将完整发布包传到设备并在解压目录中以 root 运行：

```bash
sudo ./install.sh
```

安装器会自动选择当前目录中的架构构建文件，也可明确指定：

```bash
sudo ./install.sh ./armwall-linux-armv7
```

主要文件：

- `/usr/local/bin/armwall`
- `/etc/armwall/sing-box.json`
- `/etc/armwall/naive/`
- `/var/lib/armwall/armwall.db`
- `/var/log/armwall/`

## 客户端接入

### Mixed 代理

在客户端代理设置中填写 Armbian 设备 IP，SOCKS5 或 HTTP 端口使用 Web 概览页显示的 mixed 端口，默认 `11080`。此方式不修改客户端网关。

### 透明网关

1. 在“分流与 DNS”中配置模式、出站和 DNS；DNS 监听地址填写 Armbian 的局域网 IP。
2. 在同一页面填写 LAN/WAN 接口并启用透明网关。
3. 将客户端 IPv4 网关和 DNS 都设置为 Armbian 的局域网 IP。

透明网关使用 nftables TProxy 和策略路由，启用时保存并打开 `net.ipv4.ip_forward`，关闭时恢复之前的值。启用状态与 LAN/WAN 接口会持久化，并由 `armwall-gateway.service` 在设备启动后恢复；活动网关会在 ArmWall 配置更新后自动重载 ACL。当前网关规则仅处理 IPv4；客户端存在原生 IPv6 时，应另行配置 IPv6 路由或在客户端关闭 IPv6，避免绕过代理。

MAC ACL 只能识别与 Armbian 位于同一二层网络中的客户端。跨路由网络请使用源 IP/CIDR ACL。

## 服务

```bash
systemctl status armwall.service
systemctl status armwall-sing-box.service
systemctl status armwall-naive.service
systemctl status armwall-gateway.service
systemctl status armwall-subscription-update.timer
systemctl status armwall-rule-update.timer
```

NaiveProxy 节点由独立本地 SOCKS 入口承载，再由 sing-box 统一纳入分流和策略组。未安装 NaiveProxy 核心时仍可保存节点，但该节点在安装核心前不可连接。

配置备份包含节点密码、订阅地址等敏感数据。下载后应按凭据文件保护；导入或恢复前 ArmWall 会自动创建一份当前配置备份。
