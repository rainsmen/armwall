# ArmWall

ArmWall 是面向 Armbian/Debian 设备的局域网代理网关。它使用 sing-box 处理 mixed SOCKS5/HTTP、透明代理、DNS 和分流规则，并通过 Web 页面管理节点、订阅、策略组、ACL、规则集、日志与核心程序。

## 功能

- 手动节点、分享链接和 HTTPS 订阅导入，支持 VLESS、VMess、Trojan、Shadowsocks、Hysteria2、AnyTLS 与 NaiveProxy。
- 绕过国内、GFW 规则和全局代理模式，TCP/UDP 可分别选择节点或策略组。
- Selector、URLTest 策略组，显示实际运行成员与最近延迟。
- Ping、TCP、URLTest 节点测速，以及常用国内外网站连通测试。
- sing-box DNS、DNS 劫持、FakeIP、GeoSite/GeoIP 规则与广告阻止规则；规则支持逐项备用地址、自动更新间隔、手动更新和广告拦截开关。
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

需要 Go 1.26 或更高版本和 Node.js（用于 JavaScript 语法检查）。已用 `sing-box 1.13.15` 验证过配置生成。

```bash
make test
make release VERSION=0.1.0
```

## 安装

在目标 Armbian/Debian 设备上执行一键安装命令：

```bash
curl -fsSL https://raw.githubusercontent.com/rainsmen/armwall/main/one-click-install.sh | sudo sh
```

脚本会下载完整安装包，根据 `uname -m` 自动选择 ARMv6、ARMv7、ARM64 或 AMD64 架构的 ArmWall 程序，并安装、启用所需服务。全新安装默认使用 `lan` 模式，在 `0.0.0.0:8080` 监听 IPv4，并只允许来自回环地址及 `10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16` 的客户端。安装器会输出主机当前可用的访问地址。首次访问输入安装器输出的管理 Token；Token 保存在权限为 `0600` 的 `/etc/armwall/armwall.env`。

可在安装时选择访问模式：

```bash
# 只允许本机访问
curl -fsSL https://raw.githubusercontent.com/rainsmen/armwall/main/one-click-install.sh |
  sudo env ARMWALL_WEB_ACCESS=local sh

# 自定义监听地址和允许访问的客户端网段
curl -fsSL https://raw.githubusercontent.com/rainsmen/armwall/main/one-click-install.sh |
  sudo env ARMWALL_WEB_ACCESS=custom \
    ARMWALL_LISTEN=0.0.0.0:9000 \
    ARMWALL_WEB_ALLOWED_CIDRS=192.168.50.0/24 sh
```

生产安装建议固定 `ARMWALL_REF` 到 release tag，并设置 `ARMWALL_ARCHIVE_SHA256` 校验源码归档。

升级会保留已有 Web 访问模式、`/etc/armwall/armwall.env`、SQLite 数据库和配置备份，不会静默扩大管理面板的访问范围；升级核心前会在
`/var/lib/armwall/backups/` 保留最近 3 份旧核心。生产环境不要直接跟随 `main`，
应使用固定 tag，并在下载前验证归档 SHA256。

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

### 端口与安全

| 用途 | 默认地址/端口 | 说明 |
| --- | --- | --- |
| Web 管理面板 | `0.0.0.0:8080` | 新安装默认为 `lan` 模式；明文 HTTP，需要管理 Token，不允许公网客户端 |
| Mixed SOCKS/HTTP | `0.0.0.0:11080` | 由 sing-box 配置决定 |
| 透明代理 TProxy | `0.0.0.0:11081` | 仅供本机网关规则使用 |
| Clash API | `127.0.0.1:9090` | 随机 secret，仅供 ArmWall 后端访问 |
| NaiveProxy 本地 SOCKS | `127.0.0.1:12000+` | 每个 Naive 节点占用一个端口 |

管理 Token 保存在权限为 `0600` 的 `/etc/armwall/armwall.env`。轮换 Token 或修改 Web
访问配置后执行 `systemctl restart armwall.service`；浏览器中的旧 Token 需要在页面点击
“清除 Token”后重新输入。

Web 访问由以下变量控制：

- `ARMWALL_WEB_ACCESS=local`：只允许回环地址，监听地址必须是回环地址。
- `ARMWALL_WEB_ACCESS=lan`：监听 `0.0.0.0`，默认允许常见 IPv4 私网地址；可通过 `ARMWALL_WEB_ALLOWED_CIDRS` 缩小或扩展范围。
- `ARMWALL_WEB_ACCESS=custom`：必须同时明确设置 `ARMWALL_LISTEN` 和 `ARMWALL_WEB_ALLOWED_CIDRS`。

`0.0.0.0` 使监听不受 DHCP 地址变化影响，但浏览器仍需使用主机变化后的新地址。主机防火墙也必须允许相应端口。管理面板当前使用明文 HTTP；公网访问应使用 VPN 或带 HTTPS 的反向代理，不能通过加入 `0.0.0.0/0` 直接暴露。

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

日志默认写入 `/var/log/armwall/`，安装器会配置 logrotate（每日轮转，单文件超过
10 MiB 时提前轮转，保留 7 份）。规则或订阅首次更新失败时，可查看
`journalctl -u armwall-rule-update.service`、`journalctl -u armwall-subscription-update.service`
以及 sing-box 日志，再从 Web 页面手动重试。

配置备份包含节点密码、订阅地址等敏感数据。下载后应按凭据文件保护；导入或恢复前 ArmWall 会自动创建一份当前配置备份。

### 卸载

卸载前请先导出配置。确认不再需要数据后优先运行安装器放置的脚本：

```bash
sudo armwall-uninstall
```

如需连数据一起清空，可执行：

```bash
sudo armwall-uninstall --purge
```

`--purge` 会删除 Token、节点密码、订阅地址、数据库和备份，无法恢复。
