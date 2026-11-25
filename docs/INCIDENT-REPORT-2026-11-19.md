# ArmWall 故障分析与代码根治方案记录 (2026-11-19)

> **文档编号**：INCIDENT-20261119-01  
> **涉及设备**：
> - `192.168.10.1`（ImmortalWrt `21.02-SNAPSHOT`，`luci-app-passwall` 4.68）  
> - `192.168.10.233`（`armbian`，`aarch64`，`armwall 0.7.1-dev` + `sing-box 1.14.4`）  
> - `192.168.10.217`（`onecloud`，`armv7l`，`armwall v0.7.0+dirty` + `sing-box 1.14.4`）  
> **当前状态**：现场已止血恢复（`.233` 已关闭 DNS 劫持并切至可用配置、`.233` 上冗余的 `daed` 已卸载清理、路由器 `192.168.10.1` 已添加基于 MAC 的 IPv4/IPv6 直连放行规则）；仓库源码暂未修改，本文档记录待实施的代码根治方案。

---

## 一、故障现象

1. 将路由器 `192.168.10.1` PassWall 的 TCP SOCKS 出站从 `192.168.10.217:11080` 切换到 `192.168.10.233:11080` 后，使用同一代理节点（`wikih gost` / `sub-1794905429698841162`）无法更新 Google Play。
2. 将 `.233` 切换为「全局模式（`global`）+ 分流 DNS（`dns.enabled = true`）」后，局域网设备无法访问需要代理的网站，`.233` 切回关闭分流 DNS 后恢复。

---

## 二、根因分析 (RCA)

### 1. 切换 `.233` 后 Google Play 无法更新 + `sing-box` 250% CPU 回环

1. **运行模式与强制代理后缀未覆盖 Google Play 全量域名**：
   - `.217` 工作在 `global` 模式，所有非内网 TCP 流量统一由节点出站。
   - `.233` 当时工作在 `bypass_cn` 模式，[`config.go`](../config.go#L201-L210) 内置的 `defaultForceProxyDomainSuffixes` 仅包含 8 个后缀（`googleapis.com`、`clients.google.com`、`gvt1.com`、`gvt2.com`、`dl.google.com`、`www.gstatic.com`、`redirector.gvt1.com`、`redirector.c.play.google.com`）。
   - Google Play 实际使用的 **`services.googleapis.cn`**、**`connectivitycheck.gstatic.com`**，以及 APK 下载重定向域名 **`*.xn--ngstr-lra8j.com`** 不在这 8 条后缀中，但在 `/var/lib/armwall/rules/geosite-cn.srs` 中均命中（已用 `sing-box rule-set match` 实测确认）。
   - 路由器 `192.168.10.1` 将 `services.googleapis.cn` 解析到境外 IP（如 `172.217.75.110`、`2607:f8b0:4023:200b::6e`），因不在 `passwall_chnroute` 中而被转发到 `.233:11080`；`.233` 嗅探 SNI 后命中 `geosite-cn -> direct` 走直连出站并超时（Clash API `/connections` 与 `/var/log/armwall/sing-box.log` 均可见大量 `services.googleapis.cn -> direct` 及 `172.217.75.110:443`、`142.251.150.120:443`、`192.178.164.110:443`、`[2001:4860:4826:7800::]:443` 超时）。
2. **路由器未放行旁路网关自身出站导致的直连回环风暴**：
   - 路由器 `192.168.10.1` 原先 `passwall.@global[0].acl_enable='0'`，`passwall_vpslist` 仅按**目标地址**放行 `.233`/`.217`，未按**源地址**放行两台 ArmWall 机器的出站流量。
   - `.233` 在 `bypass_cn` 模式下将 `services.googleapis.cn`、`connectivitycheck.gstatic.com`、`sgshort.wechat.com`（`101.32.104.41`/`129.226.3.47`）、`sgminorshort.wechat.com`（`161.120.168.229`）等非大陆 IP 走 `direct` 经网关 `192.168.10.1` 发出时，被路由器 `PSW` 链再次 TPROXY 截获并打回 `.233:11080`，形成高速死循环（现场观测 `.233` 的 `sing-box` CPU 达 250%、本机 3,124 个 `TIME-WAIT` 连接、路由器 1,013 个连向 `.233:11080` 的 `TIME_WAIT` 连接）。

### 2. `.233` 切换「全局模式 + 分流 DNS」后局域网无法访问代理网站

1. **`config.go` 中 `hijack-dns` 规则顶层 `invert: true` 语义错误（核心代码 Bug）**：
   - [`config.go`](../config.go#L535-L543) 在 `s.DNS.Enabled && s.DNS.Hijack` 时生成：
     ```json
     {"protocol": "dns", "ip_cidr": ["8.8.8.8/32", "..."], "invert": true, "action": "hijack-dns"}
     ```
   - 在 `sing-box` 路由规则中，顶层 `"invert": true` 是对**整条规则条件**取反，即 `!(protocol == "dns" && ip_cidr in publicResolverCIDRs)`，而非仅对 `ip_cidr` 取反。
   - **所有正常 HTTPS/HTTP/TCP 连接**均满足 `protocol != "dns"`，取反后整条规则恒成立，导致所有非 DNS 代理流量在 `sniff` 之后直接命中 `action: hijack-dns`，被送入 DNS 解析器静默挂死超时（且 `warn` 级别日志无任何错误输出）。
2. **现场复现与对比验证**：
   - 在 `.233` 使用临时 `sing-box` 实例开启 `debug` 日志实测 `curl --socks5-hostname 192.168.10.233:11280 https://www.google.com/`，6 秒超时，日志明确输出：
     ```text
     router: sniffed protocol: tls, domain: www.google.com
     router: match[2] !(protocol=dns ip_cidr=8.8.8.8/32) => hijack-dns
     ```
   - `.217` 同样开「全局模式 + 分流 DNS」之所以正常，是因为 `.217` 的 `armwall.db` 中 `dns.hijack = false`（[REVIEW-2026-11-03.md](REVIEW-2026-11-03.md#L461) 中曾手动关闭），未生成该规则；而 `.233` 的 `dns.hijack = true`，开启分流 DNS 即触发此缺陷。

---

## 三、已执行的现场处置（2026-11-19）

1. **`.233` DNS 劫持与运行配置（用户侧完成）**：关闭 `.233` Web 面板中的「DNS 劫持」（`dns.hijack = false`）并切至 `global` + 分流 DNS，业务与 Google Play 恢复。
2. **路由器 `192.168.10.1` PassWall ACL 旁路网关放行（已落地并验收）**：
   - **评估结论（为何不能整段放行局域网 `192.168.10.0/24`）**：
     - PassWall 的透明代理正是对局域网段内的手机、PC 等客户端生效的；若把 `192.168.10.0/24` 设为源地址直连（且 PassWall ACL 本身也不支持 CIDR，仅支持 `ip`/`iprange`/`ipset`/`mac`），全屋设备将全部失去路由器代理。
     - 若改为划出小段 IP 范围（如预留 `.240-.254` 并收窄 DHCP 地址池），仍只覆盖 IPv4，无法覆盖随运营商前缀或 SLAAC 变化的 IPv6 地址。
     - **最优方案是按 MAC 地址放行**：核查 `/usr/share/passwall/iptables.sh`（第 306–309、384–385、428–429 行）确认，PassWall 的 `mac:` ACL 规则会**同时注入 IPv4 `iptables` 与 IPv6 `ip6tables` 的 `PSW` 链**，既不受旁路网关后续 IPv4/IPv6 地址变更影响，也不会误伤其它局域网终端。
   - **已执行配置**（原配置已备份为 `/etc/config/passwall.bak-20261119-1320`）：
     - 开启 `passwall.@global[0].acl_enable='1'`；
     - 新增 `acl_rule`（备注 `ArmWall旁路网关直连`），`sources='<.217 MAC> <.233 MAC>'`（分别对应 `.217` 与 `.233`），`tcp_proxy_mode='disable'`、`udp_proxy_mode='disable'`、`tcp_proxy_drop_ports='disable'`、`udp_proxy_drop_ports='disable'`（避免禁用 UDP 代理时仍触发 QUIC 443 丢弃规则）。
   - **验证**：重启 PassWall 后，`iptables -t mangle -L PSW -nv` 与 `ip6tables -t mangle -L PSW -nv` 均已生成两条 MAC `RETURN` 规则且计数正常递增；经路由器 `127.0.0.1:1070` 测试 `google.com/generate_204`（204）、`play.googleapis.com`（404）、`dl.google.com`（302）均正常。
3. **卸载 `.233` 上的 `daed`（已落地并验收）**：
   - 停止并禁用 `daed.service`，执行 `apt-get purge -y daed`，清理 `/etc/daed`、`/usr/share/daed`、`/sys/fs/bpf/daed`，并清理残留的虚拟网卡 `dae0` 与网络命名空间 `daens`。

---

## 四、待实施的代码根治方案（后续修改仓库）

### 1. 修复 `hijack-dns` 公共解析器排除规则（高优先级）

- **问题位置**：[`config.go`](../config.go#L535-L543) 与 [`config_test.go`](../config_test.go#L629-L662)。
- **修改方案**：将扁平带 `invert: true` 的规则改为 `sing-box` 的 `logical`（`mode: "and"`）复合规则，仅对 `ip_cidr` 子规则取反，确保 `protocol: "dns"` 本身不被取反：
  ```go
  if s.DNS.Enabled && s.DNS.Hijack {
      rules = append(rules, map[string]any{
          "type": "logical",
          "mode": "and",
          "rules": []any{
              map[string]any{"protocol": "dns"},
              map[string]any{"ip_cidr": publicResolverCIDRs, "invert": true},
          },
          "action": "hijack-dns",
      })
  }
  ```
- **已预验证语法**：已在 `.233` 使用 `sing-box check`（v1.14.4）确认该 `logical` `hijack-dns` 规则结构校验返回 `0`。
- **测试补齐**：在 `config_test.go` 的 `TestConfigDNSHijackSkipsPublicResolvers` 中，断言生成规则为 `type: "logical"`、`mode: "and"`，且不能在顶层出现 `invert: true` + `protocol: "dns"`；如有条件可增加 `sing-box` 路由/规则匹配测试，确保非 DNS（如 `tls` / `www.google.com:443`）不会命中 `hijack-dns`。

### 2. 扩充内置强制代理域名后缀 `defaultForceProxyDomainSuffixes`（中优先级）

- **问题位置**：[`config.go`](../config.go#L201-L210)（同时作用于 `route.rules` 与 `dns.rules`）。
- **修改方案**：在 `defaultForceProxyDomainSuffixes` 中评估补充被 `geosite-cn` 收录但 Google Play / Android 连通性检查依赖的域名后缀：
  - `googleapis.cn`（覆盖 `services.googleapis.cn`）
  - `xn--ngstr-lra8j.com`（覆盖 Google Play 中国区 APK CDN `r*---sn-*.xn--ngstr-lra8j.com`）
  - `gstatic.com`（替代/扩展现有的 `www.gstatic.com`，覆盖 `connectivitycheck.gstatic.com` 等）
- **注意点**：放开 `gstatic.com` / `googleapis.cn` 到强制代理后，所有子域名流量和解析都将走代理节点（若希望某地区特定服务直连需确认无副作用）；至少应先覆盖 `services.googleapis.cn`、`xn--ngstr-lra8j.com`、`connectivitycheck.gstatic.com`（或整个 `gstatic.com`）。

### 3. 自动绕过代理节点自身地址（高优先级，延续 2026-11-17 遗留项）

- 参见 [INCIDENT-REPORT-2026-11-17.md](INCIDENT-REPORT-2026-11-17.md#五后续待修改事项代码层面长期根治)：在 [`config.go`](../config.go) 生成 `route.rules` 时，遍历已启用节点的 `Server` 与 `ServerName`（区分 IP/CIDR 与域名），在 `final` 与代理规则之前自动插入高优先级 `direct` 绕过规则，从 ArmWall 侧彻底杜绝自回环。
