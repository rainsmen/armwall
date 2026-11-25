# ArmWall 故障分析与加固记录 (2026-11-17)

> **文档编号**：INCIDENT-20261117-01  
> **受影响主机**：`192.168.10.217`（`onecloud`，Linux `6.12.28-current-meson`，`armv7l`）  
> **涉及节点**：`wikih gost`（节点 ID：`sub-1794905429698841162`，`naive` 中转节点）  
> **故障时间**：2026-11-17 16:50:32 ~ 16:58:15 CST  
> **当前状态**：✅ 已彻底根治并随 `v0.8.0` 发布验收（系统 FD 限制、探活参数、`sing-box` 节点自绕过规则及 `armwall-sing-box.service` `LimitNOFILE=65535` 均已落地并在 `.217`/`.233` 验证通过）。  
> **脱敏说明**：公开仓库中已对个人域名、节点 IP 与账号凭据脱敏。

---

## 一、故障现象

管理员在 ArmWall 切换选中节点 `wikih gost`（`sub-1794905429698841162`）后，代理流量全部超时不可用，切回 `dmit`（`sub-1793278930491431059`）后恢复。

但对 `wikih gost` 单独核查时，节点自身配置与链路均正常：
* **数据库配置**（`/var/lib/armwall/armwall.db` `nodes` 表）：
  * `server`: `hknat.<域名>`，`port`: `4441`
  * `server_name`: `wikih.<域名>`，`transport`: `https`，`naive_port`: `12010`
* **NaiveProxy 配置**（`/etc/armwall/naive/0008.json`）：
  * `listen`: `socks://127.0.0.1:12010`
  * `host-resolver-rules`: `MAP wikih.<域名> hknat.<域名>`
  * `proxy`: `https://<用户>:<密码>@wikih.<域名>:4441`
* **基础连通性实测**（从 `192.168.10.217` 直接测试）：
  * `hknat.<域名>` 解析为 IPv6 `<中转IPv6>`，`ping -6` 10 包 0% 丢包（平均 0.595 ms）。
  * `openssl s_client` 连 `hknat.<域名>:4441`（SNI `wikih.<域名>`）证书验证通过（`Verify return code: 0 (ok)`）。
  * 直接通过 `socks5h://127.0.0.1:12010` 访问：`cp.cloudflare.com/generate_204` 5 并发全部返回 `204`（1.26s ~ 1.43s）；`www.google.com/generate_204` 10 次全部 `204`（1.31s ~ 1.91s）；DoH `1.1.1.1/dns-query`（2.46s）、`google.com`（2.15s）、`youtube.com`（2.01s）均返回 `200`；出口 IP 正常。

---

## 二、完整事件时序线

结合 `/var/log/armwall/naive.log`、`/var/log/armwall/sing-box.log` 及 `journalctl`：

| 时间 (CST) | 组件 / 日志来源 | 关键事件 |
| :--- | :--- | :--- |
| `16:50:32-33` | `systemd` | `armwall-naive.service` 与 `armwall-sing-box.service` 重启，11 个 `naive` 实例同时冷启动 |
| `16:50:52-53` | `armwall-naive-supervisor` | 15s 启动宽限期结束后并发探活（`-m 6`），端口 `12001`、`12009`、`12005`、`12010` 均报超时（`HTTP 000, failure 1/3`） |
| `16:51:07-09` | `armwall` / `systemd` | 管理员将 `selected_node` 切换为 `sub-1794905429698841162`（`wikih gost`），`armwall-sing-box.service` 重启 |
| `16:51:22` | `naive`（日志内 UTC `085122`） | `naive` 进程开始密集报错 `CreatePlatformSocket() failed: Too many open files (24)`、`Accept error: ERR_INSUFFICIENT_RESOURCES`、`handshake failed ... net_error -100` |
| `16:51:44` | `armwall-naive-supervisor` | 端口 `12010` 等第 2 次探活失败（`HTTP 000, failure 2/3`） |
| `16:52:00` | `sing-box` | 开始大量记录 `open connection to [<中转IPv6>]:4441 using outbound/socks[sub-1794905429698841162]: dial tcp 127.0.0.1:12010: i/o timeout`（`16:52` 单分钟 475 条错误） |
| `16:52:38` | `armwall-naive-supervisor` | 端口 `12010` 连续 3 次探活失败，supervisor 强制重启 `/etc/armwall/naive/0008.json` 并进入 300s 退避 |
| `16:54:11-14` | `armwall` / `sing-box` | 管理员切回 `dmit`（`sub-1793278930491431059`），`sing-box` 关闭挂起连接并刷出 444 条 `context canceled` |
| `16:58:15` | `armwall-naive-supervisor` | 端口 `12010` 探活恢复（`HTTP 204`） |

---

## 三、根因深度分析 (RCA)

### 1. 主因：上游 `192.168.10.1` 将 `wikih gost` 自身端口流量送入 `10.217:11080`，在 `global` 模式下形成回环风暴
* 通过 Clash API（`127.0.0.1:9090/connections`）观察到，来自 `192.168.10.1` 的 `mixed/mixed-in`（`11080`）入站连接中包含大量发往代理节点自身地址的流量：
  * `wikih.<域名>:4441`（`destinationIP: <中转IPv6>`，即 `hknat.<域名>`）
  * `wikih6.<域名>:4435`（`<中转IPv6>`）
  * `hknat.<域名>:4431`（`<中转IPv6>`）
  * `ushome.<域名>:4431`（`<节点IPv4>`）
* 当前 `/etc/armwall/sing-box.json` 工作在 `mode: "global"`（`final` 指向 `selected_node`），`route.rules` 中仅有 `hijack-dns`、`sniff`、`ip_is_private -> direct`、Google 强制代理后缀及 `udp -> block`，**没有任何对代理节点自身域名/IP 的 `direct` 绕过规则**。
* 当节点为 `dmit` 时，`192.168.10.1` 发来的 `4441` 连接通过 `dmit` 转发，不会撞车；一旦切换为 `wikih gost`，所有 `[<中转IPv6>]:4441` 入站流量全部命中 `final -> sub-1794905429698841162`，重新打回 `127.0.0.1:12010`（`wikih gost` 自身）。
* 统计 `/var/log/armwall/sing-box.log` 在 `16:50`–`16:54` 的报错目标：总计 **754 条**连接发往 `[<中转IPv6>]:4441`。

### 2. 放大因素：`armwall-naive.service` 文件描述符软限制仅 `1024`
* 检查 `/proc/<pid>/limits` 显示，`armwall-naive.service` 下所有 `naive` 进程 `Max open files` 软限制均为 `1024`（对比独立 `naiveproxy.service` 为 `65535`）。
* 切换节点 15 秒后，回环并发迅速耗尽 1024 个 FD，`naive.log` 累计出现 `Too many open files (24)` 2,895 次、`Accept error: ERR_INSUFFICIENT_RESOURCES` 231 次、`handshake failed ... net_error -100` 2,821 次，导致 `127.0.0.1:12010` 彻底失去响应，连带 DoH（`1.1.1.1`）及所有正常网页请求一起超时。

### 3. 次要叠加因素：`armwall-naive-supervisor` 探活宽限期与超时过短，冷启动/并发抖动易误杀
* 原 `naive-supervisor.sh` 默认 `STARTUP_GRACE=15`，且 `health_round()` 在同一时刻并发拉起全部 11 个 `curl` 探活，参数硬编码为 `--connect-timeout 4 -m 6`。
* `wikih gost` 为 IPv6 `hknat` 中转链路，正常空闲单次 HTTPS 耗时 1.3s ~ 2.5s；在 11 个实例同时冷启动或系统并发较高时，很容易超过 6 秒而被判失败并重启（`16:50:53` 在尚未切换节点时即首次超时，随后 `16:52:38` 满 3 次触发 300s 退避重启）。

---

## 四、已落地的缓解措施（2026-11-17）

1. **上游路由器侧（用户侧配置）**：在上游路由器增加 `direct` 规则放行代理节点域名/IP 及 `192.168.10.217` 本机出站流量，消除入站回环来源。
2. **提高 NaiveProxy 文件描述符上限**：
   * 在本地 [`armwall-naive.service`](../armwall-naive.service) 与真机 `/etc/systemd/system/armwall-naive.service` 的 `[Service]` 段增加 `LimitNOFILE=65535`，执行 `systemctl daemon-reload` 并重启 `armwall-naive.service` 生效。
3. **优化 `naive-supervisor.sh` 抗冷启动与并发抖动能力**：
   * 在本地 [`naive-supervisor.sh`](../naive-supervisor.sh) 与真机 `/usr/local/bin/armwall-naive-supervisor` 中调整：
     * 默认启动宽限期 `ARMWALL_HEALTH_STARTUP_GRACE` 由 `15` 秒提高到 `30` 秒；
     * 探活连接超时 `ARMWALL_HEALTH_CONNECT_TIMEOUT` 默认 `5` 秒，单次请求总超时 `ARMWALL_HEALTH_PROBE_TIMEOUT` 默认 `12` 秒（原硬编码 `4s`/`6s`）；
     * 增加 `ARMWALL_HEALTH_STAGGER`（默认 `0.2` 秒），将各端口探活错峰发起，避免多节点同毫秒并发挤占 ARMv7 CPU 与连接握手资源。

---

## 五、代码层面长期根治（✅ 已于 `v0.8.0` 落地验收）

1. **`sing-box` 路由生成逻辑自动绕过代理节点自身地址（✅ 已完成）**：
   * 在 [`config.go`](../config.go) 生成 `route.rules` 与 `dns.rules` 时，自动遍历所有已启用节点，提取公网 IP CIDR、服务器域名及 NaiveProxy 真实 SNI（排除 Reality / 第三方伪装 SNI），在 `ip_is_private` 之后插入 `direct` 绕过规则与 `direct-dns` 解析规则。
2. **`armwall-sing-box.service` 文件描述符限制（✅ 已完成）**：
   * 已在 [`armwall-sing-box.service`](../armwall-sing-box.service) 显式声明 `LimitNOFILE=65535`，并在 `.217` 与 `.233` 实测 `/proc/<pid>/limits` 生效。
