# 局域网 IPv6 前缀变更导致 ArmWall IPv6 节点持续失联故障分析与根治记录 (2026-11-25)

> **文档编号**：INCIDENT-20261125-01  
> **涉及设备**：
> - `192.168.11.1`（中国移动烽火 `HG6145F` 光猫，路由拨号模式，负责 PPPoE 与向下游委派 `/60` 前缀）
> - `192.168.10.1`（ImmortalWrt `21.02-SNAPSHOT`，`odhcpd` + `odhcp6c` + `luci-app-passwall` 4.68）
> - `192.168.10.233`（`armbian`，`aarch64`，`NetworkManager` + `armwall`）
> - `192.168.10.217`（`onecloud`，`armv7l`，`NetworkManager` + `armwall`）  
> **当前状态**：**已根治并验收**。已在路由器 `192.168.10.1` 实施方案 **1A**（关闭 LAN 有状态 DHCPv6 地址分配，改纯 SLAAC + 无状态 DHCPv6）与方案 **2B**（升级 `/usr/bin/check_ipv6.sh` 至 v2，新增 WAN/PD `/60` 前缀一致性比对、国内白名单 IPv6 出站探活、恢复后二次校验熔断，以及 `/etc/hotplug.d/iface/95-check-ipv6` `wan6 ifupdate` 事件触发）。`.233` 与 `.217` 均已验证仅获取新前缀 SLAAC 地址，全部 IPv6 中转节点恢复 `HTTP 204`。

---

## 一、故障现象

1. 2026-11-24 切换 `.233` 的 ArmWall 节点为 `wikih gost`（IPv6 `hknat` 中转），2026-11-25 早晨发现局域网代理整体不通，手机在 WiFi 下也无法使用（切换手机流量正常）。
2. 手动重启路由器 LAN 口（`06:24`）与 WAN/WAN6 口（`06:28`）后，手机在 WiFi 下恢复可用；但 `.233` 直到 `08:00+` 仍出现 `wikih gost` 及全部其他 IPv6 节点（`wikih6`、`hknat`、`dmit6`）URL Test 持续失败。

---

## 二、完整事件时间线

| 时间 (2026-11-25 CST) | 组件 / 日志来源 | 关键事件 |
| :--- | :--- | :--- |
| `01:25:43` | `.233` `naive.log` | 全部 10 个 naive 端口（IPv4 + IPv6）同时探活失败，光猫 `ppp0` 断线重拨 |
| `01:26:31` | 路由器 `logread` | `Reloading firewall due to ifupdate of wan6 (eth1)`；路由器路由表残留 `unreachable 2409:8a04:5389:20b0::/64`，光猫曾短暂切换至 `5389:20b0::/60` |
| `01:26:34` | `.233` `naive.log` | 全部 IPv4 节点恢复 `HTTP 204`；全部 4 个 IPv6 节点（`12006/12008/12009/12010`）自此持续失败 |
| `03:46:20` | `.233` `NetworkManager` | `.233` 触发 12 小时租期续租，由于路由器此时仍持有旧 PD 前缀，`.233` 再次续租到旧前缀地址 **`2409:8a04:5381:58a1::fb6/128`**（`valid_lft`/`preferred_lft` 重置为 `43200s`） |
| `04:01 ~ 04:02` | 光猫 `192.168.11.1` | `/var/run/ppp0.pid` 与 `/var/appconf/radvd.conf` 更新，光猫再次重拨并获取新前缀 **`2409:8a04:538a:ebb0::/60`**；`04:02:10` 路由器 `eth1` 通过 RA 更新到 `ebb0`，但 `wan6` PD 仍停留在旧的 `5381:58a1` |
| `01:30 ~ 06:00` | 路由器 `cron` | 旧版 `/usr/bin/check_ipv6.sh` 运行 10 次均误判正常，未触发 `ifup wan6` |
| `06:24:56 ~ 06:25:05` | 路由器 & `.233` | 管理员先重启 LAN 口，`.233` `eth0` 链路闪断重连（此时 `wan6` 尚未重启，仍是旧前缀） |
| `06:28:48 ~ 06:28:50` | 路由器 & 光猫 | 管理员重启 WAN6；光猫 `/var/appconf/dhcp6s.conf` 于 `06:28` 更新并下发新 PD **`2409:8a04:538a:ebb1::/64`**；路由器 `odhcpd` 发出 RA 废弃旧 `/64` 并广播新 `/64` |
| `07:12:06` | `.217` `NetworkManager` | `.217` 恰好到达 12 小时 T1 续租时间点，自然拿到新 `/128`（`ebb1::4db`），其 IPv6 节点于 `07:28` 恢复 |
| `08:03 ~ 08:05` | 排查实测 | 确认 `.233` 仍持有非废弃的旧 `/128`（剩余 `preferred_lft 27767s`），且默认选源命中旧 `/128`，被路由器策略路由以 ICMPv6 Code 5 拒包 |
| `08:17 ~ 08:23` | 变更与验收 | 落地路由器方案 1A + 方案 2B，刷新 `.233`/`.217` 网络连接清除历史遗留 `/128` 租约，两台主机全部恢复并验收通过 |

---

## 三、双重根因深度分析 (RCA)

### 根因 1（01:25 ~ 06:28 全网 IPv6 中断 5 小时）：双层路由 PD 失步 + `check_ipv6.sh` v1 检测盲区

1. **光猫侧不推送 PD 更新**：光猫为路由拨号模式，`ppp0` 重拨拿到新 `/60` 后，光猫 `radvd` 立刻在 `br0` 上通告新 WAN `/64`（触发路由器 `ifupdate of wan6`），但光猫 `dhcp6s` 不会向路由器发送 DHCPv6 Reconfigure，也不会提前废止此前委派的 48 小时 PD 租约（`172800s`）。
2. **旧版 `/usr/bin/check_ipv6.sh`（v1）存在 3 个盲区**：
   - 仅判断 `ifstatus wan6` 中 `ipv6-prefix` 是否为空及 `preferred <= 0`，而旧 PD 租约首选期剩余数十小时，导致脚本一直判为健康；
   - 仅扫描 `logread | tail -n 30` 寻找 `No Binding`，一方面 `odhcp6c` 在 T1（约 24 小时）前不发续租，另一方面 MT7981 无线驱动日志高频刷屏导致 30 行窗口极易失效；
   - 未比对 `wan6` 的实时 WAN SLAAC 前缀（`eth1` 已更新为 `538a:ebb0`）与委派给 LAN 的 PD 前缀（仍为 `5381:58a1`），也未做实际 LAN 出站 IPv6 探活。

### 根因 2（06:28 之后手机恢复但 `.233` 仍失败）：有状态 DHCPv6 僵尸 `/128` 租约 + RFC 6724 选源冲突

1. **有状态 DHCPv6 `/128` 无法被 RA 废弃**：
   - 路由器原配置 `dhcp.lan` 启用了 `dhcpv6='hybrid'`、`ra_flags='managed-config' 'other-config'`（`M=1`）与 `leasetime='12h'`。
   - `06:28:50` 路由器拿到新前缀并发出 RA 后，`.233` 的旧 SLAAC `/64` 被立刻标记为 `deprecated`（`preferred_lft 0`），并拿到了新 SLAAC `/64`（`2409:8a04:538a:ebb1:44da:ee46:178b:412c/64`）。
   - 但 `.233`（及 `.217`）运行 `NetworkManager`，其内置 DHCPv6 客户端向路由器通告 **`accept-reconf: false`**（见 `ubus call dhcp ipv6leases`），不支持 DHCPv6 Reconfigure；且 RA 无法废弃 DHCPv6 租来的 `/128` 地址。因此 `.233` 在 `03:46:20` 续租到的 `2409:8a04:5381:58a1::fb6/128` 仍保持非废弃状态长达约 7.7 小时。
2. **内核选源命中旧 `/128` 被路由器拒包**：
   - 根据 RFC 6724，旧 `/128` 与新 `/64` 均非 `deprecated` 且同属全局单播，Linux 默认选中了靠前的 `2409:8a04:5381:58a1::fb6`（`ip -6 route get <中转IPv6>` 实证）。
   - OpenWrt 路由器使用源地址策略路由（`default from 2409:8a04:538a:ebb1::/64 via fe80::1 dev eth1`），对旧前缀源地址直接回复 **ICMPv6 Type 1 Code 5（`Source address failed ingress/egress policy`）**。
   - **对比验证**：`.233` 直接 `ping -6 <中转IPv6>` 100% 收到路由器 Code 5 拒包；显式指定新 SLAAC 源地址 `ping -6 -I 2409:8a04:538a:ebb1:44da:ee46:178b:412c` 则 0% 丢包（56.3–58.3 ms）。
3. **与 2026-11-10（[REVIEW-2026-11-09.md](REVIEW-2026-11-09.md#L254-L316)）表现差异原因**：
   - 11-10 排查时旧前缀已失效超 26 小时，`.233` 12 小时旧 DHCPv6 租约早已自然过期，所以 `ifup wan6` 后直接走了新 SLAAC 地址；本次处于续租后 3 小时窗口期内，故暴露了有状态 DHCPv6 僵尸租约隐患。

---

## 四、已落地的根治方案（2026-11-25）

### 1. 方案 1A：路由器关闭 LAN 有状态 DHCPv6 地址分配，改纯 SLAAC + 无状态 DHCPv6

在路由器 `192.168.10.1` 修改 `/etc/config/dhcp` 的 `lan` 段并重启 `odhcpd`：

```sh
uci set dhcp.lan.ra='server'
uci set dhcp.lan.dhcpv6='server'
uci set dhcp.lan.dhcpv6_na='0'
uci set dhcp.lan.dhcpv6_pd='0'
uci set dhcp.lan.ra_management='0'
uci delete dhcp.lan.ra_flags
uci add_list dhcp.lan.ra_flags='other-config'
uci delete dhcp.lan.ndp
uci commit dhcp
/etc/init.d/odhcpd restart
```

* **效果**：RA 仅下发 `A=1, M=0, O=1` 及 RDNSS；无状态 DHCPv6 仍可为客户端提供 DNS 信息，但**彻底禁止下发有状态 `/128` 租约**（`ubus call dhcp ipv6leases` 保持为空）。今后前缀变更时，`odhcpd` 发送 RA 废弃旧 `/64`（`preferred_lft=0`），包括 `.233`、`.217`、手机在内的全网终端均可秒级切换新前缀源地址。
* **兼容性确认**：路由器 PassWall ACL 已于 2026-11-19 改为按 MAC 地址放行（见 [INCIDENT-REPORT-2026-11-19.md](INCIDENT-REPORT-2026-11-19.md#L54-L62)），不依赖固定 IPv6 地址。

### 2. 方案 2B：升级路由器 `/usr/bin/check_ipv6.sh` 至 v2 并增加 `wan6 ifupdate` 热插拔钩子

1. **升级 `/usr/bin/check_ipv6.sh`（v2）**：
   - **WAN/PD `/60` 前缀一致性校验**：内置纯 POSIX `awk` IPv6 展开函数 `ipv6_prefix60()`，实时比对 `eth1` 当前非废弃 SLAAC `/64` 与 `wan6` 委派 `ipv6-prefix` 的前 60 位。
   - **LAN IPv6 出站真实探活**：从 `br-lan` 当前全局 IPv6 源地址对 3 个经 `ipset test passwall_chnroute6` 实测确认**不被 PassWall `accept_icmpv6` 本地代答**的国内 IPv6 节点（`2400:3200::1`、`2400:3200:baba::1`、`2409:8088::a`）做 2 轮容错探测（正常时首包约 11 ms 即返回）。
   - **恢复后二次验证与熔断加固**：`ifup wan6` + `odhcpd reload` 后等待 2 秒，二次执行 `probe_lan_ipv6`；仅出站真实恢复才清零失败计数，否则累计至 `MAX_FAILS=3` 触发熔断，避免上游运营商 IPv6 骨干故障时反复重启 `wan6`/`passwall`；自动重试冷却时间调整为 `COOLDOWN=300`（5 分钟）。
   - **保留兼容接口**：保留 `--status`、`--force`、`--daily`、`--reset` 以及 30 分钟 cron 兜底，新增 `--event` 模式供热插拔触发。
2. **新增事件驱动钩子 `/etc/hotplug.d/iface/95-check-ipv6`**：
   ```sh
   #!/bin/sh
   [ "$INTERFACE" = "wan6" ] || exit 0
   [ "$ACTION" = "ifupdate" ] || exit 0
   (
       sleep 5
       /usr/bin/check_ipv6.sh --event
   ) >/dev/null 2>&1 &
   ```
   - 仅监听 `wan6` 的 `ifupdate` 事件（光猫换前缀时 `radvd` 1 秒内触发），后台延迟 5 秒后异步执行，不阻塞 `netifd`，也不会因 `ifup` 递归自触发，将前缀失步自愈时间从 5 小时压缩至数秒内。

### 3. 清理两台 Armbian 主机遗留的历史 `/128` 租约

在 `.233`（`Wired connection 1`）与 `.217`（`有线连接 1`）分别执行一次 `nmcli connection up` 刷新连接，释放方案 1A 落地前持有的旧 DHCPv6 `/128` 租约，进入纯 SLAAC + 无状态 DHCPv6 模式。

---

## 五、验收结果（2026-11-25 08:21 ~ 08:24）

| 检查项 | 验收结果 |
| :--- | :--- |
| 路由器 `dhcp.lan` 与 `odhcpd` 租约 | `dhcpv6_na='0'`、`ra_management='0'`、`ra_flags='other-config'`；`ubus call dhcp ipv6leases` 为空（0 条 `/128` 租约） |
| 路由器 `check_ipv6.sh --status` | `wan6 UP: true`；`WAN SLAAC /60 = 24098a04538aebb` 与 `LAN PD /60 = 24098a04538aebb` 一致；`LAN IPv6 Egress Probe: ok`；`Hotplug hook: yes`；`sh -n` 语法校验通过 |
| `.233` IPv6 地址与选源 | **无任何 `/128` 租约**，仅持有新 SLAAC `2409:8a04:538a:ebb1:44da:ee46:178b:412c/64`（+ ULA + link-local）；无状态 DHCPv6 正常提供 DNS `fdca:6736:ba8d::1`；`ip -6 route get` 正确选源新 SLAAC |
| `.233` 连通性与 IPv6 节点实测 | `ping -6 hknat` 3/3 0% 丢包（56.3 ms）；`curl -6 https://www.baidu.com` HTTP 200（0.50 s）；`12006`（wikih6）、`12008`（wikih gost）、`12009`（hknat）、`12010`（dmit6）全部返回 **HTTP 204** |
| `.217` IPv6 地址与选源 | **无任何 `/128` 租约**，仅持有新 SLAAC `2409:8a04:538a:ebb1:eab8:a095:32fa:ddf/64`（+ ULA + link-local）；无状态 DHCPv6 正常提供 DNS `fdca:6736:ba8d::1`；`ip -6 route get` 正确选源新 SLAAC |
| `.217` 连通性与 IPv6 节点实测 | `ping -6 hknat` 3/3 0% 丢包（51.0 ms）；`curl -6 https://www.baidu.com` HTTP 200；IPv6 中转端口 `12006/12007/12009/12010` 全部返回 **HTTP 204**（0.52–0.90 s） |

---

## 六、备份与回滚

所有变更仅涉及路由器 `192.168.10.1`（`.233` 与 `.217` 未修改任何持久化配置文件）：

| 改动项 | 备份路径（路由器 `192.168.10.1`） | 回滚命令 |
| :--- | :--- | :--- |
| LAN 关闭有状态 DHCPv6（方案 1A） | `/etc/config/dhcp.bak-20261125-0816` | `cp -a /etc/config/dhcp.bak-20261125-0816 /etc/config/dhcp && /etc/init.d/odhcpd restart` |
| `check_ipv6.sh` v2 与 `95-check-ipv6`（方案 2B） | `/usr/bin/check_ipv6.sh.bak-20261125-0816` | `rm -f /etc/hotplug.d/iface/95-check-ipv6 && cp -a /usr/bin/check_ipv6.sh.bak-20261125-0816 /usr/bin/check_ipv6.sh && chmod 755 /usr/bin/check_ipv6.sh` |

> **长期架构备注**：若后续将光猫 `192.168.11.1` 改为桥接模式由主路由直接拨号，方案 1A 依然是局域网 IPv6 最佳实践，方案 2B 因包含 `probe_lan_ipv6` 二次确认也不会在桥接模式下误触发。
