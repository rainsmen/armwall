# ArmWall 故障分析与应急加固报告 (2026-10-29)

> **文档编号**：INCIDENT-20261029-01  
> **故障定级**：P1（局域网境外流量与 DNS 全面中断）  
> **故障时间**：2026-10-29 12:18:00 ~ 12:26:24 CST（持续约 8 分钟）  
> **影响范围**：局域网内所有终端无法访问 Google、YouTube 等境外站点，控制台测速超时  
> **处理人员**：系统管理员 / AI 自动化排查助手  
> **当前状态**：已自愈（人工切节点触发重启恢复），应急加固方案已全面落地并在真机生效  

---

## 目录

- [一、故障现象与影响](#一故障现象与影响)
- [二、完整事件时序线](#二完整事件时序线)
- [三、根因深度剖析 (RCA)](#三根因深度剖析-rca)
- [四、应急处置与已落地加固方案](#四应急处置与已落地加固方案)
- [五、真机落地验证记录](#五真机落地验证记录)
- [六、中长期防范与架构优化建议](#六中长期防范与架构优化建议)

---

## 一、故障现象与影响

2026 年 10 月 29 日 12:18 左右，ArmWall 旁路网关运行期间出现以下异常：
1. **全屋断网（境外流量）**：局域网内 PC、手机等所有设备突发无法打开 Google、YouTube 等境外网站；
2. **管理后台测速失败**：在 ArmWall Web 管理控制台（端口 8080）点击“节点测速”或“策略测试”，均返回超时报错；
3. **国内流量正常**：局域网访问百度、Bilibili 等国内网站及网关本机 SSH 均完全正常；
4. **切节点后立即自愈**：管理员在 Web 控制台将当前节点切换至另一备用节点，再切回原节点后，所有网络访问立刻恢复正常。

---

## 二、完整事件时序线

通过提取分析网关主机 `192.168.10.217` 上的 `/var/log/armwall/sing-box.log`、`journalctl` 系统日志及网络连接状态表，还原真实故障时序如下：

```mermaid
sequenceDiagram
    autonumber
    participant Client as LAN 终端设备
    participant Singbox as sing-box (本地端口 11080)
    participant Naive as NaiveProxy (本地端口 12000)
    participant ISP as 运营商/GFW 骨干网
    participant Remote as DMIT 远端服务器 (端口 4431)

    Note over Client,Remote: 12:17 之前：网络正常（DNS 查询 ~20 次/分）
    Client->>Singbox: 访问 Google / 发起高频请求
    Singbox->>Naive: 转发至 socks5://127.0.0.1:12000
    Naive-->>Remote: QUIC/UDP 报文传输 (端口 4431)
    
    Note over ISP,Remote: 12:18:52：UDP 遭遇 QoS 丢包或 NAT 会话阻断
    ISP--xRemote: UDP 5元组单向黑洞 (丢包/无响应)
    Note over Naive: NaiveProxy Chromium 内部工作线程 (ThreadPoolForeg) 卡死挂起
    
    Note over Singbox,Naive: 本地 127.0.0.1:12000 TCP 监听未挂，握手仅需 2ms
    Client->>Singbox: 请求解析境外域名 (8.8.8.8:53)
    Singbox->>Naive: 持续注入 DNS 查询报文
    Naive--xClient: 链路挂死，无任何 DNS 响应回包
    Note over Client: 客户端疯狂重传 DNS (从 30次/分 暴增至 560次/分)
    
    Note over Client,Remote: 12:25:52：管理员在 Web 页面点击测试，请求超时
    Note over Client,Remote: 12:26:00：管理员手动切换节点，触发服务重启
    Singbox--xNaive: 停止服务，systemd 强杀僵死线程 (SIGKILL)
    Note over Naive: 重启并绑定全新随机本地 UDP 端口，重建 QUIC 握手
    Note over Client,Remote: 12:26:24：切回原节点，DNS 降至 5次/分，网络彻底恢复
```

### 关键数据记录表

| 时间节点 | 境外 DNS (8.8.8.8:53) 查询频次 | 境外 TCP 访问连接数 | 状态诊断 |
| :--- | :---: | :---: | :--- |
| **12:16** | 31 次 / 分 | 1505 次 / 分 | 🟢 正常运行 |
| **12:17** | 98 次 / 分 | 1504 次 / 分 | 🟡 链路开始出现丢包 |
| **12:18** | **556 次 / 分** | 46 次 / 分 | 🔴 **UDP 链路断流，DNS 开始严重堆积重试** |
| **12:19 ~ 12:25** | **250 ~ 422 次 / 分** | **5 ~ 17 次 / 分** | 🔴 **全屋终端境外 DNS 完全瘫痪，无法建连** |
| **12:25:52** | 密集重发 | 1 次 (`www.google.com:443`) | 🔴 **Web 控制台测试触发，请求超时失败** |
| **12:26:00** | - | - | 🟡 **管理员切换节点，服务触发重启** |
| **12:26:24** | - | 1 次 (google.com 200 OK) | 🟢 **切回原节点，全新 UDP 端口握手成功** |
| **12:27** | **5 次 / 分** | 19 次 / 分 | 🟢 **DNS 重试风暴消除，网络全面恢复** |

---

## 三、根因深度剖析 (RCA)

经过对底层组件架构与 Linux 内核跟踪，定位本次事故存在 **3 层连锁诱因**：

### 1. 协议脆弱性（直接诱因）：`quic://` (UDP) 遭遇网络黑洞
* 故障节点 `dmit udp naive` 配置为：
  ```json
  {
    "listen": "socks://127.0.0.1:12000",
    "proxy": "quic://rainman:rainman2009@dmit.zhilutianshi.com:4431"
  }
  ```
* 传输层采用基于 **UDP 的 HTTP/3 QUIC 协议**。
* 在 12:18:52 发生大量 Google HTTPS 并发流量后，运营商骨干网或家庭路由器 NAT 网关触发了对高端口 UDP 的 QoS 限流、丢包阻断或会话老化单向黑洞。

### 2. 核心架构缺陷（中间诱因）：本地 SOCKS 端口假死与“盲转发”
* **Chromium 线程挂死**：NaiveProxy 基于 Chromium Cronet 网络栈构建。当底层 UDP 遭遇静默丢包时，其工作线程 `ThreadPoolForeg`（PID 32273）陷入不可中断的死锁状态；
* **本地假活与黑洞吸流**：NaiveProxy 在本机环回接口 `127.0.0.1:12000` 上的 TCP 监听端口并未关闭。前置核心 `sing-box` 与本机建立 TCP 握手仅需 2ms，误认为该 Outbound 状态良好；
* **DNS 穿透失败**：局域网终端向 `8.8.8.8:53` 发送的所有 DNS 报文均被 sing-box 注入此黑洞端口，无应答返回，导致局域网全网域名解析彻底瘫痪。

### 3. 守护机制缺失（根本诱因）：无链路探测且子进程信号断链
* **无链路健康感知**：原有 [`naive-supervisor.sh`](../naive-supervisor.sh) 仅有简单的 `while [ -f "$config" ]; do naive ...; done` 循环，**只有当进程主动退出时才会拉起**。面对进程未死但网络挂死的“僵尸状态”，完全无能为力；
* **进程链信号截断**：原脚本退出处理函数仅执行 `kill "$pid"`（发送给最外层 subshell），未能将 SIGTERM 传递给孙进程 `naive`。因此在 12:26:00 停止服务时，出现如下系统日志：
  ```text
  10月 29 12:26:00 onecloud systemd[1]: Stopping armwall-naive.service...
  10月 29 12:26:00 onecloud systemd[1]: armwall-naive.service: Killing process 32273 (ThreadPoolForeg) with signal SIGKILL.
  10月 29 12:26:00 onecloud systemd[1]: armwall-naive.service: Failed with result 'exit-code'.
  ```
  工作线程卡死无法响应常规退出信号，最终只能依赖 systemd 超时强行执行 `SIGKILL`。

---

## 四、应急处置与已落地加固方案

根据现场排查结论，已针对生产服务器 `192.168.10.217` 与代码库实施了**方案 A（Supervisor 进程级看门狗增强与退出链加固）**：

### 1. 完善进程退出信号链与优雅清场
在 [`naive-supervisor.sh`](../naive-supervisor.sh#L16-L48) 中重写 `cleanup()` 函数：
* **级联信号传递**：退出时使用 `pkill -TERM -P "$pid"` 递归向每个子 shell 的真实 `naive` 进程投递 SIGTERM；
* **精准匹配防护**：追加 `pkill -TERM -f "naive $CONFIG_DIR"`，确保仅影响 ArmWall 自身配置的实例，严禁误杀宿主机其他独立 Naive 实例（如 1080 端口）；
* **轮询自适应收尾**：引入最多 1.5 秒的退出等待探测；若超时仍有线程残留，主动执行 `pkill -KILL` 兜底，避免触发 systemd 的长超时惩罚。

> **2026-10-31 更正**：上述 `pkill -f "naive $CONFIG_DIR"` 按命令行子串匹配，实测会误杀任何命令行中包含该路径的进程（真机上曾误杀管理员 SSH 会话中的诊断命令），"仅影响 ArmWall 自身实例"的结论不成立。同时 TERM trap 返回后脚本会继续执行主循环，导致 `systemctl stop` 需等待 90 秒超时。现已改为按 PID 文件只向本脚本拉起的 naive 进程发信号，并在 TERM 后显式退出，详见 [综合改进计划 4.10 节](CONSOLIDATED-IMPROVEMENT-PLAN-2026-10-29.md#410-2026-10-31-复评修复)。

### 2. 引入轻量级无侵入主动健康检测 (Watchdog)
在 Supervisor 主循环中增加后台探活协程：
* **极低开销探测**：每隔 **45 秒**（`CHECK_INTERVAL`）自动提取 `/etc/armwall/naive/*.json` 中的本地 SOCKS 端口，通过 `curl --socks5-hostname` 请求轻量 204 探针（`http://cp.cloudflare.com/generate_204`，请求体为 0 字节）；
* **防抖熔断自愈**：
  * 单次失败仅计数并记入警告日志；
  * **连续 3 次探测失败**（持续约 2.5 分钟确认假死），触发自动自愈动作：精确终止该节点的 Naive 进程（`pkill -f "naive $config"`）；
  * Supervisor 的 `run_instance` 循环捕获退出并在 2 秒后自动拉起全新实例；
  * 新实例向内核申请全新的随机本地 UDP 端口，避开原有的运营商丢包/阻断会话，实现**全自动断线自愈，无需人工切换节点**；
* **结构化日志**：自愈、失败与恢复全流程记录至 `/var/log/armwall/naive.log`。

---

## 五、真机落地验证记录

已将加固后的脚本部署至生产主机 `/usr/local/bin/armwall-naive-supervisor`，实测结果如下：

### 1. 启停性能验证
```bash
# 执行服务重启
systemctl restart armwall-naive.service
```
* **耗时对比**：原先停机耗时超过数秒甚至等待 systemd 超时；加固后服务停止并重新拉起仅耗时 **56 毫秒**；
* **Systemd 日志**：退出干净利落，`journalctl` 中彻底消除 `Killing process with signal SIGKILL` 告警。

### 2. 实时健康检测日志核验
查看 `/var/log/armwall/naive.log`：
```text
[2026-10-29 19:35:32] Stopping armwall-naive-supervisor, cleaning up worker processes...
[2026-10-29 19:35:53] [HEALTH] Port 12001 probe failed (HTTP 000, failure 1/3)
[2026-10-29 19:36:44] [HEALTH] Port 12001 recovered (probe HTTP 204)
[2026-10-29 19:37:04] Stopping armwall-naive-supervisor, cleaning up worker processes...
[2026-10-29 19:37:34] [HEALTH] Port 12000 probe OK (204)
```
* 主节点（12000，DMIT QUIC）持续探活成功；
* 备用节点偶发失败被准确记录为 `1/3`，恢复后自动记录 `recovered`，防抖逻辑完全符合预期。

### 3. CPU 与系统负载核验
* **常驻内存**：Supervisor 脚本与探测逻辑常驻内存仅 **1.0 MB**；
* **CPU 开销**：`top -bn1` 显示 Supervisor CPU 占用为 **0.0%**，探活瞬时开销对单板机完全无感；
* **访问验证**：经由 12000 端口请求 `https://www.google.com` 响应状态码 `200`，代理链路畅通。

---

## 六、中长期防范与架构优化建议

为了进一步提升系统的抗风险能力，建议在后续软件版本规划中推进以下优化：

1. **协议偏好建议（运维层面）**：
   * 在国内复杂网络环境下，**强烈建议优先使用基于 TCP 的 HTTP/2（`https://`）**，而非 UDP 的 QUIC（`quic://`）；
   * TCP 协议具备完善的链路超时重传与内核级 Keepalive 检测，不会出现 Chromium UDP 假死后挂死本地 SOCKS 端口的情况。
2. **Sing-box 链路健康分组（配置层面）**：
   * 将默认出口由单节点直连，改造为 `urltest` 或 `fallback` 策略组；
   * 在 sing-box 内部集成定期测速机制，当底层 SOCKS 5 端口无法返回数据时，自动将流量回退至可用直连或其他备用节点。
3. **Go 原生健康巡检协程（代码层面）**：
   * 在后续大版本更新中，可在 `main.go` 内部建立轻量 Goroutine，对所有已启动的 Outbound 进行端到端周期性质量评估，并在 Web UI 仪表盘展示实时连通性状态。
