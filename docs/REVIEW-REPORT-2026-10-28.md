# ArmWall 项目评估报告

- 日期：2026-10-28
- 范围：`main.go` / `management.go` / `storage.go` / `strategy_runtime.go`、`web/`、全部 shell 脚本与 systemd 单元、CI、仓库状态
- 方式：只读静态审查，未修改任何文件
- 验证说明：本机未安装 Go 工具链，无法执行 `go build` / `go test` 复现；`armwall-linux-amd64 --version` 可正常执行（输出 `0.3.1`）。结论基于源码与脚本阅读，并与仓库内三份既有审计文档（`AUDIT-REPORT.md`、`CODEX-AUDIT-REPORT.md`、`IMPROVEMENT-PLAN.md`）交叉比对

---

## 一、项目概况

- 形态：Go 单体服务（`main.go` 3890 行 + `management.go` / `storage.go` / `strategy_runtime.go`）+ 原生 JS 单页前端（`web/`，约 2800 行）+ 一组 shell 运维脚本（install / gateway / update-core / naive-supervisor / uninstall）。
- 能力相当完整：多协议订阅解析、selector/urltest 策略组、nftables TProxy 透明网关、MAC ACL、DNS/FakeIP、规则集热更新、SQLite 持久化、配置导入导出、备份、多架构发布。
- 基础工程也不错：约 45 个单元测试、GitHub CI、release 产物带 SHA256SUMS、一键安装校验 checksum、systemd 单元、logrotate、README 比较诚实（明确写了明文 HTTP 和 IPv4-only）。
- 主要短板不在“功能”，而在三处：**请求/锁/重启模型**、**安全边界**、**工程结构与仓库卫生**。

总体评价：功能完成度约 80%、生产可靠性约 60%、安全性约 50%。测试与文档基础好于多数同类项目，最该优先处理的不是加功能，而是把**锁边界、超时、重启策略**和**凭据/传输/核心更新的信任链**收干净。

---

## 二、P0：建议优先处理

### 1. 明文 HTTP + 长期 Bearer Token + 全量凭据下发 = 一次嗅探直达 root

- 新装默认 `lan` 模式，监听 `0.0.0.0:8080` 且为明文 HTTP（`install.sh:68`，README 亦承认）。
- Token 存于浏览器 `localStorage` 永久保存（`web/app.js:3,45`），请求失败即 prompt 重新输入。
- `/api/state` 全量返回节点 UUID/密码、订阅 URL（`main.go:1866`），而 `/api/core/upload` 能把任意 ELF 以 root 执行（`management.go:244`）。
- 影响：同一 WiFi 内一次抓包或任一 XSS 等价于 root。
- 建议：默认 `local`（配 SSH 隧道）或内置 HTTPS（自签 + 启动打印指纹，或提供 nginx/caddy 反代示例）；token 改 `sessionStorage` / HttpOnly Cookie + CSRF；`/api/state` 字段脱敏，编辑时单独取凭据。

### 2. 核心更新没有并发保护，且下载无完整性校验

- `/api/core/update`、`/api/core/upload` 走 `handleUnlockedAPI`，不拿 `mu`，并发请求可直接并行（`main.go:2043,2059`）。
- `update-core.sh:37` 使用固定路径 `$BIN_DIR/$name.new`：并发更新互相覆盖同一临时文件，可能装坏 `/usr/local/bin/sing-box`。
- `latest_sing_box` / `latest_naive` 只校验 tar 可解压，不校验二进制哈希或签名（`update-core.sh:100-137`）。
- 建议：进程内 + flock 幂等锁；临时文件用 `mktemp`；用 GitHub API digest 或固定版本 + sha256；发布侧对 SHA256SUMS 签名（cosign/minisign）。

### 3. 30s 超时 + 全局锁 + 慢 I/O 三者互相打架

- `ReadTimeout/WriteTimeout = 30s`（`main.go:3775-3776`）：`/api/subscription/update`（3 次重试 × 20s）、`/api/rules/update`（32MB × 2 URL）、`/api/core/update`（下载核心）均可能超时，客户端收到截断响应而服务端继续执行，重试叠加副作用；128MB 核心上传在慢 WiFi 上会被 `ReadTimeout` 掐断。
- `api()` 先 `mu.Lock()` 再取 flock，然后**在锁内**做订阅下载（`main.go:2357-2364`、`2660`、`2726`），一次订阅刷新期间整个面板串行阻塞。
- 建议：临界区只保留 load-modify-save，网络 I/O 移出锁；flock 用 `LOCK_NB` + 有限重试并返回 503；长任务改异步 job + 状态轮询；按路由放宽超时（`http.ResponseController` 或独立 Server）。

---

## 三、P1：正确性与可靠性

| # | 问题 | 位置 | 影响 / 建议 |
|---|---|---|---|
| 4 | 任何保存都会重写 `sing-box.json` → `sing-box check` → 重启 sing-box → 重建 nft | `persistStore` 960-1001、`restartProxy` 2066-2087 | 改日志级别/开关节点即全量掉连接；Pi 上每次操作 1-3s；ACL 重载有短暂绕过窗口。建议加“配置哈希未变则跳过”并对重启做 1-2s 合并去抖 |
| 5 | 订阅刷新把该订阅节点整体挪到数组末尾，随后被 `normalizeStore` 重写成 `SortOrder=i` | 480-489 + 895-905 | 手动排序每次定时刷新被清掉；节点改名/端口轮换会换 ID，策略组成员与 disabled 状态静默丢失。建议拆出 override 表 |
| 6 | 规则集只检查 `len(body) >= 16` | `updateRule` 727-741 | CDN 返回 HTML 错误页（200 + 大 body）会被写成 `.srs`；重启失败回滚恢复 store 但**不回滚规则文件**。建议校验 SRS 魔数或 `sing-box rule-set` 解析 |
| 7 | `uninstall.sh` 不调用 `armwall-gateway disable` | `uninstall.sh:27-37` | nft 表与 `ip rule fwmark` 残留，卸载后 LAN 流量仍被 TProxy 到死端口，表现为“断网”直到重启 |
| 8 | `gateway.sh` 的 `detect()` 强制要求 `/dev/net/tun` | `gateway.sh:20` | TProxy 不需要 tun，无 tun 设备直接无法启用；`restore` 无重试，开机 DHCP 未就绪时一次失败即永久不恢复；规则用十几次独立 `nft` 命令逐条下发，非原子。建议 `nft -f` 整表原子下发 + `Restart=on-failure` |
| 9 | 透明网关只覆盖 IPv4 | `gateway.sh` 全文 | 客户端有原生 IPv6 时完全绕过代理（README 已声明，但安装期无检测/提示）。建议加 ip6 规则或安装时提示关闭客户端 IPv6 |
| 10 | 10 个端点重复实现，锁内那份永远不可达 | `main.go:2371/3100/3106/3285/3293/3430/3448/3490/3571/3587` | 约 250 行死代码；“哪些端点受锁保护”不可读；两套实现已出现行为差异 |
| 11 | mixed 入站固定 `0.0.0.0`、无认证 | `main.go:1722` | 局域网内任何人可当开放代理使用。建议默认 `127.0.0.1` + 显式开关，或给 socks 配 users |
| 12 | 凭据多处明文落盘 | `saveJSON` `storage.go:57-63`、`/api/config/export`、备份 JSON | 宿主机多一份明文凭据；备份可被 LAN 客户端以明文 HTTP 下载 |
| 13 | 端口冲突无校验 | `validateDNSSettings` / `/api/settings` | 代理端口设成 9090/11081/53/12000+ 时 `sing-box check` 不校验绑定，直到 restart 才失败回滚，错误为英文 systemd 输出 |
| 14 | `exec.Command` 全程无 `context`/超时 | `run()` 1826、`reloadGatewayIfActive` 1009、`restartProxy` 2068、`ping` 2018 | systemd/nft/curl 卡住会永久占住 `mu`；客户端断开时无法取消 |

补充细节：

- `ping -c 1 -W 3 <host>` 的 host 来自节点 `Server`，仅 TrimSpace（`main.go:1036`），以 `-` 开头的值会被当作 ping 参数（无 shell，危害有限但应校验）。
- `/api/node` 允许客户端自带 ID，不校验是否与已有节点/`direct`/`block`/策略组重名（2387-2392），重名到写配置时才 500。
- `authFailures` map 只增不减（2091-2151），长期运行 + 多 IP 无界增长；429 无 `Retry-After`。
- `restartProxy` 用 `LookPath("naive")` 决定是否重启 naive 服务（2067），装了二进制但服务被禁用时会让保存失败回滚。
- `Store.UpdateHours` 是死字段：`/api/subscription/schedule` 只改 systemd timer override（2886-2913），实际调度用每订阅 `UpdateHours`，两个“间隔”语义不一致。
- `/api/log/clear` 直接 `os.WriteFile(..., nil)` 截断（3315-3324），sing-box 日志 writer 持有偏移，后续可能写出稀疏空洞；应走 logrotate 或重启重开。
- `writeAtomicFile`/`writeConfig`/`writeNaiveConfigs` 只 `fsync` 文件、不 `fsync` 父目录，SD 卡掉电可能丢 rename。

---

## 四、P2：可维护性与性能

### 存储层

- 每次 `loadStore/save` 都 `sql.Open` + 建表 + 关库（`storage.go:26-44`）；`busy_timeout` 是每连接 PRAGMA，连接池换连接后可能失效——应改 DSN `_pragma` 并复用单例 `*sql.DB`。
- `saveDB` 每次 `DELETE` 全表再全量 INSERT（192-243）：10000 节点下改一个开关就要上万次写入，再叠加配置重写和重启。
- 没有 schema 版本管理（只有 `CREATE TABLE IF NOT EXISTS`），后续加列困难；建议 `PRAGMA user_version` 迁移。
- 遗留 JSON 镜像（`store.json`）已无作用，只剩第二份明文凭据与额外写入，可在一个发布周期后删除。

### 结构

- `main.go` 3890 行，`api()` 约 1370 行 switch（2351-3723），`config()` 用嵌套 `map[string]any` 拼装；约 20 个可变全局（路径、端口、命令路径）导致测试只能靠环境变量。
- 建议拆为 `internal/store`、`internal/configgen`、`internal/api`（按资源拆 handler + 路由表）、`internal/platform`（systemd/nft/exec）；用 `App`/`Config` struct 注入路径与命令，`exec` 换 `exec.CommandContext`。
- 没有 `context` 贯穿、没有优雅退出（`log.Fatal(server.Serve())`，3889）、没有结构化日志、请求 ID、`/healthz`、`/api/version`、`/metrics`。

### 前端

- 请求无超时/取消（`fetch` 裸调用），订阅或重启请求会挂到浏览器默认超时；429 未处理。
- 15s 轮询中每次 `systemctl is-active` 都 fork 进程，多标签页按倍数增长；建议缓存 1-2s 或统一 SSE。
- 表格全量 `innerHTML` 重绘（上万节点很慢），无虚拟滚动/分页。
- `/static/` 响应 `no-store` 但资源又带 `?v=20260726-5` 手工版本号，两者矛盾且易忘更新；无 favicon 导致每次 404。
- 缺少“本次修改是否需要重启代理”的提示，用户不易理解操作耗时来源。

### 仓库与供应链

- `.gitignore` 写了 `armwall-linux-*`，但 4 个约 10MB 二进制仍在索引中，`.git` 已 110MB（`git ls-files` 可复现）；且“源码通道”实际依赖这些入库二进制（`one-click-install.sh` source 分支直接取 `armwall-linux-$ARCH`）——要么明确保留并接受体积，要么去掉 source 通道改为现场 `go build`。
- 根目录 `armwall`（dev 版 amd64）是过期产物，`install.sh:26` 优先使用它；在 ARM 上误装会 exec format error，`install.sh` 无 ELF 架构校验。
- 三份审计文档未提交（`??`）；根目录 `armwall` / `armwall-install-files.tar.gz` / `SHA256SUMS` 属本地产物，建议文档移入 `docs/` 并提交，产物全部 gitignore。
- 缺 `LICENSE`（README 未声明协议）、CHANGELOG、SECURITY.md；`go.mod` 中 `modernc.org/sqlite 1.29.10`、`golang.org/x/sys 0.19.0` 明显落后，无 dependabot/renovate；CI 无 `gofmt`、staticcheck、`govulncheck`（`make test` 有 gofmt，但 push 触发的 `ci.yml` 没有）。

---

## 五、值得做的功能 / 体验优化

1. **订阅信息**：展示 `Subscription-Userinfo`（流量/到期）；请求加 `User-Agent`（很多机场按 UA 返回 403）；支持 Clash YAML 订阅。
2. **批量测速**：现在测 50 个节点要发 50 个请求；应支持批量并发测速与排序。
3. **节点覆盖层**：把“订阅源数据”和“用户改名/禁用/排序”分离成 override 表，订阅刷新不再丢用户修改（顺带修 P1-5）。
4. **规则集镜像**：`ruleURLs` 全为 raw.githubusercontent.com（`main.go:646`），被墙环境首装必失败；提供国内镜像或随包内置规则。
5. **配置 diff 与一键回滚**：应用前提示“本次变更会重启代理”，失败时整体回滚（含规则集文件）。
6. **只读角色 / 多 Token**：给只查看状态的用户一个只读 token。
7. **IPv6 网关**与**客户端 DNS 自动配置指引**（dnsmasq / AdGuardHome 示例）。
8. **可观测**：`/healthz`、`/api/version`（前端显示版本便于支持）、node_exporter textfile 指标（连接数、重连次数）。

---

## 六、与既有三份审计文档的关系

- 已落地：token fail-closed、`clash_api` secret、HTTP 超时与安全响应头、跨进程 flock、广告规则开关、备份数量上限、logrotate、CI、卸载脚本、`/api/subscription/clear` 误删手动节点、`clashDelay` 先判状态码、`fallback→urltest` 兼容。
- 仍未处理（本报告已复核）：二进制仍在索引、30s 超时回归、核心上传执行链未收紧、10 个不可达端点、`authFailures` 无界、flock 无超时、`persistStore` 回滚丢弃错误、MAC ACL 写在 rename 之后、`uninstall` 不清网关、`armwall.service` 沙箱最弱（root + 可写 `/etc` + 可执行外部脚本）、前端无超时、README 缺 sing-box 最低版本。
- 本报告新增发现：网关强制依赖 `/dev/net/tun`、nft 规则非原子、规则文件校验/回滚缺失、核心更新无并发锁、mixed 入站开放、订阅刷新打乱排序、节点身份随改名变化、端口冲突无校验、`Store.UpdateHours` 语义分裂、日志截断方式、目录未 fsync、`naive` 配置目录 env 与 Go 硬编码不一致（`naive-supervisor.sh:4` vs `main.go:515`）、naive 端口基数无上限检查。

---

## 七、建议实施顺序

### 第一阶段（安全与止血，1-2 天）

1. 核心更新加锁 + `mktemp` + 校验
2. 锁外做网络 I/O、flock 加超时
3. 删掉 10 个重复端点
4. `uninstall` 调 gateway disable
5. 网关去掉 tun 依赖、`nft -f` 原子化
6. 端口冲突与保留 ID 校验

### 第二阶段（可用性，3-5 天）

7. 配置哈希比对 + 重启去抖/合并
8. 订阅并行拉取、保留排序、UA/ETag
9. 规则集校验与失败回滚
10. `/api/state` 脱敏
11. 默认 local 或自带 TLS
12. 长任务路由放宽超时（配合 job 化）

### 第三阶段（结构与工程，1-2 周）

13. 拆包 + 依赖注入 + `context` + 优雅退出 + slog
14. 单例 DB + 增量写 + schema 迁移 + 删除 JSON 镜像
15. 前端超时 / 虚拟列表 / 轮询瘦身
16. CI 加 gofmt / staticcheck / govulncheck + dependabot
17. 仓库清理（二进制、审计文档入库、LICENSE/CHANGELOG）
18. 补 `gateway.sh` 与订阅排序的回归测试
