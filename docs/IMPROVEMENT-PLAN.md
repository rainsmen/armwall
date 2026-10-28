# ArmWall 改进与优化清单

- **编制日期**：2026-07-30
- **基线提交**：`4d2f7be`（docs: add one-click installer）+ 工作区未提交修改（21 个文件，+1379 / −219）
- **参考材料**：`AUDIT-REPORT.md`（31 项）、`CODEX-AUDIT-REPORT.md`（S0×7 / S1×12 / S2×11）
- **性质**：只读复核，未修改任何源文件

## 验证状态说明

本机**未安装** Go 工具链（`go`、`gofmt` 均不可用）、**未安装** sing-box、**未安装** shellcheck。以下命令未能实际执行：

```
go build ./...   go vet ./...   go test ./...   go test -race ./...
gofmt -l *.go    staticcheck    govulncheck     sing-box check
shellcheck *.sh  make test      make release
```

Go 与 Shell 的全部结论来自静态阅读，未经编译器与测试验证。`node` 可用（v22.23.2）。

联网核查（WebFetch / WebSearch）全程返回 **429**，因此 sing-box 版本兼容性一项仍**无法核实**，与前次审计相同，见 P2-11。

已实测确认的项：`git ls-files` 二进制入库状态、`.git` 体积 72 MB、API 端点数、测试函数数、状态码风格统计、LICENSE 缺失。

---

## 一、整改进度核对

两份审核报告合计提出的问题，当前工作区状态如下。

### 1.1 已完成（21 项）

| 原编号 | 问题 | 落实位置 |
|---|---|---|
| A1 / C-S0-1 | Token 为空时无鉴权 | `main.go:2093` `validateAuthToken` fail-closed（最小 16 字符、禁换行）；`main.go:3713` 启动即校验；`armwall.service` 的 `ExecStartPre=--check-config` 且 `EnvironmentFile` 去掉了 `-` 前缀；默认监听改为 `127.0.0.1:8080` |
| A2 部分 / C-S0-7 部分 | 非常量时间比较、缓存与安全响应头 | `main.go:2107` SHA-256 + `subtle.ConstantTimeCompare`；`main.go:2084` `setSecurityHeaders` 覆盖 CSP / XCTO / XFO / Referrer-Policy / no-store；鉴权失败写审计日志 |
| A4 / C-S0-6 | 跨进程配置竞态 | `main.go:551` `lockStoreFile` 使用 `syscall.Flock`；CLI 与 Web 两条路径统一走 `withStoreFileLock`；`writeConfig` 改用 `os.CreateTemp` 生成唯一候选文件（`main.go:1771`） |
| A5 / C-S1-4 | `/api/subscription/clear` 误删手动节点 | `main.go:2547` 改用 `SubscriptionID == ""` 判定；`main_test.go:526` 有回归测试 |
| A6 / C-S1-2 | SQLite 非唯一真相源 | `main.go:838` `loadStore` 按文件存在性判断初始化，不再用 `ErrNoRows`；`loadDB` 显式返回错误并检查 `rows.Err()` 与 settings 反序列化错误；`main_test.go:373,391` 两个测试 |
| A8 / C-S1-6 | 广告规则强制启用 | `Store.AdBlockEnabled *bool` + API + UI 开关 + 旧配置默认迁移；`main_test.go:437,748` |
| A10 / C-S1-8 部分 | 备份无数量上限 | `management.go:177` `pruneConfigBackups(20)`；`update-core.sh:50` `prune_backups` 默认保留 3 份 |
| A11 | 无日志轮转 | 新增 `armwall.logrotate`（daily / 10M / rotate 7 / copytruncate），`install.sh:47` 安装到 `/etc/logrotate.d/` |
| A12 / C-S1-9 | clash_api 无 secret | `main.go:603` `ensureClashAPISecret` 生成 32 字节随机值写入 `0600` 文件；`strategy_runtime.go:28` 请求带 `Authorization: Bearer` |
| A15 / C-S2-1 部分 | `Decode` 错误被忽略 | `main.go:2168` `decodeJSONPayload` 统一处理：体积上限、`DisallowUnknownFields`、拒绝尾随内容；`main_test.go:500` |
| A16 / C-S0-7 部分 | HTTP Server 无超时 | `main.go:3611` 四个超时 + `MaxHeaderBytes` |
| A18 / C-S2-3 | 过滤视图下排序语义错误 | `web/app.js:934` 先在 `filteredNodes()` 中求相邻，再映射回全量列表交换 |
| A19 / C-S2-5 | `clashDelay` 先解码后判状态码 | `strategy_runtime.go:113` 顺序已对调；`main_test.go:161` |
| A21 / C-S2-4 部分 | 前端无自动刷新 | `web/app.js:796` 15 秒轮询，`document.hidden` 与当前视图判断 |
| A22 部分 | `nodeTests` 无上限、无 Token 重置、method 校验、charset | `web/app.js:146` 按现存节点清理；`web/app.js:1197` "清除 Token"；各端点补 method 校验；`text/plain; charset=utf-8` |
| A26 部分 / C-S2-9 部分 | 无卸载脚本 | 新增 `uninstall.sh`（含 `--purge`、二次确认） |
| A27 / C-S1-11 部分 | `update-core.sh` `sed` 解析脆弱 | 改用 `python3 -c` 解析 JSON（`update-core.sh:78,103`） |
| A28 / C-S1-10 | NaiveProxy 监督逻辑 | `naive-supervisor.sh:19` 逐实例 `run_instance` 循环重启；`armwall-naive.service` 改 `Restart=always` |
| A31 / C-S2-10 部分 | `go.mod` 依赖标注不实 | `modernc.org/sqlite` 已提升为直接依赖 |
| C-S0-3 | Go 工具链停止安全维护 | `go.mod` 与 CI 均升到 Go 1.26 |
| C-S0-5 部分 | 真实 sing-box 约束不一致 | `validateNode` 已强制 trojan / hysteria2 / anytls 必须 TLS（`main.go:1038-1062`）；ACL 单端口与端口范围已分离为 `port` / `port_range`（`main.go:1164` `splitPortMatches`） |

其他显著改善：README 补齐了端口清单、安全须知、Token 轮换、升级、卸载、日志与备份、IPv6 限制、故障排查；测试从 32 个增至 41 个，新增鉴权、SQLite 容错、广告开关、订阅清空等关键用例；`armwall-sing-box.service` 与 `armwall-naive.service` 加了 `ProtectSystem=strict` / `ReadOnlyPaths` / `ReadWritePaths` 沙箱；新增 `.github/workflows/ci.yml`（test / race / vet / shellcheck / sh -n / node --check）。

### 1.2 部分完成（7 项）

| 原编号 | 问题 | 已做 | 仍缺 |
|---|---|---|---|
| A3 / C-S1-1 | 全局锁包裹慢 I/O | `handleUnlockedAPI` 抽出 10 个端点到锁外 | `/api/subscription*`、`/api/rules/update` 仍在锁内；读端点仍受 flock 阻塞（见 P1-8、P1-9） |
| A7 / C-S1-5 | Fallback 语义不符 | UI 与 README 已移除该选项 | 代码仍静默降级且永久改写数据（见 P2-6） |
| A9 / C-S1-7 | 首次安装缺本地规则集 | `install.sh:76` 尝试预取；README 有故障排查 | 预取时机在 sing-box 启动之前，必走直连 GitHub；无校验、无 UI 状态、无镜像源（见 P2-4） |
| A23 / C-S0-4 | 二进制入库 | 已添加 `.gitignore` | **二进制仍在 git 索引中**（见 P0-1） |
| A24 / C-S0-4 | 一键安装无校验 | 新增可选 `ARMWALL_ARCHIVE_SHA256` + 未校验时告警 | 默认仍 `ARMWALL_REF=main`，未校验也继续执行（见 P2-8） |
| A25 / C-S2-7 | 无 CI | 已建 `ci.yml` | 缺 gofmt / staticcheck / govulncheck / 多架构构建 / sing-box 集成 / release 流水线（见 P2-9） |
| C-S1-3 | 持久化事务与回滚 | `save()` 的 JSON 失败降级为告警；`writeConfig` 候选文件唯一命名 | 订阅/规则路径无回滚；回滚错误全部丢弃；MAC ACL 写在 rename 之后（见 P1-4、P1-5、P1-6） |

### 1.3 未开始（11 项）

`A13` 死端点、`A14 / C-S2-1` 拆分 `api()`、`A17 / C-S2-6` 中文错误、`A20` finally 按钮、`A29` LICENSE、`A30` sing-box 版本要求、`C-S0-2` 核心上传信任链、`C-S1-12` 主服务沙箱、`C-S2-8` 高风险测试、`C-S2-10` 依赖维护、`C-S2-11` 状态码常量。

---

## 二、新发现问题（本次复核）

以下 **13 项**在两份既有报告中均未记录，其中 4 项是本轮整改引入的回归。

### P0-1 — `.gitignore` 已加但二进制**仍在 git 索引中**，整改实际未生效

```
$ git ls-files | grep armwall-linux
armwall-linux-amd64
armwall-linux-arm64
armwall-linux-armv6
armwall-linux-armv7
$ du -sh .git
72M	.git
```

`.gitignore` 对**已被跟踪**的文件无效。四个二进制（合计约 38 MB）仍在索引中，仍会随每次提交进入历史，`.git` 仍是 72 MB。`AUDIT #23` 与 `CODEX S0-4` 都把这一项列为发布阻断项，目前的状态是"看起来修了，实际没修"。

**动作**：`git rm --cached armwall-linux-*`，提交后二进制改由 GitHub Releases 分发。若要回收历史体积，需 `git filter-repo` 重写并强推（会改写全部提交哈希，需与协作者协调）。

---

### P0-2 — 新增的 `WriteTimeout: 30s` 会切断三类长任务，属整改引入的回归

**位置**：`main.go:3616`

```go
WriteTimeout: 30 * time.Second,
```

Go 的 `WriteTimeout` 从读完请求头起算到响应写完为止。以下端点的最坏耗时全部超过 30 秒：

| 端点 | 最坏耗时 | 依据 |
|---|---|---|
| `/api/subscription`（新增订阅） | **66 秒** | `fetchSubscription` 3 次重试 × 20s + 退避 2s + 4s（`main.go:352-371`） |
| `/api/subscription/update`、`/update-one` | 66 秒 × 订阅数（串行） | 同上，`updateSubscriptionsWithForceLocked` 逐个订阅循环 |
| `/api/rules/update` | **120 秒** | `updateRule` 最多 2 个 URL × `outboundHTTPClients` 返回的 2 个 client × 30s 超时（`main.go:703-733`、`main.go:656`） |
| `/api/core/update`（latest） | 分钟级 | 下载 30–40 MB sing-box 归档 |

**后果链**：连接在 30 秒被服务端关闭 → 前端 `fetch` 抛网络错误 → 后端 goroutine 仍持有 `mu` 与 flock 继续跑完 → 用户以为失败而重试 → 新请求阻塞在 flock 上 → 再次 30 秒超时。订阅更新、规则更新、核心更新这三项核心功能在真实（慢速/被墙）网络下**基本不可用**。

**动作**：长任务改为异步任务 + 任务 ID + 状态轮询（`CODEX S1-1` 已提出）；在此之前，至少把这几个端点的处理时长压到 `WriteTimeout` 以内（缩短重试次数与单次超时），或对这些路径使用 `http.ResponseController.SetWriteDeadline` 单独放宽。

---

### P0-3 — 核心上传的 root 执行链完全未收紧（`CODEX S0-2` 零进展）

**位置**：`management.go:244` `handleCoreUpload` → `update-core.sh:29` `install_binary`

当前校验：

1. `file "$src" | grep -q ELF` — 只证明是 ELF
2. `"$name.new" version` 能返回 0 — 只证明能启动
3. sing-box 额外要求 `check -c "$CONFIG"` 通过 — 只证明能解析现有配置

三项都**无法证明来源可信**。随后 `install -m 0755` 写入 `/usr/local/bin/`，`systemctl restart` 以 root 执行。既不记录哈希、来源、操作时间，也没有二次风险确认。

在 token 已泄露或管理面板被暴露的场景下，这是从"拿到 token"到"设备 root 持久化"的最短路径。

**动作**：优先只允许安装官方 Release 资产（校验 GitHub 附带的 checksum）；手工上传要求用户同时提交 SHA256 并显式确认风险；记录审计日志（哈希 / 来源 / 时间 / 客户端 IP）；长期把特权安装拆成窄接口 helper。

---

### P1-1 — `api()` 中有 10 个永不可达的重复分支

`handleUnlockedAPI`（`main.go:1854`）对下列路径全部 `return true`，而 `api()` 的加锁 switch 中**同名 case 仍完整保留**：

| 路径 | 无锁实现 | 死代码 |
|---|---|---|
| `/api/state` | `main.go:1856` | `main.go:2211` |
| `/api/strategy/status` | `main.go:1864` | `main.go:2940` |
| `/api/strategy/test` | `main.go:1876` | `main.go:2946` |
| `/api/service/status` | `main.go:1909` | `main.go:3125` |
| `/api/logs` | `main.go:1922` | `main.go:3133` |
| `/api/network/test` | `main.go:1949` | `main.go:3270` |
| `/api/gateway/status` | `main.go:1971` | `main.go:3288` |
| `/api/node/test` | `main.go:1974` | `main.go:3330` |
| `/api/core/update` | `main.go:2033` | `main.go:3411` |
| `/api/core/upload` | `main.go:2049` | `main.go:3427` |

约 200 行永远执行不到的代码。真实危害是**两份实现会漂移**：无锁版 `/api/service/status` 强制 `GET`，死代码版的约定不同；今后修改任一端点时改错位置不会有任何报错。

**动作**：删除加锁 switch 中这 10 个 case，并加一个测试断言两个 switch 的路径集合不相交。

---

### P1-2 — `authFailures` map 无界增长

**位置**：`main.go:2082`、`main.go:2126`

```go
var authFailures = map[string][]time.Time{}
```

`recordAuthFailure` 只裁剪**单个 client 的时间戳切片**，从不删除已过期的空条目。每个出现过的源 IP 永久占用一个 map key。局域网内伪造源地址扫描（或长期运行 + 大量客户端）会让该 map 单调增长。在 512 MB / 1 GB 内存的 Armbian 设备上这是可触及的风险。

**动作**：定期扫描清理空条目，或改用带 TTL 的 LRU（容量上限 + 淘汰）。

---

### P1-3 — 速率限制对暴力破解无实际抑制作用

**位置**：`main.go:2143` `authHandler`

```go
if !authorized(token, r.Header.Get("Authorization")) {
    limited := recordAuthFailure(r.RemoteAddr)
    ...
    if limited {
        http.Error(w, "too many authentication failures", http.StatusTooManyRequests)
        return
    }
    http.Error(w, "unauthorized", http.StatusUnauthorized)
```

触发阈值后**只是把 401 换成 429**：token 比较仍然每次完整执行，没有拒绝服务、没有退避延迟、没有锁定期。攻击者可以保持任意速率继续猜测，唯一变化是响应码。

同时前端只对 **401** 弹出 Token 输入框（`web/app.js:43`），返回 429 时用户看到的是一句英文 toast，无从判断发生了什么。

**动作**：`limited` 状态下在窗口内直接短路拒绝（不再比较 token）并引入指数退避；前端识别 429 并给出中文提示与倒计时。

---

### P1-4 — 订阅与规则更新路径没有事务回滚，与 `persistStore` 行为不一致

**位置**：`main.go:441` `updateSubscriptionsWithForceLocked`、`main.go:814` `applyScheduledRuleUpdatesLocked`

```go
if err := writeConfig(s); err != nil {
    return err
}
if err := save(s); err != nil {
    return err          // sing-box.json 已是新配置，数据库仍是旧的
}
if wasRunning {
    if err := restartProxyFn(); err != nil {
        return err      // 配置与数据库都已提交，进程可能起不来
    }
}
```

对比 `persistStore`（`main.go:950`）具备四级回滚，同一份代码里两条写路径的失败语义完全不同。`save` 失败会留下"配置文件已换、数据库未换"的不一致状态；下次 `loadStore` 会用旧数据重新生成配置，静默丢弃本次订阅更新。

**动作**：`CODEX S1-3` 已提出的"订阅和规则更新统一走同一事务接口"，让这两条路径复用 `persistStore`。

---

### P1-5 — `persistStore` 回滚链的错误全部丢弃且无日志

**位置**：`main.go:970`、`main.go:976-978`、`main.go:984-987`

```go
if err := restartProxyFn(); err != nil {
    proxyPort = previousProxyPort
    _ = save(previous)
    _ = writeConfig(previous)
    _ = restartProxyFn()
    return err
}
```

五处 `_ =` 全部丢弃错误。回滚本身失败时（例如磁盘满导致 `writeConfig(previous)` 失败），系统停留在"新配置写了一半、旧配置没写回、代理没起来"的未知状态，而返回给用户的只有最初那个错误，日志里没有任何线索。

`CODEX S1-3` 明确要求"回滚失败必须写入高优先级日志，不应忽略错误"，未落实。

**动作**：每个回滚步骤失败都 `log.Printf` 记录，并在最终错误信息中标注"自动回滚失败，配置可能不一致"。

---

### P1-6 — `writeConfig` 中 MAC ACL 写在 `os.Rename` 之后，可留下部分提交

**位置**：`main.go:1806-1812`

```go
if err := os.Rename(candidate, configPath); err != nil { return err }
candidate = ""
if err := writeAtomicFile(macACLPath, macData, 0640); err != nil {
    return fmt.Errorf("write MAC ACL bindings: %w", err)
}
```

`sing-box.json` 已经提交（含新的 per-MAC tproxy inbound 标签与端口），此时 `mac-acl.tsv` 写失败则仍是旧内容。随后 `reloadGatewayIfActive` 会按**旧绑定**生成 nft 规则，tproxy 目标端口与 sing-box 实际监听端口不匹配 → 该 MAC 对应的客户端直接断网，且错误信息只提到"写 MAC ACL 失败"，与断网现象没有明显关联。

**动作**：把 MAC ACL 候选文件与 sing-box 候选文件一起先落盘校验，最后统一 rename 提交。

---

### P1-7 — `uninstall.sh` 不清理透明网关，卸载后可能导致局域网断网

**位置**：`uninstall.sh:22-35`

```sh
systemctl disable --now ... armwall-gateway.service ... || true
rm -f /usr/local/bin/armwall-gateway ...
```

`armwall-gateway.service` 是 `Type=oneshot` + `RemainAfterExit=yes`，且**没有定义 `ExecStop=`**。`disable --now` 不会执行任何清理动作。结果是卸载完成后：

- nft 表 `inet armwall` 仍在，`prerouting` 链继续把 LAN 的 IPv4 TCP/UDP `tproxy ip to :11081`
- `ip rule fwmark 0x2333 table 233` 与 `ip route table 233` 的 `local 0.0.0.0/0 dev lo` 仍在
- `net.ipv4.ip_forward` 保持为 1（`gateway.sh:97` 的恢复逻辑只在 `disable` 子命令里）
- **清理工具 `/usr/local/bin/armwall-gateway` 已被删除**，用户失去恢复手段

sing-box 已停止，11081 无人监听，经该设备转发的客户端流量全部黑洞。这是卸载脚本可能造成的最严重后果。

**动作**：在删除任何文件之前执行 `/usr/local/bin/armwall-gateway disable || true`；同时给 `armwall-gateway.service` 补 `ExecStop=/usr/local/bin/armwall-gateway disable`。

---

### P1-8 — flock 无超时阻塞，与 HTTP 超时叠加产生 goroutine 堆积

**位置**：`main.go:560`

```go
if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
```

使用 `LOCK_EX` 而非 `LOCK_EX|LOCK_NB`，无超时。当 systemd timer 进程正在做一次 66 秒的订阅更新时，Web 端每一个写请求都会无限期阻塞在这里。配合 P0-2 的 `WriteTimeout: 30s`：客户端连接在 30 秒被切断，但服务端 goroutine 仍在等锁，并且仍会在拿到锁后完整执行一遍写操作（客户端已经看不到结果）。

用户在 UI 上重复点击会持续制造这样的"幽灵写入"。

**动作**：改为带超时的尝试加锁（`LOCK_NB` + 重试若干次），超时返回 `409 Conflict` 或 `503` 并附中文提示"另一项更新正在进行"；同时在 handler 中检查 `r.Context()` 是否已取消，避免执行已被放弃的请求。

---

### P1-9 — 读端点仍会被慢写任务阻塞，`CODEX S1-1` 的目标未达成

`handleUnlockedAPI` 的本意是让读操作绕开写锁，但 `/api/state`、`/api/strategy/status`、`/api/strategy/test`、`/api/node/test` 都调用 `loadAPIStoreSnapshot()`（`main.go:1841`），而它内部同样取 `lockStoreFile()` 的**排他锁**：

```go
func loadAPIStoreSnapshot() (Store, error) {
    unlock, err := lockStoreFile()   // 与写路径同一把 LOCK_EX
    ...
}
```

只要 timer 或任一慢写请求持锁，连"看一眼当前状态"都会挂起。`CODEX S1-1` 要求的"为读操作和状态查询提供不受慢写任务阻塞的路径"实际未实现，只是把慢 I/O 从**进程内 mutex** 移出，没有从**跨进程 flock** 移出。

**动作**：读路径改用共享锁（`LOCK_SH`）；或维护一份内存快照，写提交后原子替换，读端点直接读快照不加锁。

---

### P1-10 — `armwall.service` 是攻击面最大的进程，却是沙箱最弱的单元

对比三个常驻单元：

| 单元 | User | ProtectSystem | ReadWritePaths | 资源限制 |
|---|---|---|---|---|
| `armwall-sing-box.service` | root | `strict` | 已声明 | 无 |
| `armwall-naive.service` | root | `strict` | 已声明 | 无 |
| **`armwall.service`** | **root（默认）** | **无** | **无** | **无** |

`armwall.service` 是唯一监听网络端口、接受用户输入、执行 `systemctl` 与核心安装的进程，具备完整的 root 文件系统写权限。`CODEX S1-12` 的整改覆盖了两个下游单元，恰好漏掉了最需要加固的那个。

同时三个单元都没有 `MemoryMax` / `TasksMax` / `LimitNOFILE`，在嵌入式设备上缺少最后一道资源护栏。

**动作**：至少补 `ProtectSystem=full` + `ReadWritePaths=/etc/armwall /var/lib/armwall /var/log/armwall` + `ProtectKernelTunables` / `ProtectControlGroups` / `RestrictSUIDSGID` / `LockPersonality`，并加内存与进程数上限。长期按 `CODEX S1-12` 拆出低权限 Web 进程 + 特权 helper。

---

### P2-1 — 状态码风格混用较整改前更严重

实测统计：`http.Error(w, ..., <数字字面量>)` **114 处**，`http.Status*` 常量 **112 处**。新写的代码（`handleUnlockedAPI`、`decodeJSONPayload` 相关分支）用常量，旧分支用数字，同一个 `case` 内部经常两种混用：

```go
case "/api/node":
    if r.Method != "POST" {
        http.Error(w, "method", http.StatusMethodNotAllowed)   // 常量
        return
    }
    if decodeJSONBody(r, &n) != nil {
        http.Error(w, "invalid json", 400)                     // 字面量
```

`CODEX S2-11` 提到 staticcheck 报告约 50 处，现在是 114 处。

---

### P2-2 — 遗留 JSON 镜像已无作用，只剩多余的凭据落盘面

`save()`（`main.go:875`）仍向 `/var/lib/armwall/store.json` 写入完整 Store（含全部节点明文密码、UUID、订阅地址），但 `loadStore()`（`main.go:838`）**只在数据库文件不存在时**才读它。也就是说该镜像在正常运行中永远不会被读取，纯粹是一份多余的敏感数据副本（`0600`，但会被配置备份、`--purge` 之外的任何目录级操作带走）。

`CODEX S1-2` 要求"明确旧 JSON 迁移完成后的退役策略"，未落实。

**动作**：迁移完成后删除源文件并停止双写；或明确改名为一次性迁移文件。

---

### P2-3 — `ruleSet()` 与 `updateRule()` 硬编码路径，无法测试

**位置**：`main.go:644`、`main.go:727`

```go
path := "/var/lib/armwall/rules/" + tag + ".srs"
dir := "/var/lib/armwall/rules"
```

项目中其他所有路径（`dbPath`、`dataPath`、`configPath`、`macACLPath`、`logDir`、`backupDir`、`coreUploadDir`、`gatewayStatePath`）都是可覆写的包级变量，唯独规则集目录写死。后果是"本地规则集存在时用 local、不存在时用 remote"这条关键分支**无法被单元测试覆盖**，而它正是 `AUDIT #9` 首次安装死锁问题所在的位置。

---

### P2-4 — 首次安装的规则预取时机不对，被墙环境下必然直连 GitHub

`install.sh:76`：

```sh
systemctl start armwall-rule-update.service || true
```

该行位于 `systemctl restart armwall-sing-box.service`（第 83 行）**之前**。`armwall-rule-update.service` 虽然声明了 `After=armwall-sing-box.service`，但 `After` 只影响并发启动时的排序，手动 `start` 不会拉起未运行的依赖（没有 `Requires`/`Wants`）。

于是 `outboundHTTPClients`（`main.go:656`）探测 `127.0.0.1:11080` 失败，只能回落直连 `raw.githubusercontent.com` —— 正是目标部署环境最可能失败的路径。`|| true` 让失败静默，用户在 Web 界面上看不到任何规则集缺失提示。

**动作**：把预取移到 sing-box 启动之后；失败时在 UI 显式展示规则集状态与手动重试入口；或让 Release 携带经校验的 `.srs` 资产。

---

### P2-5 — 前端无请求超时与 429 处理

`web/app.js:31` 的 `request()` 直接 `await fetch(path, ...)`，无 `AbortController`、无超时。配合 P0-2，长任务请求会挂起 30 秒后抛出网络错误，期间按钮虽已禁用但用户无任何进度反馈。429 响应也没有专门处理（见 P1-3）。

---

### P2-6 — Fallback 兼容降级会静默改写用户数据

**位置**：`main.go:907`（`normalizeStore`）、`main.go:1086`（`validateStrategyGroup`）

```go
if group.Type == "fallback" {
    group.Type = "urltest"
}
```

UI 与 README 都已移除该选项，代码保留转换作为向后兼容——这个方向没问题。问题在于 `normalizeStore` 在**每次加载**时执行，转换结果随下一次 `save()` **永久写入数据库**。用户导入旧配置或旧备份时，策略组类型被无声改写，既没有 UI 提示也没有日志记录。

**动作**：转换时 `log.Printf` 记录，并在 `/api/config/import`、`/api/backups/restore` 的响应中返回被迁移的策略组列表，由前端提示用户。

---

### P2-7 — NaiveProxy 端口按顺序分配，增删节点会整体偏移

**位置**：`main.go:1375`

```go
port := naiveProxyPort + len(bindings)
```

端口由"第几个启用的 naive 节点"决定。禁用或删除中间某个 naive 节点，其后所有节点的本地 SOCKS 端口全部前移。由于 `writeNaiveConfigs` 与 sing-box 出站是同批重写的，稳态下自洽；但 naive 与 sing-box 是两个独立服务、重启不同步，切换窗口内会出现"sing-box 已指向新端口、naive 还监听旧端口"的错配。另外没有端口上限检查，`naiveProxyPort + N` 可无限增长并与其他服务冲突。

**动作**：端口按节点 ID 稳定哈希分配（冲突时线性探测）并持久化绑定关系；加上限校验。

---

### P2-8 — 一键安装仍不可复现

`one-click-install.sh:17` 默认 `ARMWALL_REF=main`；`ARMWALL_ARCHIVE_SHA256` 为空时只打印一行 stderr 警告然后**继续以 root 执行**下载来的 `install.sh`。README 建议生产环境固定 tag，但脚本默认值仍是最不安全的那个，而 `curl | sudo sh` 的用户几乎不会去改环境变量。

**动作**：默认改为最新 release tag；未提供校验和时默认拒绝，需显式 `ARMWALL_ALLOW_UNVERIFIED=1` 才继续。

---

### P2-9 — CI 覆盖不足，无 release 流水线

现有 `ci.yml` 有 `go test` / `go test -race` / `go vet` / shellcheck / `sh -n` / `node --check`。缺：

| 缺口 | 说明 |
|---|---|
| `gofmt -l` | `Makefile:11` 有，但 CI 没有调用 `make test`，格式回归不会被拦 |
| staticcheck | `CODEX S2-7` 要求，未加 |
| `govulncheck` | `CODEX S0-3` 要求"加入发布门禁"，未加 |
| 四架构交叉编译 | `make release` 从未在 CI 跑过，ARMv6/ARMv7 构建失败只能在发版时才发现 |
| sing-box 真实配置校验 | `CODEX S0-5` 的核心要求；上次审计正是靠这一步发现了 TLS 与 ACL 端口两个真实缺陷 |
| release workflow | 无 `release.yml`，`SHA256SUMS` 仍需人工 `make checksums`，无 SBOM、无构建元数据 |

---

### P2-10 — 依赖已落后两年，无自动化维护

```
modernc.org/sqlite v1.29.10     (2024-04)
golang.org/x/sys v0.19.0        (2024-03)
modernc.org/libc v1.49.3        (2024-04)
```

仓库无 `.github/dependabot.yml`，也无 Renovate 配置。`CODEX S2-10` 提出的"分批升级 + 迁移测试 + 每次升级跑完整测试与漏洞扫描"未落实。

---

### P2-11 — README 仍未写 sing-box 最低版本要求（`AUDIT #30` 唯一残留项）

README 只写了"已用 `sing-box 1.13.15` 验证过配置生成"，没有给出**最低支持版本**。代码同时使用了新旧两套 schema：

| 新特性 | 位置 |
|---|---|
| `action: hijack-dns` | `main.go:1650,1653` |
| DNS 规则 `action: route` | `main.go:1731` |
| `default_domain_resolver` | `main.go:1745` |
| 新式 DNS server 格式（`type` + `server`） | `main.go:1311` `dnsServerConfig` |

| 旧 schema | 位置 |
|---|---|
| legacy `block` 出站类型 | `main.go:1473` |
| route rule 的 legacy `outbound` 字段 | `main.go:1660` 等 |

用户手工上传较旧核心时会直接卡在 `sing-box check` 失败上，而错误信息只有 sing-box 原文。

> **本次仍无法核实**：`block` 出站与 route rule `outbound` 字段在 sing-box 1.13 的确切废弃/移除状态——WebFetch 与 WebSearch 全程返回 429。建议作者对照上游 `https://sing-box.sagernet.org/migration/` 自查后写入 README，并在 CI 中固定最低版本与最新版本两条校验。

---

### P2-12 — `gateway.sh` 的三处细节

| 项 | 位置 | 说明 |
|---|---|---|
| reload 期间存在流量泄漏窗口 | `gateway.sh:43-44` | `nft delete table` 与重建之间，LAN 流量不经 tproxy 直接转发 |
| `nft.backup` 备份了但从不使用 | `gateway.sh:70` vs `gateway.sh:95` | `disable()` 只删自己的表，备份文件永远不会被恢复，也不会被清理 |
| `ip-forward.before` 不清理 | `gateway.sh:97-100` | `disable()` 读取后不删除，下次 enable 时若 `STATE_FILE` 已存在则不会刷新，可能记录过时的值 |

---

### P2-13 — 前端与文案的零散项

| 项 | 位置 |
|---|---|
| 静态资源版本号 `?v=20260726-5` 仍手工维护 | `web/index.html:8,760` |
| UI 硬编码端口文案（11081、`:8080`） | `web/index.html:96,640` |
| token 仍长期存于 `localStorage`（`CODEX S2-4` 建议支持会话级） | `web/app.js:3,45` |
| `handleAction` 的 `finally` 无条件启用按钮 | `web/app.js:1203` |
| 后端英文错误直接 toast 到中文界面（`AUDIT #17` / `CODEX S2-6`） | `web/app.js:1201` |
| 15 秒轮询在低性能 ARM 上会持续 `exec systemctl` + 请求 clash API | `web/app.js:796` |

---

## 三、完整改进清单（按优先级）

### P0 — 发布前必须处理（3 项）

- [ ] **P0-1** `git rm --cached armwall-linux-*` 把二进制移出索引；二进制改由 GitHub Releases 分发；评估是否需要 `git filter-repo` 回收 72 MB 历史
- [ ] **P0-2** 解决 `WriteTimeout: 30s` 与长任务的冲突：订阅 / 规则 / 核心更新改为异步任务 + 状态轮询，或对这些路径单独放宽写截止时间
- [ ] **P0-3** 收紧核心上传信任链：优先只装官方 Release 资产并校验 checksum；手工上传要求提交 SHA256 + 显式风险确认 + 审计日志

### P1 — 近期处理（12 项）

- [ ] **P1-1** 删除 `api()` 中 10 个被 `handleUnlockedAPI` 覆盖的不可达 case，加路径集合不相交的测试
- [ ] **P1-2** `authFailures` 加过期条目清理或改用带 TTL 的 LRU
- [ ] **P1-3** 速率限制触发后短路拒绝 + 指数退避；前端识别 429 并中文提示
- [ ] **P1-4** 订阅与规则更新复用 `persistStore` 的事务与回滚
- [ ] **P1-5** `persistStore` 回滚链每步失败都记录高优先级日志，错误信息标注"自动回滚失败"
- [ ] **P1-6** MAC ACL 与 sing-box 候选文件一起校验后统一提交
- [ ] **P1-7** `uninstall.sh` 删文件前先 `armwall-gateway disable`；给 `armwall-gateway.service` 补 `ExecStop=`
- [ ] **P1-8** flock 改为带超时的尝试加锁，超时返回 409/503 中文提示；handler 检查 `r.Context()` 取消
- [ ] **P1-9** 读路径改共享锁或内存快照，与写路径解耦
- [ ] **P1-10** `armwall.service` 补 `ProtectSystem` / `ReadWritePaths` / 内核与 SUID 保护；三个单元统一加 `MemoryMax` / `TasksMax` / `LimitNOFILE`
- [ ] **P1-11** 补高风险测试（`CODEX S2-8`）：跨进程 flock 并发与丢失更新、真实 `sing-box check` 集成、`downloadResource` / `fetchSubscription` 重试与降级、`handleCoreUpload` 拒绝路径、数据库事务失败注入
- [ ] **P1-12** 补 Shell 脚本行为测试（bats 或 fixture 驱动 dry-run）：`gateway.sh` 的 nft 规则生成、`update-core.sh` 的回滚与备份修剪、`uninstall.sh` 的清理完整性

### P2 — 规划处理（22 项）

**代码质量**

- [ ] **P2-1** 统一使用 `http.Status*` 常量（当前 114 处字面量）
- [ ] **P2-2** 退役 `store.json` 遗留镜像，迁移后停止双写并删除源文件
- [ ] **P2-3** 规则集目录改为可覆写变量，补 local/remote 切换测试
- [ ] **P2-4** 拆分 `api()`（当前约 1370 行 / 64 个 case），按 node / subscription / routing / acl / management / gateway 分文件
- [ ] **P2-5** 清理死端点 `/api/dns`、`/api/mode`、`/api/subscription/schedule`
- [ ] **P2-6** 后端返回结构化错误 `{code, message, details}`，前端按错误码显示中文；不直接透传 systemctl / sing-box 原始输出
- [ ] **P2-7** NaiveProxy 端口改稳定哈希分配 + 持久化 + 上限校验

**运维可靠性**

- [ ] **P2-8** 规则预取移到 sing-box 启动之后；失败在 UI 显式展示并提供手动重试 / 镜像源 / 手工上传
- [ ] **P2-9** Fallback 迁移改为记录日志 + 导入/恢复响应中返回被改写的策略组
- [ ] **P2-10** `gateway.sh`：缩小 reload 泄漏窗口（原子替换规则集）；清理或启用 `nft.backup`；`disable` 后删除 `ip-forward.before`
- [ ] **P2-11** `update-core.sh` 校验 Release 资产哈希、支持固定版本、处理 GitHub API 限速

**发布与供应链**

- [ ] **P2-12** `one-click-install.sh` 默认指向 release tag；未提供校验和时默认拒绝
- [ ] **P2-13** CI 补 `gofmt -l`（或直接调用 `make test`）
- [ ] **P2-14** CI 补 staticcheck 与 `govulncheck`
- [ ] **P2-15** CI 补四架构交叉编译验证
- [ ] **P2-16** CI 补真实 sing-box 配置校验（最低支持版本 + 最新稳定版两条矩阵）
- [ ] **P2-17** 新增 release workflow：干净 tag 构建、`SHA256SUMS`、SBOM、构建元数据
- [ ] **P2-18** 添加 `.github/dependabot.yml` 或 Renovate；分批升级 `modernc.org/sqlite` 等落后依赖

**文档**

- [ ] **P2-19** 添加 LICENSE（`AUDIT #29`，仍缺失）
- [ ] **P2-20** README 写明 sing-box **最低支持版本**与已验证版本；先对照上游迁移文档自查 `block` 出站与 route rule `outbound` 的废弃状态

**前端**

- [ ] **P2-21** `request()` 加 `AbortController` 超时与进度反馈；处理 429
- [ ] **P2-22** 静态资源版本号由构建注入；端口文案从后端状态生成；支持会话级 Token；`finally` 改为仅恢复本次禁用的按钮

---

## 四、建议实施顺序

### 第一阶段：让当前整改真正生效

P0-1（二进制出库）→ P0-2（长任务超时回归）→ P1-1（删死代码）→ P1-7（卸载清网关）

前两项是"整改宣称完成但实际未生效"和"整改引入新回归"，优先级高于任何新功能。P1-1 与 P1-7 改动小、收益直接。

### 第二阶段：并发与事务正确性

P1-8 → P1-9 → P1-4 → P1-5 → P1-6

这五项互相关联，建议一并设计：确定"锁的边界在哪、事务提交顺序是什么、失败如何回滚与记录"，再统一改造两条写路径。

### 第三阶段：安全边界

P0-3（核心上传）→ P1-2、P1-3（鉴权加固）→ P1-10（systemd 沙箱）

### 第四阶段：可验证性

P1-11、P1-12（测试）→ P2-13～P2-17（CI 与 release 门禁）

在没有 CI 跑 `gofmt` / staticcheck / govulncheck / 四架构构建 / 真实 sing-box 校验之前，前三个阶段的改动都缺少回归防护。

### 第五阶段：可维护性与体验

P2-4（拆分 `api()`）→ P2-5、P2-6 → 其余 P2 项

---

## 五、总体评价

相对两份审核报告，本轮整改的完成度是**实质性的**：31 + 30 项中已完成 21 项、部分完成 7 项。四个 P0 里有三个（鉴权 fail-closed、跨进程锁、HTTP 超时与安全头）解决得干净且带测试；SQLite 单一真相源、广告规则开关、clash secret、日志轮转、备份保留、`validateNode` 的 TLS 约束、ACL 端口分离、前端排序与自动刷新都是到位的修复。README 与 CI 从无到有，测试从 32 增至 41。

仍需正视的是三类问题：

1. **两项 S0 被标记完成但实际未生效**：`.gitignore` 没有配合 `git rm --cached`，二进制仍在索引；核心上传信任链完全没动。
2. **整改本身引入了回归**：`WriteTimeout: 30s` 让订阅、规则、核心更新三大功能在慢网络下不可用；`handleUnlockedAPI` 留下 10 个不可达分支；flock 无超时与 HTTP 超时叠加会产生幽灵写入。
3. **事务一致性只做了一半**：跨进程锁有了，但两条写路径的失败语义仍不统一，回滚错误仍被静默丢弃。

按上述顺序推进第一、二阶段后，项目具备作为局域网内部工具部署的条件；完成第三、四阶段后，才适合作为公开发布包分发。

---

## 附录：问题索引

| 编号 | 级别 | 标题 | 主要位置 | 来源 |
|---|---|---|---|---|
| P0-1 | P0 | 二进制仍在 git 索引，`.gitignore` 未生效 | 仓库根 | 本次（A23 / C-S0-4 未完成） |
| P0-2 | P0 | `WriteTimeout: 30s` 切断三类长任务 | `main.go:3616` | 本次（整改回归） |
| P0-3 | P0 | 核心上传 root 执行链未收紧 | `management.go:244`, `update-core.sh:29` | C-S0-2 未开始 |
| P1-1 | P1 | 10 个不可达的重复 API 分支 | `main.go:2211` 等 | 本次（整改回归） |
| P1-2 | P1 | `authFailures` map 无界增长 | `main.go:2082` | 本次 |
| P1-3 | P1 | 速率限制无实际抑制作用 | `main.go:2143` | 本次 |
| P1-4 | P1 | 订阅/规则更新无事务回滚 | `main.go:441,814` | C-S1-3 部分 |
| P1-5 | P1 | 回滚链错误全部丢弃且无日志 | `main.go:970-987` | C-S1-3 未完成 |
| P1-6 | P1 | MAC ACL 写在 rename 之后 | `main.go:1806` | 本次 |
| P1-7 | P1 | 卸载不清理透明网关 | `uninstall.sh:22` | 本次 |
| P1-8 | P1 | flock 无超时，与 HTTP 超时叠加 | `main.go:560` | 本次 |
| P1-9 | P1 | 读端点仍被慢写任务阻塞 | `main.go:1841` | C-S1-1 未达成 |
| P1-10 | P1 | 主服务沙箱最弱 | `armwall.service` | C-S1-12 部分 |
| P1-11 | P1 | 高风险路径测试缺口 | `main_test.go` | C-S2-8 |
| P1-12 | P1 | Shell 脚本无行为测试 | `*.sh` | A 第八节 / C-S2-8 |
| P2-1 | P2 | 状态码风格混用（114 处字面量） | `main.go` | C-S2-11 |
| P2-2 | P2 | 遗留 JSON 镜像已无作用 | `main.go:875` | C-S1-2 未完成 |
| P2-3 | P2 | 规则集目录硬编码，无法测试 | `main.go:644,727` | 本次 |
| P2-4 | P2 | `api()` 约 1370 行 / 64 个 case | `main.go:2191` | A14 / C-S2-1 |
| P2-5 | P2 | 三个死端点仍在 | `main.go:2726,2850,3047` | A13 / C-S2-2 |
| P2-6 | P2 | 英文错误透传中文 UI | `main.go`, `app.js:1201` | A17 / C-S2-6 |
| P2-7 | P2 | NaiveProxy 端口顺序分配会偏移 | `main.go:1375` | 本次 |
| P2-8 | P2 | 规则预取时机在 sing-box 启动前 | `install.sh:76` | A9 部分 |
| P2-9 | P2 | Fallback 降级静默改写数据 | `main.go:907,1086` | A7 部分 |
| P2-10 | P2 | `gateway.sh` 泄漏窗口与备份未用 | `gateway.sh:43,70,97` | 本次 |
| P2-11 | P2 | `update-core.sh` 无资产校验/固定版本/限速处理 | `update-core.sh:74,94` | C-S1-11 部分 |
| P2-12 | P2 | 一键安装默认 `main` 且校验可跳过 | `one-click-install.sh:17,42` | A24 部分 |
| P2-13～17 | P2 | CI 五项缺口 + 无 release 流水线 | `.github/workflows/ci.yml` | A25 / C-S2-7 部分 |
| P2-18 | P2 | 依赖落后两年，无自动化维护 | `go.mod` | C-S2-10 |
| P2-19 | P2 | 无 LICENSE | 仓库根 | A29 未开始 |
| P2-20 | P2 | README 缺 sing-box 最低版本要求 | `README.md:29` | A30 残留 |
| P2-21～22 | P2 | 前端超时/429/版本号/端口文案/Token 存储 | `web/app.js`, `web/index.html` | A22 / C-S2-4 部分 |

**合计**：37 项（P0 × 3，P1 × 12，P2 × 22），其中本次新发现 13 项。
