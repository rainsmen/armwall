# ArmWall 代码与文档审核报告

- **审核日期**：2026-07-30
- **审核提交**：`4d2f7be`（docs: add one-click installer）
- **分支**：`main`
- **审核范围**：全部源码（Go 6118 行、前端 2795 行、Shell 5 个、systemd 单元 8 个）、README、构建与部署配置
- **审核性质**：只读审计，未修改任何源文件

## 验证状态说明

本机未安装 Go 工具链（`go`、`gofmt` 均不可用），因此以下命令**未能实际执行**：

- `go vet ./...`
- `go test ./...`
- `gofmt -l .`
- `make build` / `make release`

Go 侧的全部结论来自静态阅读，未经编译器与测试验证。`node --version` 可用（v22.23.2），Shell 与 JavaScript 逻辑按语义人工核对。

已实测验证的项：`update-core.sh` 的 GitHub API `sed` 解析（实际返回 `1.13.15`，解析成功，**未**列为缺陷）。

无法验证的项已在正文中明确标注（见问题 30 关于 sing-box `block` 出站的说明）。

---

## 一、概况

| 项目 | 值 |
|---|---|
| 后端 | Go 1.22 |
| | `main.go` 3019 行 |
| | `management.go` 278 行 |
| | `storage.go` 229 行 |
| | `strategy_runtime.go` 108 行 |
| 前端 | 原生 JS，无框架 |
| | `web/app.js` 1237 行 |
| | `web/index.html` 760 行 |
| | `web/styles.css` 798 行 |
| | 通过 `embed.FS` 内嵌进二进制 |
| 测试 | `main_test.go` 784 行，21 个测试函数 |
| 部署 | `install.sh`、`one-click-install.sh`、`gateway.sh`、`update-core.sh`、`naive-supervisor.sh` |
| | 4 个 service 单元 + 2 个 timer 单元 |
| 依赖 | 纯 Go SQLite（`modernc.org/sqlite`），`CGO_ENABLED=0` 静态构建 |
| 支持架构 | ARMv6 / ARMv7 / ARM64 / AMD64 |
| 提交数 | 29 |
| `.git` 体积 | 72 MB |

## 二、值得肯定的设计

以下不是客套，是审计中确认的实质优点：

| 项 | 位置 |
|---|---|
| 配置落盘用临时文件 + `rename` 原子替换 | `main.go:1206` `writeAtomicFile` |
| 应用前用 `sing-box check` 校验候选配置，失败即拒绝 | `main.go:1525-1532` |
| `persistStore` 具备完整失败回滚链（配置、存储、服务、网关四级） | `main.go:773-811` |
| 订阅刷新用内容哈希复用节点身份，保留用户的启停状态 | `main.go:385-417` `reconcileSubscriptionNodes` |
| 网络接口名在 Go 与 Shell 两侧独立做白名单校验 | `main.go:2902` `safeIface` / `gateway.sh:12` `safe_iface` |
| 备份文件名白名单校验 + `filepath.Base` 防路径遍历，且有对应测试 | `management.go:176-196` / `main_test.go:59` |
| 上传有双层大小限制（`MaxBytesReader` + `LimitReader`） | `management.go:235,265` |
| 前端所有动态插值统一走 `escapeHTML`，未发现 XSS 面 | `web/app.js:57` |
| 部分订阅源失败不影响其他源，且有对应测试 | `main.go:427-491` / `main_test.go:479` |
| 核心二进制更新失败自动回滚上一版本 | `update-core.sh:48-58` |

---

## 三、严重问题（P0）

### 问题 1 — `ARMWALL_TOKEN` 为空时 API 完全无鉴权，构成远程 root 代码执行链

**位置**：`main.go:2997-3003`

```go
http.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
    if token := os.Getenv("ARMWALL_TOKEN"); token != "" && r.Header.Get("Authorization") != "Bearer "+token {
        http.Error(w, "unauthorized", 401)
        return
    }
    api(w, r)
})
```

`token != ""` 是短路条件，环境变量缺失时**整段鉴权被跳过**，所有 API 无条件放行。

配套配置放大了后果：

- `armwall.service` 设置 `Environment=ARMWALL_LISTEN=0.0.0.0:8080` — 监听全部网卡
- `armwall.service` 使用 `EnvironmentFile=-/etc/armwall/armwall.env` — 前缀 `-` 表示文件不存在也照常启动，不报错

**完整攻击链**：

1. `armwall.env` 被误删、权限错误，或用户手工部署时遗漏
2. 服务静默启动，监听 `0.0.0.0:8080`，零鉴权
3. 局域网任意主机 `POST /api/core/upload`（`main.go:2765` → `management.go:230`）
4. 上传任意 ELF 文件（校验仅为 `file | grep ELF` 与能响应 `version` 子命令，`update-core.sh:31,41`）
5. `install -m 0755` 写入 `/usr/local/bin/sing-box`（`update-core.sh:38,46`）
6. `systemctl restart armwall-sing-box.service` 以 `User=root` 执行恶意二进制

同一无鉴权状态下，`GET /api/state`（`main.go:1599`）直接返回全部节点密码、UUID 与订阅地址。

**建议**：token 为空时 `log.Fatal` 拒绝启动，或强制回落 `127.0.0.1` 并在日志中显著告警；`install.sh` 增加 env 文件存在性与非空的启动前检查。

---

### 问题 2 — Token 传输与比较的三个弱点

| 弱点 | 位置 | 说明 |
|---|---|---|
| 明文 HTTP | `main.go:3018` | 无 TLS 支持，Bearer token 与节点密码在局域网明文传输 |
| 非常量时间比较 | `main.go:2998` | 使用 `!=` 比较，建议改 `crypto/subtle.ConstantTimeCompare` |
| 无速率限制 | `main.go:2997` | 无失败计数、无锁定、无延迟。128 位 token 暴力破解不现实，但配合鉴权日志缺失，无法察觉扫描行为 |

**附带的响应头缺口**：

- `/api/state` 返回含明文密码的 JSON，但 `api()` 只设置 `Content-Type`（`main.go:1594`），未设 `Cache-Control: no-store`，响应可能被浏览器或中间层缓存
- `page()`（`main.go:2913`）未设置 `X-Content-Type-Options`、`X-Frame-Options`、`Content-Security-Policy`

---

### 问题 3 — 全局互斥锁包裹慢网络 I/O，整个管理面板串行阻塞

**位置**：`main.go:1595-1596`

```go
mu.Lock()
defer mu.Unlock()
```

一把全局锁覆盖 `api()` 的**所有** 53 个分支，其中包含长耗时网络操作：

| 端点 | 最坏耗时 | 位置 |
|---|---|---|
| `/api/subscription` | 3 次重试 × 20s + 2s + 4s ≈ **66 秒** | `main.go:346-365` |
| `/api/rules/update` | 每规则 30 秒 | `main.go:587` |
| `/api/core/update`（latest） | 下载 30–40 MB 核心，分钟级 | `main.go:2749` |
| `/api/node/test?method=urltest` | 12 秒 | `strategy_runtime.go:85` |
| `/api/network/test` | 10 秒 | `main.go:2620` |

期间连 `/api/state`、`/api/service/status` 都会挂起，UI 表现为整站冻结。前端 `loadStrategyStatus()` 在每次 `renderRouting` 时都发一次请求（`web/app.js:287`），加剧排队。

**建议**：锁只保护 `load()` → 修改 → `persistStore()` 的临界区，网络 I/O 移到锁外；长任务改为异步任务 + 状态轮询。

---

### 问题 4 — 定时任务与 Web 进程之间无跨进程锁，存在配置覆盖竞态

`--update-subscriptions` 与 `--update-rules`（`main.go:2982-2996`）由 systemd timer 以**独立进程**运行，而 `sync.Mutex` 只在进程内有效。

**竞态 A：读-改-写丢失更新**

1. 定时任务 `load()` 取得配置快照
2. 用户在 Web UI 修改模式 / DNS / ACL 并写库
3. 定时任务用步骤 1 的旧快照 `save(s)`，覆盖用户的修改

`saveDB` 是 `DELETE FROM` + 全表重插（`storage.go:172-211`），整份配置一起被覆盖，不是字段级合并，因此丢失范围是全部设置而非单个字段。

**竞态 B：候选配置文件互相踩踏**

`writeConfig` 使用固定名 `configPath + ".candidate"`（`main.go:1521`），两个进程同时生成会交叉污染。值得注意的是相邻的 `writeAtomicFile` 正确使用了 `os.CreateTemp` 生成唯一名（`main.go:1211`）——同一份代码里存在两种不一致的做法。

**建议**：在 `/var/lib/armwall/` 下加 `flock` 文件锁，Web 与 CLI 两条路径都获取；或让 timer 改为调用本机 API 而非启动独立进程。

---

## 四、功能性缺陷（P1）

### 问题 5 — `/api/subscription/clear` 会误删手动导入的节点

**位置**：`main.go:1925`

```go
if n.SubscriptionID == "" && !strings.HasPrefix(n.ID, "sub-") {
    kept = append(kept, n)
}
```

判据是"ID 不以 `sub-` 开头"。但"导入分享链接"功能走 `parseSubscription`，其生成的 ID 正是 `fmt.Sprintf("sub-%d", ...)`（`main.go:176`、`241`、`296`），且 `SubscriptionID` 被显式清空（`main.go:2737`）。

**后果**：清空订阅会连带删除用户手工导入的所有节点。

该端点目前无 UI 入口，但 API 已暴露且可直接调用。建议改用 `SubscriptionID` 归属判断，不要依赖 ID 前缀。

---

### 问题 6 — `load()` 用 `ErrNoRows` 判空，导致 SQLite 不是唯一真相源

**位置**：`storage.go:155-157`、`main.go:694-704`

```go
// storage.go
if len(s.Nodes) == 0 && len(s.Subscriptions) == 0 {
    return s, sql.ErrNoRows
}
```

节点和订阅同时为空（全新安装，或用户删除了所有节点）就被当作"数据库无数据"。`load()` 随即**丢弃已从 `settings` 表成功读出的**模式、DNS、ACL、策略组、代理端口、日志级别，改从 JSON 文件重建。

目前靠 `save()` 双写 JSON 兜住（`storage.go:705-710`），数据不必然丢失，但代价是：

- SQLite 与 JSON 两份真相源，存在不一致风险
- 每次 `load()` 在空库状态下都触发一次多余的 `saveDB` 写入
- JSON 一旦缺失或写失败，所有设置回落默认值 `Store{Mode: "bypass_cn"}`
- README 宣称"SQLite 持久化"，与实际的双写实现不符

**建议**：改用 schema 版本键或 `settings` 表行数判断初始化状态。

---

### 问题 7 — Fallback 策略组被静默降级为 URLTest

**位置**：`main.go:1351-1354`

```go
if groupType == "fallback" {
    // sing-box implements health-based failover through URLTest.
    groupType = "urltest"
}
```

UI 仍提供独立的"Fallback 健康优先"选项（`web/index.html:498`），README 也并列宣称"Selector、URLTest、Fallback 策略组"。

用户选择 Fallback 后实际得到 URLTest 语义（最低延迟优先），而非 fallback 语义（主节点健康就一直用主节点），且无任何提示。

**建议**：要么实现真正的 fallback，要么从 UI 与 README 中移除该选项。

---

### 问题 8 — 广告拦截规则强制启用，无法关闭

**位置**：`main.go:1439`

```go
rules = append(rules, map[string]any{"ip_is_private": true, "outbound": "direct"},
    map[string]any{"rule_set": []string{"geosite-ads"}, "outbound": "block"})
```

无条件注入，`Store` 结构中也没有对应开关字段。规则误杀正常站点时，用户无从关闭。

---

### 问题 9 — 首次安装缺本地规则集，被墙环境下 sing-box 需自行访问 GitHub

**位置**：`main.go:512-518`

```go
func ruleSet(tag string) map[string]any {
    path := "/var/lib/armwall/rules/" + tag + ".srs"
    if _, err := os.Stat(path); err == nil {
        return map[string]any{"type": "local", ...}
    }
    return map[string]any{"type": "remote", ..., "url": ruleURLs[tag], "download_detour": "direct"}
}
```

`install.sh` 未预下载任何 `.srs` 文件。首次运行时 4 个规则集全部走 `remote` + `download_detour: direct`，即直连 `raw.githubusercontent.com` —— 正是目标部署环境最可能失败的路径。

拉取失败会导致规则为空或 sing-box 启动异常，形成"必须先能翻墙才能配好翻墙"的启动死锁。

**建议**：`install.sh` 尽力预取规则集；或首次启动时经代理拉取，失败时给出明确提示与手动上传入口。

---

### 问题 10 — 两处备份目录均无数量上限，嵌入式设备易被写满

| 备份类型 | 位置 | 触发时机 | 单份大小 |
|---|---|---|---|
| 配置备份 | `management.go:159` `createConfigBackup` | 每次导入（`main.go:2795`）、每次恢复（`main.go:2869`）、手动创建 | KB 级 |
| 核心二进制备份 | `update-core.sh:34-37` | 每次核心更新 | sing-box 约 30–40 MB |

两者均无清理逻辑，只增不减。在典型 8–16 GB eMMC / TF 卡的 Armbian 设备上这是现实风险。

**建议**：保留最近 N 份（配置建议 20 份，二进制建议 2 份）。

---

### 问题 11 — 无日志轮转

`sing-box.log` 存在**两个写入者**：

- sing-box 自身（`main.go:1483` 的 `log.output` 指向该文件）
- systemd（`armwall-sing-box.service` 的 `StandardOutput=append:` / `StandardError=append:` 也指向该文件）

既无 logrotate 配置，也无大小上限。`trace` / `debug` 级别下增长很快。`/api/log/clear` 是唯一的手动清理手段。

`naive.log`（`naive-supervisor.sh:4`）连查看入口都没有，只能 SSH 上机查看。

---

### 问题 12 — clash_api 无 secret

**位置**：`main.go:1483`

```go
"experimental": map[string]any{
    "clash_api": map[string]any{"external_controller": "127.0.0.1:9090"},
}
```

本机 9090 端口无任何认证。本机任何用户、任何容器进程都可切换出站、枚举活动连接、读取节点列表。

**建议**：生成随机 `secret` 并由后端持有（`strategy_runtime.go` 调用时附带）。

---

### 问题 13 — 四个死代码端点

| 端点 | 位置 | 状况 |
|---|---|---|
| `/api/dns` | `main.go:2217` | 功能已被 `/api/routing` 的 `dns` 字段完全覆盖 |
| `/api/mode` | `main.go:2414` | 功能已被 `/api/routing` 的 `mode` 字段完全覆盖 |
| `/api/subscription/schedule` | `main.go:2093` | 无 UI 入口；每订阅已有独立 `update_hours`，此端点还会写 systemd drop-in 文件 |
| `/api/subscription/clear` | `main.go:1918` | 无 UI 入口，且带问题 5 的缺陷 |

四者仍是完整的攻击面与维护负担。

---

## 五、健壮性与代码质量（P2）

### 问题 14 — `api()` 单函数 1300 行

**位置**：`main.go:1593-2901`

53 个 `case` 的巨型 switch。方法校验、请求体解码、字段校验、持久化、响应编码在每个分支重复实现，是问题 15 这类不一致的直接来源。

**建议**：抽出公共中间件（方法校验 + 解码 + 统一错误响应），按资源拆分 handler。`main.go` 3019 行也应按领域拆文件（node / subscription / routing / acl / gateway）。

---

### 问题 15 — 大量 `Decode` 错误被忽略

**位置**：`main.go:1632`、`1695`、`1723`、`1845`、`2041`、`2075`、`2420`、`2535`、`2554` 等

```go
json.NewDecoder(r.Body).Decode(&v)   // 返回值直接丢弃
```

畸形请求体退化为零值语义，返回的错误信息误导用户（例如报 `"node not found"`，实际是 JSON 解析失败）。同文件其他分支正确检查了返回值，风格不统一。

---

### 问题 16 — HTTP Server 无超时

**位置**：`main.go:3018`

```go
log.Fatal(http.ListenAndServe(addr, nil))
```

未设置 `ReadTimeout` / `WriteTimeout` / `IdleTimeout`。Slowloris 类连接可长期占用资源，配合问题 3 的全局锁影响放大。

---

### 问题 17 — 后端错误信息全英文，直接透传到中文 UI

后端错误如 `"node not found"`、`"unsupported node type"`（`main.go:844`）、`"strategy requires at least one node"`（`main.go:892`）由 `toast(error.message, true)`（`web/app.js:1163`）原样展示。

整站界面为中文，错误提示为英文，体验断裂。

---

### 问题 18 — 过滤视图下"上移/下移"语义错误

**位置**：`web/app.js:904-911`

```js
const ids = appState.nodes.map((node) => node.id);   // 全量列表
const from = ids.indexOf(id);
const to = from + Number(direction);
```

索引基于全量 `appState.nodes` 计算，而表格显示的是 `filteredNodes()` 的结果（`web/app.js:185`）。在搜索或筛选状态下点"上移"，节点会与一个屏幕上看不见的节点交换位置，用户看到的是"点了没反应"。

---

### 问题 19 — `clashDelay` 先解码 body 再判状态码

**位置**：`strategy_runtime.go:95-100`

```go
if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
    return 0, fmt.Errorf("invalid urltest response")
}
if resp.StatusCode < 200 || resp.StatusCode >= 300 {
    return 0, fmt.Errorf("urltest failed: %d", resp.StatusCode)
}
```

非 2xx 且响应非 JSON 时返回 `"invalid urltest response"`，真实错误（如 404 表示 proxy tag 不存在）被吞掉。两步顺序应对调。

---

### 问题 20 — `handleAction` 的 `finally` 无条件启用按钮

**位置**：`web/app.js:1164-1166`

```js
} finally {
    if (button) button.disabled = false;
}
```

会把本应保持禁用的按钮一并启用，长任务期间可被重复点击。

---

### 问题 21 — 前端无自动刷新

`loadState()` 仅在页面加载时调用一次（`web/app.js:1237`）。服务状态、策略组延迟、日志内容都需用户手动操作才更新。

---

### 问题 22 — 次要项

| 项 | 位置 |
|---|---|
| `nodeTests` Map 无上限累积 | `web/app.js:5` |
| token 存于 `localStorage`，一旦出现 XSS 即失窃 | `web/app.js:3` |
| `window.prompt` 取 token，输错后无重置入口，之后每次请求都弹窗 | `web/app.js:43` |
| 静态资源版本号 `?v=20260726-5` 手工维护，应由构建注入 | `web/index.html:8,758` |
| UI 文案硬编码端口 11081 与 8080 | `web/index.html:93,638` |
| `/api/logs`、`/api/state` 等端点无 HTTP method 校验，GET/POST 均可 | `main.go:1599,2497` |
| `/api/service/status` 前端用 POST，后端未校验 method，接口约定不一致 | `web/app.js:767` / `main.go:2489` |
| `run()` 设置 `text/plain` 未带 charset | `main.go:1553` |

---

## 六、部署与供应链（P1）

### 问题 23 — 4 个预编译二进制入库，`.git` 膨胀至 72 MB，且无 `.gitignore`

```
armwall-linux-amd64  9.6M
armwall-linux-arm64  9.2M
armwall-linux-armv6  9.3M
armwall-linux-armv7  9.3M
```

`git log` 显示这批二进制已提交 **5 轮**（`54474b1`、`1d2c232`、`9829bb7` 等），每轮约 38 MB 进入历史，永久不可回收（除非 rewrite history）。

仓库**无 `.gitignore`**，`make build` 产出的 `armwall` 也随时可能被误提交。

**建议**：添加 `.gitignore`；二进制改由 GitHub Releases 分发；`one-click-install.sh` 改为下载 release 资产而非源码归档。

---

### 问题 24 — `curl | sudo sh` 无完整性校验，且不可复现

**位置**：`README.md:41`、`one-click-install.sh:16-34`

```bash
curl -fsSL https://raw.githubusercontent.com/rainsmen/armwall/main/one-click-install.sh | sudo sh
```

| 问题 | 位置 |
|---|---|
| 默认 `ARMWALL_REF=main`，拉主分支当前状态，无版本固定，不可复现 | `one-click-install.sh:17` |
| 下载的 tar.gz 无 SHA256 校验、无签名 | `one-click-install.sh:31-34` |
| 随后以 root 执行归档内的 `install.sh` | `one-click-install.sh:41` |
| `Makefile` 的 `release` 目标不生成 `SHA256SUMS` | `Makefile:15-19` |

任何对仓库或传输链的干扰都直接获得目标设备的 root 权限。

**建议**：默认指向 release tag 而非 `main`；发布 `SHA256SUMS`（理想情况加 GPG 签名）；安装脚本校验通过后再执行。

---

### 问题 25 — 无 CI，Makefile 缺质量门禁

无 `.github/workflows/` 目录。

`Makefile:10-13` 的 `test` 目标仅包含：

```makefile
test:
	$(GO) test ./...
	node --check web/app.js
	sh -n gateway.sh install.sh one-click-install.sh update-core.sh naive-supervisor.sh
```

缺失：`go vet`、`gofmt -l`、`clean` 目标、多架构构建验证。四种架构的交叉编译目前完全依赖人工执行 `make release`。

---

### 问题 26 — 无卸载脚本

`install.sh` 安装 9 个文件、6 个 systemd 单元、4 个数据目录，并会修改 `net.ipv4.ip_forward` 与 nftables 规则，但没有对应的 `uninstall.sh`，README 也未给出手动清理步骤。

---

### 问题 27 — `update-core.sh` 的 JSON 解析脆弱 + GitHub 限速

**位置**：`update-core.sh:63,82`

```bash
version=$(sed -n 's/.*"tag_name": "v\([^"]*\)".*/\1/p' "$tmp/release.json" | head -1)
```

**实测当前可用**（返回 `1.13.15`），依赖 GitHub 当前的缩进输出格式。风险点：

- 格式一旦转为紧凑 JSON（无空格）即完全失效
- `.*` 贪婪匹配在单行 JSON 场景会取最后一个匹配项
- 未认证的 GitHub API 请求限速 60 次/小时/IP，多设备同 NAT 出口易触发

**建议**：改用 `jq`（若可接受依赖）或更严格的正则。

---

### 问题 28 — `naive-supervisor.sh` 容错偏弱

**位置**：`naive-supervisor.sh:22-28`

```sh
for config in "$CONFIG_DIR"/*.json; do
  naive "$config" >> "$LOG_FILE" 2>&1 &
  PIDS="$PIDS $!"
done
wait
```

`wait` 返回后脚本退出，`trap cleanup EXIT` 会 kill 全部子进程。任一 naive 实例正常退出（码 0）将导致所有实例被连带杀掉，而 `Restart=on-failure` 对零退出码不重启 —— 多 naive 节点场景下会静默失去全部 naive 出站。

**建议**：改 `Restart=always`，或改为逐进程监控与独立重启。

---

## 七、文档问题

### 问题 29 — 无 LICENSE 文件

仓库无任何许可声明。默认情况下他人无权复制、修改或分发。对一个通过 `curl | sh` 公开分发的项目，这是应优先补齐的一项。

---

### 问题 30 — README 缺口

| 缺失内容 | 为什么重要 |
|---|---|
| **sing-box 最低版本要求** | 代码混用新旧 schema：新式 DNS server 格式（`type: https` + `server`，`main.go:1074`）、`action: hijack-dns`（`main.go:1414`）、`default_domain_resolver`（`main.go:1499`）需较新版本；同时仍注入 `block` 类型出站（`main.go:1236`）与 legacy `outbound` 路由字段（`main.go:1424`）。测试注释明确提到"sing-box 1.13 does not support source_mac_address"（`main_test.go:702`），说明代码存在具体版本假设，但 README 一字未提。用户手动上传旧核心会直接卡在 `sing-box check` 失败上。<br>**注：`block` 出站在 sing-box 1.13 的确切状态本次审计无法联网核实（WebFetch/WebSearch 均返回 429），建议作者对照上游 deprecated 文档自查并写入 README。** |
| **卸载步骤** | 见问题 26 |
| **端口清单** | 8080 / 11080 / 11081 / 9090 / 12000+ 分散在代码与 UI 文案中，无集中说明 |
| **安全须知** | Web 面板为明文 HTTP；token 存于 `/etc/armwall/armwall.env`；如何轮换 token；为何不应暴露到公网 |
| **运维提示** | 日志与备份会持续增长（问题 10、11），需人工关注 |
| **故障排查** | 首次安装规则集拉取失败（问题 9）几乎必然遇到，无对应指引 |
| **升级流程** | 重跑 `install.sh` 是否安全、token 是否保留（代码上保留，文档未说明） |

---

### 问题 31 — `go.mod` 依赖标注不实

**位置**：`go.mod:6-19`

全部 15 个依赖标为 `// indirect`，但 `modernc.org/sqlite` 是 `storage.go:12` 的直接导入。执行一次 `go mod tidy` 即可修正。

---

## 八、测试覆盖缺口

现有 21 个测试覆盖了协议解析、sing-box 配置生成、SQLite 往返、订阅 reconcile、规则调度、备份生命周期——核心逻辑覆盖扎实。缺口集中在高风险路径：

| 缺口 | 关联问题 |
|---|---|
| **鉴权中间件零覆盖**（token 为空 / 错误 / 缺失头部） | 问题 1 正是靠这类测试能拦住的 |
| **并发与跨进程锁行为零覆盖** | 问题 3、4 无回归防护 |
| `/api/subscription/clear` 无测试 | 问题 5 因此未被发现 |
| `validateACLRule` 负例未测（非法端口范围、非法 MAC、空来源） | — |
| `updateRule` 降级路径未测（主地址失败→备用、下载超限、内容过短） | — |
| `handleCoreUpload` 拒绝路径未测（超限、空文件、非法 core 名） | — |
| **Shell 脚本只有 `sh -n` 语法检查**，`gateway.sh` 的 nft 规则生成、`install.sh` 的架构选择、`update-core.sh` 的回滚均无行为测试 | 可用 bats 或 fixture 驱动的 dry-run 覆盖 |
| **前端只有 `node --check`**，无单元测试 | — |

---

## 九、建议处理顺序

### 立即处理（安全边界）

| # | 问题 | 动作 |
|---|---|---|
| 1 | 问题 1 | token 缺失时拒绝启动，或强制回落 localhost 并告警 |
| 2 | 问题 2 | 常量时间比较、`Cache-Control: no-store`、安全响应头；规划 TLS |
| 3 | 问题 29 | 补 LICENSE |
| 4 | 问题 23 | 补 `.gitignore`，二进制迁出仓库 |

### 近期处理（正确性与可用性）

| # | 问题 | 动作 |
|---|---|---|
| 5 | 问题 3 | 缩小锁粒度，网络 I/O 移出临界区 |
| 6 | 问题 4 | 跨进程 `flock` + 候选文件唯一命名 |
| 7 | 问题 5 | 改用 `SubscriptionID` 归属判断，不依赖 ID 前缀 |
| 8 | 问题 10、11 | 备份数量上限 + logrotate 配置 |
| 9 | 问题 9 | 安装期预取规则集，失败时给明确提示 |
| 10 | 问题 24 | release 固定 tag + 发布 SHA256SUMS |
| 11 | 问题 30 | README 补 sing-box 版本要求、卸载、端口清单、安全须知 |

### 规划处理（质量与可维护性）

| # | 问题 | 动作 |
|---|---|---|
| 12 | 问题 14 | 拆分 `main.go` 与 `api()`，抽公共中间件 |
| 13 | 问题 25 | 建 CI（`vet` + `gofmt` + 多架构构建 + `test`） |
| 14 | 问题 6 | 统一为 SQLite 单一真相源 |
| 15 | 问题 7、8、13 | 对齐承诺与实现，清理死端点 |
| 16 | 第八节 | 优先补鉴权与并发测试 |
| 17 | 问题 15–22、26–28、31 | 逐项清理 |

---

## 附录：问题索引

| 编号 | 等级 | 标题 | 主要位置 |
|---|---|---|---|
| 1 | P0 | `ARMWALL_TOKEN` 为空时无鉴权，构成远程 root RCE 链 | `main.go:2997` |
| 2 | P0 | Token 明文传输 / 非常量时间比较 / 无速率限制 | `main.go:2998,3018` |
| 3 | P0 | 全局锁包裹慢 I/O，管理面板串行阻塞 | `main.go:1595` |
| 4 | P0 | 定时任务与 Web 进程无跨进程锁，配置覆盖竞态 | `main.go:2982`, `storage.go:172` |
| 5 | P1 | `/api/subscription/clear` 误删手动导入节点 | `main.go:1925` |
| 6 | P1 | `load()` 用 `ErrNoRows` 判空，SQLite 非唯一真相源 | `storage.go:155` |
| 7 | P1 | Fallback 策略组静默降级为 URLTest | `main.go:1351` |
| 8 | P1 | 广告拦截规则强制启用，无开关 | `main.go:1439` |
| 9 | P1 | 首次安装缺本地规则集，依赖直连 GitHub | `main.go:512` |
| 10 | P1 | 配置备份与核心二进制备份均无数量上限 | `management.go:159`, `update-core.sh:34` |
| 11 | P1 | 无日志轮转，且 sing-box.log 有两个写入者 | `armwall-sing-box.service` |
| 12 | P1 | clash_api 无 secret | `main.go:1483` |
| 13 | P1 | 四个死代码端点 | `main.go:1918,2093,2217,2414` |
| 14 | P2 | `api()` 单函数 1300 行 | `main.go:1593` |
| 15 | P2 | 大量 `Decode` 错误被忽略 | `main.go:1632` 等 |
| 16 | P2 | HTTP Server 无超时 | `main.go:3018` |
| 17 | P2 | 后端英文错误信息透传中文 UI | `main.go:844`, `app.js:1163` |
| 18 | P2 | 过滤视图下上移/下移语义错误 | `app.js:904` |
| 19 | P2 | `clashDelay` 先解码后判状态码 | `strategy_runtime.go:95` |
| 20 | P2 | `finally` 无条件启用按钮 | `app.js:1164` |
| 21 | P2 | 前端无自动刷新 | `app.js:1237` |
| 22 | P2 | 次要项合集（8 项） | 见正文 |
| 23 | P1 | 4 个二进制入库，`.git` 72MB，无 `.gitignore` | 仓库根 |
| 24 | P1 | `curl \| sudo sh` 无校验，`ARMWALL_REF=main` 不可复现 | `README.md:41` |
| 25 | P1 | 无 CI，Makefile 缺 `vet`/`gofmt`/checksum | `Makefile:10` |
| 26 | P1 | 无卸载脚本 | — |
| 27 | P1 | `update-core.sh` `sed` 解析脆弱 + GitHub 限速 | `update-core.sh:63` |
| 28 | P1 | `naive-supervisor.sh` 单实例退出导致全部被杀 | `naive-supervisor.sh:28` |
| 29 | P1 | 无 LICENSE | 仓库根 |
| 30 | P1 | README 七项缺口（含 sing-box 版本要求） | `README.md` |
| 31 | P2 | `go.mod` 全部标 `// indirect` | `go.mod:6` |

**合计**：31 项（P0 × 4，P1 × 16，P2 × 11）
