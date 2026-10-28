# ArmWall 项目复核评估与改进清单

评估日期：2026-07-30  
评估范围：项目文档、Go 后端、原生 JavaScript 前端、Shell 部署脚本、systemd 单元、构建与发布流程  
参考材料：`AUDIT-REPORT.md`（Claude 审核报告）

## 一、总体结论

综合项目文档、代码、部署脚本、systemd 单元及 Claude 审核报告，原报告提出的 31 项问题大部分成立，但存在少量误报、统计过时和遗漏项。

当前版本不建议直接作为公开管理面板或正式发布包继续分发。最需要先解决的是：

1. Token 缺失时鉴权失效；
2. 发布二进制使用已停止安全维护的旧 Go 工具链；
3. 仓库内发布物不可复现、不可追溯；
4. Web 与 systemd timer 之间存在跨进程配置竞态；
5. 测试默认绕过真实 sing-box 配置校验，真实核心验证出现失败。

## 二、实际验证结果

| 检查 | 结果 |
| --- | --- |
| `go test ./...` | 通过，当前共有 32 个测试函数，不是原报告中的 21 个 |
| `go test -race ./...` | 通过 |
| `go vet ./...` | 通过 |
| `gofmt -l *.go` | 通过，无未格式化文件 |
| `CGO_ENABLED=0 go build ./...` | 通过 |
| `node --check web/app.js` | 通过 |
| Shell 语法检查 | 5 个脚本全部通过 |
| ShellCheck 0.11 | 通过 |
| 测试覆盖率 | 44.9%；`api()` 仅 16.4% |
| sing-box 1.13.15 集成验证 | 32 个测试中 9 个失败 |
| `govulncheck` | Go 1.22.12 标准库报告 28 条带调用路径的安全告警 |
| Staticcheck | 主要是大量 HTTP 状态码使用数字常量，未发现新的严重逻辑问题 |

验证使用 `/tmp` 下的临时 Go 1.22.12 和 sing-box 1.13.15，没有修改项目源文件。

## 三、S0：发布或上线前必须处理

### 1. 鉴权必须改为 fail-closed

位置：`main.go:2997`、`armwall.service:7`

`ARMWALL_TOKEN` 为空时，当前中间件会跳过整个鉴权检查；同时服务默认监听 `0.0.0.0:8080`，环境文件又被配置为可选。该组合会暴露全部节点密码、订阅地址、服务控制和核心上传接口。

改进清单：

- [ ] Token 为空、格式错误或长度不足时拒绝启动；
- [ ] systemd 增加 `ExecStartPre` 配置检查；
- [ ] 默认监听 `127.0.0.1`，由安装器显式选择是否暴露到 LAN；
- [ ] 增加 Token 为空、错误、缺少请求头、正确 Token 四类测试；
- [ ] 增加鉴权失败审计日志和基本速率限制；
- [ ] 为敏感响应统一设置 `Cache-Control: no-store`。

### 2. 收紧核心上传和更新的 root 执行链

位置：`management.go:230`、`update-core.sh:26`

上传接口最终会安装并执行用户提交的 ELF。当前自检只能证明程序能够响应 `version` 或 `check`，无法证明它是可信的 sing-box 或 naive 二进制。

改进清单：

- [ ] 优先只允许安装官方 Release 资产；
- [ ] 使用版本白名单和 SHA256/签名验证；
- [ ] 手工上传时记录文件哈希、来源、操作者和更新时间；
- [ ] 手工上传增加显式风险确认；
- [ ] 长期将 Web 服务与特权安装 helper 分离。

### 3. 使用仍受安全支持的 Go 工具链重建

仓库 AMD64 二进制由 Go 1.22.5 构建。使用 Go 1.22.12 执行 `govulncheck`，标准库仍报告 28 条带调用路径的安全告警。部分告警需要结合 Linux 平台和实际入口继续分诊，但继续发布由已停止安全维护的 Go 1.22 构建的二进制并不合适。

改进清单：

- [ ] `go.mod` 可保留 `go 1.22` 作为语言版本下限；
- [ ] CI 和 Release 使用当前受支持、已修复的 Go 工具链；
- [ ] 重新生成四架构二进制；
- [ ] 将 `govulncheck` 加入发布门禁；
- [ ] 在 Release 中记录 Go 版本和依赖清单。

### 4. 修复发布物不可复现、不可追溯

当前四个预编译二进制直接提交到仓库，`.git` 已约 72 MiB，历史中提交过 5 轮。AMD64 二进制元数据为：

```text
vcs.revision=a9ef16e
vcs.modified=true
```

当前源码 HEAD 为 `4d2f7be`。因此该二进制无法被证明与当前源码一致。

改进清单：

- [ ] 添加 `.gitignore`；
- [ ] 从源码仓库迁出二进制；
- [ ] 使用干净 Git tag 在 CI 中构建 Release；
- [ ] 发布 `SHA256SUMS`、SBOM 和构建元数据；
- [ ] 一键安装器固定版本，不再默认下载 `main`；
- [ ] 下载后先校验哈希或签名，再以 root 安装。

### 5. 将真实 sing-box 配置校验加入 CI

把 sing-box 1.13.15 放入 PATH 后，现有 32 个测试中有 9 个失败，暴露出测试 fixture 和真实核心约束不一致。

已确认的两类问题：

1. `validateNode` 接受缺少必需 TLS 的 AnyTLS、Hysteria2 等节点，最终才由 sing-box 返回 `TLS required`；
2. ACL 将 `"443"` 与 `"1000:2000"` 都写入 `port_range`，sing-box 对单端口返回 `bad port range: 443`。单端口应写入 `port`，范围才写入 `port_range`。

改进清单：

- [ ] 按协议验证必填字段、TLS、UUID、密码和传输组合；
- [ ] 分离 ACL 单端口与端口范围；
- [ ] 修正测试 fixture，使其符合真实协议要求；
- [ ] 增加“生成配置 -> `sing-box check`”集成测试；
- [ ] 至少覆盖最低支持版本和最新稳定版本；
- [ ] README 明确最低及已测试 sing-box 版本。

### 6. 增加跨进程配置锁和唯一候选文件

位置：`main.go:427`、`main.go:673`、`main.go:1521`

Web、订阅 timer、规则 timer 是独立进程。进程内 `sync.Mutex` 无法防止它们同时读取旧快照并整库重写，固定的 `.candidate` 文件也可能互相覆盖。

改进清单：

- [ ] 所有“读配置 -> 生成文件 -> 写库 -> 重启”流程使用跨进程文件锁；
- [ ] 候选文件使用 `os.CreateTemp`；
- [ ] timer 与 Web 写路径使用同一事务接口；
- [ ] 更优方案是 timer 调用本机 API，由单一进程提交；
- [ ] 增加多进程并发与丢失更新测试。

### 7. 增加 HTTP 资源限制和安全响应头

位置：`main.go:3018`

当前 HTTP Server 没有读取、写入、空闲和请求头超时，也没有请求头大小上限。除配置导入和核心上传外，大多数 JSON 请求体没有大小限制。

改进清单：

- [ ] 配置 `ReadHeaderTimeout`、`ReadTimeout`、`WriteTimeout` 和 `IdleTimeout`；
- [ ] 配置 `MaxHeaderBytes`；
- [ ] 对 JSON 请求体设置统一大小上限；
- [ ] 增加 CSP、`X-Content-Type-Options` 和防嵌入策略；
- [ ] 提供 TLS 或明确支持的反向代理部署方式；
- [ ] 提供 Token 轮换、退出和清除入口。

## 四、S1：近期正确性和可靠性改进

### 1. 缩小全局锁粒度

位置：`main.go:1593`

`api()` 使用同一把锁包住 54 个端点及网络下载、测速、核心更新和 systemctl 操作。慢订阅或更新可能冻结整个管理界面。

- [ ] 锁只保护内存状态和最终提交；
- [ ] 下载、测速、核心更新和进程操作移到锁外；
- [ ] 分钟级任务改为异步任务、任务 ID 和状态轮询；
- [ ] 为读操作和状态查询提供不受慢写任务阻塞的路径。

### 2. 让 SQLite 成为唯一真相源

位置：`storage.go:155`、`main.go:694`

`loadDB` 在节点和订阅都为空时返回 `ErrNoRows`，即使 settings 已加载也会被放弃；`load()` 对任意数据库错误都会静默回退 JSON。

- [ ] 使用 schema version 或 initialized 元数据判断首次初始化；
- [ ] 数据库损坏、权限错误、busy 超时应显式报错；
- [ ] 不要用旧 JSON 静默覆盖 SQLite；
- [ ] 检查所有 `rows.Err()`；
- [ ] 检查 settings JSON 反序列化错误；
- [ ] 明确旧 JSON 迁移完成后的退役策略。

### 3. 重做持久化事务与回滚

位置：`main.go:705`、`main.go:773`、`main.go:1506`

Claude 报告称 `persistStore` 有“完整四级回滚”，这一评价过高。`save()` 先提交 SQLite 再写 JSON；如果 JSON 写失败，SQLite 已是新状态，但当前错误分支不会回退数据库。

`writeConfig` 也会依次修改 Naive 配置、sing-box 配置和 MAC ACL，后一步失败可能留下前面已经提交的文件。

- [ ] 先生成所有候选文件并完成核心校验；
- [ ] 使用同一快照统一提交运行配置；
- [ ] SQLite 最后提交，或记录可恢复事务；
- [ ] 订阅和规则更新统一走同一事务接口；
- [ ] 为每个失败点增加 fault-injection 测试；
- [ ] 回滚失败必须写入高优先级日志，不应忽略错误。

### 4. 修复 `/api/subscription/clear` 误删节点

位置：`main.go:1918`

当前逻辑依赖 `sub-` ID 前缀判断来源，而分享链接手动导入也生成该前缀。

- [ ] 只根据 `SubscriptionID != ""` 删除订阅节点；
- [ ] 或直接移除这个无 UI 入口的端点；
- [ ] 增加手动导入节点保留测试。

### 5. 对齐 Fallback 的承诺与实现

位置：`main.go:1351`

配置生成会将 fallback 静默转换为 urltest，两者语义不同。

- [ ] 实现真正的主节点健康优先行为；
- [ ] 若当前核心无法表达，则从 UI、README 和校验结构中移除；
- [ ] 不应继续以同名功能向用户展示不同语义。

### 6. 为广告规则增加开关

`geosite-ads -> block` 当前无条件注入，误杀后用户无法关闭。

- [ ] 增加持久化配置字段；
- [ ] 增加 UI 开关和清晰默认值；
- [ ] 增加旧配置迁移；
- [ ] 测试启用和关闭两种配置输出。

### 7. 解决首次安装规则集依赖直连 GitHub

位置：`main.go:512`

本地规则不存在时，sing-box 需要直连 GitHub 获取规则，目标网络环境很可能无法访问。

- [ ] 安装器预取并校验规则；
- [ ] Release 可携带经过验证的规则资产；
- [ ] 失败时在 UI 显示明确状态；
- [ ] 提供手工上传或镜像源配置。

### 8. 增加日志和备份保留策略

配置备份、核心备份、`sing-box.log` 和 `naive.log` 均没有自动清理。

- [ ] 配置备份建议保留最近 20 份；
- [ ] 核心备份建议保留最近 2 份；
- [ ] 配置 logrotate 或改用 journald；
- [ ] 避免 sing-box 和 systemd 同时写同一日志文件；
- [ ] UI 展示磁盘占用、保留数量和清理结果。

### 9. 为 Clash API 设置 secret

位置：`main.go:1483`、`strategy_runtime.go:26`

虽然接口只监听 `127.0.0.1:9090`，本机其他用户或容器进程仍可访问。

- [ ] 生成随机 secret 并使用最小权限保存；
- [ ] 后端请求携带认证头；
- [ ] 禁止把 secret 返回到 `/api/state`。

### 10. 修正 NaiveProxy 监督逻辑

位置：`naive-supervisor.sh:22`、`armwall-naive.service`

Claude 报告所述“任一实例退出会立刻杀掉全部”不准确。实际问题是单个实例退出后不会被单独重启；所有实例结束后，无参数 `wait` 在 dash 中还可能返回 0，使 `Restart=on-failure` 不生效。

- [ ] 优先使用 systemd 模板单元逐实例管理；
- [ ] 或使用能够监控和单独重启子进程的可靠 supervisor；
- [ ] 最低限度改为 `Restart=always` 并正确传播失败状态；
- [ ] 增加多节点退出与重启行为测试。

### 11. 完善核心更新器

位置：`update-core.sh:62`

- [ ] 使用稳定 JSON 解析；
- [ ] 处理 GitHub API 限速；
- [ ] 支持固定版本而不只是 latest；
- [ ] 校验下载资产哈希或签名；
- [ ] 自动清理旧备份；
- [ ] 记录安装前后版本和回滚结果。

### 12. 做 systemd 权限隔离和沙箱加固

Web、sing-box 和 NaiveProxy 当前基本都以 root 运行，且缺少 systemd 沙箱配置。

- [ ] Web 管理进程使用专用低权限用户；
- [ ] nft、systemctl 和核心安装通过窄接口特权 helper；
- [ ] sing-box 只保留实际需要的 capabilities；
- [ ] 使用 `NoNewPrivileges`、`ProtectSystem`、`ProtectHome`、`PrivateTmp`；
- [ ] 明确 `ReadWritePaths`；
- [ ] 增加内存、文件描述符和进程数量上限。

## 五、S2：代码质量、测试和体验优化

### 1. 拆分巨型 API handler

位置：`main.go:1593`

`api()` 约 1300 行，包含 54 个端点。应按 node、subscription、routing、ACL、management 和 gateway 拆分，并统一：

- [ ] 方法检查；
- [ ] 请求体大小限制；
- [ ] 严格 JSON 解码；
- [ ] 结构化错误响应；
- [ ] 审计日志和请求 ID；
- [ ] 成功响应编码。

当前至少有 12 处 `Decode` 错误被直接忽略，应统一修复。

### 2. 清理重复或死端点

重点评估：

- [ ] `/api/dns`；
- [ ] `/api/mode`；
- [ ] `/api/subscription/schedule`；
- [ ] `/api/subscription/clear`。

同时统一 GET/POST 约定，`/api/service/status` 前端不应使用 POST。

### 3. 修复前端节点排序

位置：`web/app.js:904`

筛选视图中仍按全量节点计算上移和下移，可能与不可见节点交换。

- [ ] 筛选状态下禁用排序；
- [ ] 或提供明确的全量排序模式；
- [ ] 添加对应前端测试。

### 4. 改善前端状态和凭据体验

- [ ] 定时刷新服务状态和策略延迟；
- [ ] 日志只在相关视图可见时刷新；
- [ ] `nodeTests` 增加容量上限或清理策略；
- [ ] 增加 Token 重置、退出和轮换入口；
- [ ] 支持会话级 Token，避免强制长期存储在 `localStorage`；
- [ ] 端口文案从后端状态生成，不再硬编码；
- [ ] 静态资源版本由构建 hash 注入。

### 5. 修正 `clashDelay` 错误处理顺序

位置：`strategy_runtime.go:95`

应先判断 HTTP 状态码，再解析成功响应，避免把真实 404、401 等错误覆盖为 `invalid urltest response`。

### 6. 统一中文错误和结构化 API 错误

- [ ] 后端返回 `{code, message, details}`；
- [ ] 前端按错误码显示中文；
- [ ] 日志保留原始技术信息；
- [ ] 不直接把 systemctl、sing-box 和 Shell 原始输出展示给终端用户。

### 7. 建立 CI 质量门禁

至少应包含：

- [ ] `go test ./...`；
- [ ] `go test -race ./...`；
- [ ] `go vet ./...`；
- [ ] `gofmt` 检查；
- [ ] Staticcheck；
- [ ] `govulncheck`；
- [ ] Node 语法或单元测试；
- [ ] ShellCheck；
- [ ] 四架构交叉编译；
- [ ] sing-box 最低版本及最新版配置校验；
- [ ] Release checksum、SBOM 和可复现构建检查。

### 8. 补高风险测试

当前总体语句覆盖率为 44.9%，但风险分布不均：

| 位置 | 覆盖情况 |
| --- | --- |
| `api()` | 16.4% |
| `fetchSubscription` | 0% |
| `downloadResource` | 0% |
| `updateRule` | 0% |
| `applyScheduledRuleUpdates` | 0% |
| `restartProxy` | 0% |
| 鉴权和 HTTP Server | 0% |

优先补充：

- [ ] 鉴权测试；
- [ ] 跨进程锁和丢失更新测试；
- [ ] 订阅清空测试；
- [ ] 真实 sing-box 配置测试；
- [ ] 下载重试、超限和备用地址测试；
- [ ] 核心上传拒绝路径；
- [ ] 数据库损坏和事务失败注入；
- [ ] Shell 脚本 fixture/dry-run 行为测试。

### 9. 补齐仓库基础文件和运维文档

- [ ] 添加 LICENSE；
- [ ] 添加 `.gitignore`；
- [ ] 增加 `uninstall.sh`；
- [ ] README 写明最低和已测试 sing-box 版本；
- [ ] README 增加端口清单；
- [ ] README 增加明文 HTTP 风险和 Token 轮换说明；
- [ ] README 增加升级、卸载、日志、备份和规则下载故障排查；
- [ ] 明确 IPv4-only 透明网关限制；
- [ ] 说明本地 Clash API 9090 的用途和保护方式。

### 10. 整理 Go 模块和依赖

在临时副本执行 `go mod tidy` 后，`modernc.org/sqlite` 会被正确标记为直接依赖，Claude 报告第 31 项成立。

- [ ] 执行并提交 `go mod tidy` 结果；
- [ ] 使用 Renovate 或 Dependabot 持续维护依赖；
- [ ] SQLite 当前版本与最新版本跨度较大，应分批升级并配合迁移测试；
- [ ] 每次依赖升级运行完整测试、race、vulnerability scan 和真实核心集成测试。

### 11. 清理低级静态检查问题

Staticcheck 当前主要报告约 50 处数字 HTTP 状态码。

- [ ] 使用 `http.Status*` 常量；
- [ ] 统一 `Content-Type` 和 charset；
- [ ] 统一错误写入和 JSON 响应；
- [ ] 避免忽略关键文件、JSON 和回滚错误。

## 六、对 Claude 审核报告的校正

1. 问题 1、3-19、21-27、29-31 基本成立。

2. 问题 2 中明文 HTTP、缓存和安全响应头缺失成立。常量时间比较和速率限制属于合理加固，但不应与“Token 为空导致完全无鉴权”视为同一级主风险。

3. 问题 20“`finally` 导致长任务期间按钮可重复点击”未能确认。`finally` 在异步任务结束后恢复按钮，目前页面也没有初始永久禁用的 action 按钮。可以做防御性优化，但不应列为已确认缺陷。

4. 问题 28 的结果方向成立，但根因应改为“缺少逐实例监督，且无参数 `wait` 可能返回 0，导致 `Restart=on-failure` 不生效”。

5. 报告写 21 个测试和 53 个 API 分支，当前实际是 32 个测试函数和 54 个 API case。

6. 报告对 `persistStore`“完整失败回滚”的正面评价不成立：SQLite 已提交而 JSON 写入失败时，仍可能留下不一致状态。

7. sing-box 1.13.15 的最小测试仍接受旧 `block` 出站和旧 `outbound` 路由字段，因此不能简单断言新安装一定因这两个字段失败。但真实集成测试已经发现 TLS 和 ACL 配置兼容问题，仍需尽快建立版本矩阵。

## 七、建议实施顺序

### 第一阶段：安全边界与发布可信度

1. 修复 Token 缺失时无鉴权；
2. 使用受支持 Go 版本重建；
3. 建立可信 Release、校验和与固定版本安装；
4. 收紧核心上传和特权操作；
5. 增加 HTTP 超时、请求限制和安全响应头。

### 第二阶段：配置正确性和并发安全

1. 修复真实 sing-box 配置兼容问题；
2. 增加跨进程锁；
3. 重构持久化事务与回滚；
4. 统一 SQLite 真相源；
5. 修复订阅清空、Fallback 和广告规则行为。

### 第三阶段：运维可靠性

1. 日志轮转与备份保留；
2. 规则首次安装和更新可靠性；
3. NaiveProxy 逐实例监督；
4. systemd 沙箱和最小权限；
5. 升级与卸载流程。

### 第四阶段：可维护性和体验

1. 拆分 `api()`；
2. 建立完整 CI；
3. 提升高风险路径测试覆盖；
4. 统一错误响应和中文提示；
5. 完善 README、LICENSE、依赖维护和前端状态刷新。

## 八、最终结论

项目核心功能已有一定测试基础，配置原子写入、订阅节点身份保持、导入备份及部分失败回滚设计值得保留。但当前安全边界、跨进程一致性和发布供应链仍不足以支撑公开或无人值守部署。

建议在完成 S0 清单前暂停继续扩大功能范围，先使鉴权、发布物、真实核心兼容和配置事务具备可验证的安全与正确性保障。
