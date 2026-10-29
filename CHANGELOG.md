# Changelog

All notable changes to ArmWall will be documented in this file.

## [0.4.0] - 2026-10-29

### Added
- **Offline Rule Assets & Bootstrap**: Bundled precompiled official SRS rule sets (`geoip-cn.srs`, `geosite-ads.srs`, `geosite-cn.srs`, `geosite-proxy.srs`) into releases and `/usr/share/armwall/rules/`, supporting zero-network initial bootstrap (`--bootstrap-rules`).
- **Monotonic Revision Tracking**: Added `Revision int64` counter to `Store` and SQLite `settings` table, incrementing on every transaction commit, combined with `time.RFC3339Nano` timestamp precision to eliminate subscription update concurrency races.
- **Transport Normalization**: Added `normalizeTransport` handling `tcp`/`none` and `h2 -> http` mapping, preventing airport subscription parameter mismatches with sing-box.
- **Rule Update Optimization**: Added `bytes.Equal` content comparison during rule updates to skip redundant disk writes and core restarts when rule contents are identical; enhanced atomic rollback with `.absent` tracking.
- **Concurrency & Resource Safety**:
  - Wrapped global `proxyPort` in `sync.RWMutex` with safe accessors.
  - Added port reservation table in `assignNaivePorts` excluding SSH (22), DNS (53), Web (8080), Clash API (9090), Proxy, TProxy, and MAC ports.
  - Extended frontend batch test timeout to 180s and enhanced backend cancellation handling (`r.Context().Done()`).
- **Packaging & CI Gateways**:
  - Added `binutils` (`readelf`) to `install.sh` prerequisites.
  - Multi-script syntax verification in CI and Makefile (`for script in ...; do sh -n "$script"; done`).
  - Strict Go formatting check (`test -z "$(gofmt -l *.go)"`) and toolchain pinning to Go 1.26.10.

### Fixed
- **Frontend Subscription Creation**: Fixed `POST /api/subscription` payload deserialization 400 error by adding JSON struct tags for frontend attributes (`id`, `enabled`, `update_hours`, `last_updated`).
- **sing-box Protocol Sniffing Order**: Placed `action: sniff` at index 0 of route rules ahead of DNS hijack rules, ensuring proper TProxy protocol sniffing.
- **CSP Compliance**: Removed inline styles from `web/index.html` and migrated cursor styles to `web/styles.css`, achieving 100% CSP strict compliance.
- **Gateway Fault Tolerance**: Added automatic fallback to dynamic interface detection (`detect`) in `gateway.sh load_state` when saved network interface names become invalid.
- **Dead Code Cleanup**: Removed unused legacy functions (`updateSubscriptionsWithForceLocked`).
- **Repository Governance**: Purged precompiled binaries from Git tracking and updated `.gitignore`.
- **Documentation Consolidation**: Unified all historical audit reports and improvement plans into `docs/CONSOLIDATED-IMPROVEMENT-PLAN-2026-10-29.md`.

## [0.3.2] - 2026-10-28

### Added
- **Batch Node Testing Engine**: Support concurrent batch Ping, TCP handshake, and URLTest delay measurement via `/api/node/batch-test`.
- **Node Management UI Enhancements**:
  - One-click batch testing buttons (批量 Ping, 批量 TCP, 批量 URLTest).
  - Delay badges with dynamic latency grading (Green/Yellow/Red/Timeout).
  - Sort nodes by delay ascending or descending.
  - Transparent credential retrieval on demand via `/api/node/get`.
- **Protocol Sniffing Support**: Configured sing-box 1.14+ compatible route-level protocol sniffing (`action: sniff`).
- **Session Auth & Request Resiliency**: Added `sessionStorage` token support and `AbortController` timeout handling in Web UI.
- **SQLite Singleton Connection**: Reused long-lived database connection with WAL mode and memory cache preservation.
- **License & Security**: Added MIT License and SECURITY.md.

### Fixed
- **Transparent Gateway**: Added `ExecStop` to `armwall-gateway.service` and pre-uninstall cleanup in `uninstall.sh` to prevent network blackout.
- **Interface Detection**: Fixed single-NIC bypass gateway interface detection to filter virtual interfaces (Tailscale/Docker/Tun) and verify interface existence in kernel.
- **Concurrency Protection**: Added `coreOperationMu` locking around core updates and uploads.
- **Atomic Operations**: Used secure temporary files in `update-core.sh` and added directory sync in `writeAtomicFile`.
- **Input Validation**: Added reservation checks for node IDs, port conflict checks, and hyphen-injection prevention in ping.
- **Embedded ARM Timing**: Increased sing-box port readiness check timeout from 3s to 8s to accommodate rule set parsing on lower-power ARM boards.
- **Subscription Identity**: Preserved node ordering and user overrides across subscription refreshes.
- **Dead Code Cleanup**: Removed duplicate unreachable handler implementations.
