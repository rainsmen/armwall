# Changelog

All notable changes to ArmWall will be documented in this file.

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
