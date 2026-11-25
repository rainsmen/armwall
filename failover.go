package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	defaultFailoverIntervalSec       = 30
	defaultFailoverFailureThreshold  = 3
	defaultFailoverRecoveryThreshold = 2
	defaultFailoverTestURL           = "https://www.gstatic.com/generate_204"
	failoverProbeTimeout             = 6 * time.Second
	failoverStartupGrace             = 5 * time.Second
	failoverMaxEvents                = 20
)

type FailoverEvent struct {
	Time    time.Time `json:"time"`
	Type    string    `json:"type"`
	From    string    `json:"from,omitempty"`
	To      string    `json:"to,omitempty"`
	Message string    `json:"message"`
}

type FailoverStatus struct {
	Enabled              bool            `json:"enabled"`
	Managing             bool            `json:"managing"`
	InactiveReason       string          `json:"inactive_reason,omitempty"`
	State                string          `json:"state"`
	PrimaryNodeID        string          `json:"primary_node_id,omitempty"`
	ActiveNodeID         string          `json:"active_node_id,omitempty"`
	Chain                []string        `json:"chain,omitempty"`
	ConsecutiveFailures  int             `json:"consecutive_failures"`
	PrimaryRecoveryCount int             `json:"primary_recovery_count"`
	FailureThreshold     int             `json:"failure_threshold"`
	RecoveryThreshold    int             `json:"recovery_threshold"`
	AutoFailback         bool            `json:"auto_failback"`
	LastCheckAt          time.Time       `json:"last_check_at,omitempty"`
	LastSwitchAt         time.Time       `json:"last_switch_at,omitempty"`
	LastActiveDelayMS    int64           `json:"last_active_delay_ms,omitempty"`
	LastPrimaryDelayMS   int64           `json:"last_primary_delay_ms,omitempty"`
	LastError            string          `json:"last_error,omitempty"`
	Events               []FailoverEvent `json:"events,omitempty"`
}

type failoverManager struct {
	checkMu  sync.Mutex
	mu       sync.RWMutex
	notifyCh chan struct{}

	st FailoverStatus

	loadStoreFn    func() (Store, error)
	proxyRunningFn func() bool
	probeFn        func(tag, testURL string) (int64, error)
	selectFn       func(groupTag, targetTag string) error
	proxyNowFn     func(tag string) (string, error)
	nowFn          func() time.Time
}

func newFailoverManager() *failoverManager {
	return &failoverManager{
		notifyCh: make(chan struct{}, 1),
		st: FailoverStatus{
			State: "disabled",
		},
		loadStoreFn:    loadAPIStoreSnapshot,
		proxyRunningFn: func() bool { return proxyRunningFn() },
		probeFn: func(tag, testURL string) (int64, error) {
			return clashDelayTimeout(tag, testURL, failoverProbeTimeout)
		},
		selectFn:   clashSelectProxy,
		proxyNowFn: clashProxyNow,
		nowFn:      time.Now,
	}
}

var defaultFailover = newFailoverManager()

func (m *failoverManager) notify() {
	select {
	case m.notifyCh <- struct{}{}:
	default:
	}
}

func (m *failoverManager) status() FailoverStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cp := m.st
	if len(m.st.Chain) > 0 {
		cp.Chain = append([]string(nil), m.st.Chain...)
	}
	if len(m.st.Events) > 0 {
		cp.Events = append([]FailoverEvent(nil), m.st.Events...)
	}
	return cp
}

func (m *failoverManager) appendEventLocked(ev FailoverEvent) {
	m.st.Events = append(m.st.Events, ev)
	if len(m.st.Events) > failoverMaxEvents {
		m.st.Events = append([]FailoverEvent(nil), m.st.Events[len(m.st.Events)-failoverMaxEvents:]...)
	}
}

func (m *failoverManager) syncConfigState(s Store) (chain []string, active bool, nextInterval time.Duration) {
	cfg := s.Failover
	intervalSec := cfg.CheckIntervalSec
	if intervalSec < 10 {
		intervalSec = defaultFailoverIntervalSec
	}
	failureThreshold := cfg.FailureThreshold
	if failureThreshold < 1 {
		failureThreshold = defaultFailoverFailureThreshold
	}
	recoveryThreshold := cfg.RecoveryThreshold
	if recoveryThreshold < 1 {
		recoveryThreshold = defaultFailoverRecoveryThreshold
	}
	autoFailback := boolValue(cfg.AutoFailback, true)

	m.mu.Lock()
	defer m.mu.Unlock()
	m.st.Enabled = cfg.Enabled
	m.st.FailureThreshold = failureThreshold
	m.st.RecoveryThreshold = recoveryThreshold
	m.st.AutoFailback = autoFailback

	if !cfg.Enabled {
		m.st.Managing = false
		m.st.InactiveReason = ""
		m.st.State = "disabled"
		m.st.PrimaryNodeID = resolvePrimaryNode(s)
		m.st.ActiveNodeID = m.st.PrimaryNodeID
		m.st.Chain = nil
		m.st.ConsecutiveFailures = 0
		m.st.PrimaryRecoveryCount = 0
		m.st.LastError = ""
		return nil, false, 60 * time.Second
	}

	chain = failoverChain(s)
	if len(chain) < 2 {
		reason := "没有可用的备用节点"
		if s.TCPOutbound != "" && s.TCPOutbound != "same" {
			reason = "TCP 默认出站已手动覆盖，全局故障转移未接管"
		} else if resolvePrimaryNode(s) == "" {
			reason = "没有已启用的主节点"
		}
		m.st.Managing = false
		m.st.InactiveReason = reason
		m.st.State = "inactive"
		m.st.PrimaryNodeID = resolvePrimaryNode(s)
		m.st.ActiveNodeID = m.st.PrimaryNodeID
		m.st.Chain = nil
		m.st.ConsecutiveFailures = 0
		m.st.PrimaryRecoveryCount = 0
		m.st.LastError = ""
		return nil, false, time.Duration(intervalSec) * time.Second
	}

	primary := chain[0]
	m.st.Managing = true
	m.st.InactiveReason = ""
	m.st.Chain = append([]string(nil), chain...)

	// Reset state if user changed the primary node or active node disappeared from the chain.
	if m.st.PrimaryNodeID != primary || m.st.ActiveNodeID == "" || !slices.Contains(chain, m.st.ActiveNodeID) {
		m.st.PrimaryNodeID = primary
		m.st.ActiveNodeID = primary
		m.st.ConsecutiveFailures = 0
		m.st.PrimaryRecoveryCount = 0
		m.st.LastActiveDelayMS = 0
		m.st.LastPrimaryDelayMS = 0
		m.st.LastError = ""
	}
	if m.st.State == "disabled" || m.st.State == "inactive" || m.st.State == "stopped" || m.st.State == "" {
		m.st.State = "healthy"
	}

	return chain, true, time.Duration(intervalSec) * time.Second
}

func (m *failoverManager) step(ctx context.Context) time.Duration {
	m.checkMu.Lock()
	defer m.checkMu.Unlock()

	s, err := m.loadStoreFn()
	if err != nil {
		log.Printf("failover: load store failed: %v", err)
		return time.Duration(defaultFailoverIntervalSec) * time.Second
	}

	chain, managing, nextInterval := m.syncConfigState(s)
	if !managing {
		return nextInterval
	}
	if ctx.Err() != nil {
		return nextInterval
	}

	if !m.proxyRunningFn() {
		m.mu.Lock()
		m.st.State = "stopped"
		m.st.LastError = ""
		m.mu.Unlock()
		return nextInterval
	}

	cfg := s.Failover
	testURL := strings.TrimSpace(cfg.TestURL)
	if testURL == "" {
		testURL = defaultFailoverTestURL
	}
	failureThreshold := cfg.FailureThreshold
	if failureThreshold < 1 {
		failureThreshold = defaultFailoverFailureThreshold
	}
	recoveryThreshold := cfg.RecoveryThreshold
	if recoveryThreshold < 1 {
		recoveryThreshold = defaultFailoverRecoveryThreshold
	}
	autoFailback := boolValue(cfg.AutoFailback, true)

	primary := chain[0]
	m.mu.RLock()
	activeNode := m.st.ActiveNodeID
	prevState := m.st.State
	m.mu.RUnlock()

	if activeNode == "" || !slices.Contains(chain, activeNode) {
		activeNode = primary
	}

	// If sing-box restarted externally (e.g. rule/subscription update), the
	// selector resets to its default (primary). Re-align to our active backup
	// so traffic does not fall back onto a known-failed primary.
	if activeNode != primary && m.proxyNowFn != nil {
		if nowTag, nowErr := m.proxyNowFn(failoverOutboundTag); nowErr == nil && nowTag != "" && nowTag != activeNode {
			if selErr := m.selectFn(failoverOutboundTag, activeNode); selErr == nil {
				now := m.nowFn()
				m.mu.Lock()
				m.appendEventLocked(FailoverEvent{
					Time:    now,
					Type:    "realigned",
					From:    nowTag,
					To:      activeNode,
					Message: fmt.Sprintf("检测到出站重置为 %s，已重新对齐至备用节点 %s", nodeDisplayName(s, nowTag), nodeDisplayName(s, activeNode)),
				})
				m.mu.Unlock()
				log.Printf("failover: realigned %s from %s back to active backup %s", failoverOutboundTag, nowTag, activeNode)
			}
		}
	}

	// Probe currently active node.
	activeDelay, activeErr := m.probeFn(activeNode, testURL)
	now := m.nowFn()

	if activeErr == nil {
		m.mu.Lock()
		m.st.LastCheckAt = now
		m.st.ConsecutiveFailures = 0
		m.st.LastActiveDelayMS = activeDelay
		m.st.LastError = ""
		if activeNode == primary {
			m.st.State = "healthy"
			m.st.LastPrimaryDelayMS = activeDelay
			m.st.PrimaryRecoveryCount = 0
		} else {
			m.st.State = "failed_over"
		}
		m.mu.Unlock()
	} else {
		m.mu.Lock()
		m.st.LastCheckAt = now
		m.st.ConsecutiveFailures++
		fails := m.st.ConsecutiveFailures
		m.st.LastActiveDelayMS = 0
		m.st.LastError = activeErr.Error()
		if activeNode == primary && fails < failureThreshold {
			m.st.State = "degraded"
		}
		m.mu.Unlock()

		log.Printf("failover: active node %s probe failed (%d/%d): %v", activeNode, fails, failureThreshold, activeErr)

		if fails >= failureThreshold {
			candidates := failoverCandidates(chain, activeNode, autoFailback)
			switched := false
			for _, candidate := range candidates {
				if ctx.Err() != nil {
					return nextInterval
				}
				delay, candErr := m.probeFn(candidate, testURL)
				if candErr != nil {
					log.Printf("failover: candidate node %s probe failed: %v", candidate, candErr)
					continue
				}
				if selErr := m.selectFn(failoverOutboundTag, candidate); selErr != nil {
					m.mu.Lock()
					m.st.LastError = selErr.Error()
					m.mu.Unlock()
					log.Printf("failover: switch %s -> %s failed: %v", activeNode, candidate, selErr)
					return nextInterval
				}
				switchTime := m.nowFn()
				evType := "failover"
				nextState := "failed_over"
				msg := fmt.Sprintf("节点 %s 连续 %d 次探测失败，已切换至 %s（%dms）", nodeDisplayName(s, activeNode), fails, nodeDisplayName(s, candidate), delay)
				if candidate == primary {
					evType = "failback"
					nextState = "healthy"
					msg = fmt.Sprintf("备用节点 %s 连续 %d 次探测失败，原主节点 %s 已恢复并切回（%dms）", nodeDisplayName(s, activeNode), fails, nodeDisplayName(s, candidate), delay)
				}
				m.mu.Lock()
				m.st.ActiveNodeID = candidate
				m.st.State = nextState
				m.st.ConsecutiveFailures = 0
				m.st.PrimaryRecoveryCount = 0
				m.st.LastSwitchAt = switchTime
				m.st.LastActiveDelayMS = delay
				if candidate == primary {
					m.st.LastPrimaryDelayMS = delay
				}
				m.st.LastError = ""
				m.appendEventLocked(FailoverEvent{
					Time:    switchTime,
					Type:    evType,
					From:    activeNode,
					To:      candidate,
					Message: msg,
				})
				m.mu.Unlock()
				log.Printf("failover: %s (%s -> %s, %dms)", evType, activeNode, candidate, delay)
				switched = true
				break
			}
			if !switched {
				m.mu.Lock()
				m.st.State = "all_down"
				if prevState != "all_down" {
					m.appendEventLocked(FailoverEvent{
						Time:    now,
						Type:    "all_down",
						From:    activeNode,
						Message: fmt.Sprintf("当前节点 %s 及全部备用节点探测失败，保持当前节点等待恢复", nodeDisplayName(s, activeNode)),
					})
				}
				m.mu.Unlock()
				log.Printf("failover: all nodes in chain %v failed, staying on %s", chain, activeNode)
			}
			return nextInterval
		}
	}

	// While running on a backup node and auto-failback is enabled, continuously
	// probe the original primary node and fail back after RecoveryThreshold
	// consecutive successes.
	m.mu.RLock()
	stillOnBackup := m.st.ActiveNodeID != primary
	currentActive := m.st.ActiveNodeID
	m.mu.RUnlock()

	if stillOnBackup && autoFailback && ctx.Err() == nil {
		primaryDelay, primaryErr := m.probeFn(primary, testURL)
		checkTime := m.nowFn()
		if primaryErr != nil {
			m.mu.Lock()
			m.st.PrimaryRecoveryCount = 0
			m.st.LastPrimaryDelayMS = 0
			m.mu.Unlock()
			return nextInterval
		}

		m.mu.Lock()
		m.st.PrimaryRecoveryCount++
		recCount := m.st.PrimaryRecoveryCount
		m.st.LastPrimaryDelayMS = primaryDelay
		m.mu.Unlock()

		log.Printf("failover: primary node %s probe succeeded (%d/%d, %dms)", primary, recCount, recoveryThreshold, primaryDelay)

		if recCount >= recoveryThreshold {
			if selErr := m.selectFn(failoverOutboundTag, primary); selErr != nil {
				m.mu.Lock()
				m.st.LastError = selErr.Error()
				m.mu.Unlock()
				log.Printf("failover: failback to primary %s failed: %v", primary, selErr)
				return nextInterval
			}
			m.mu.Lock()
			m.st.ActiveNodeID = primary
			m.st.State = "healthy"
			m.st.ConsecutiveFailures = 0
			m.st.PrimaryRecoveryCount = 0
			m.st.LastSwitchAt = checkTime
			m.st.LastActiveDelayMS = primaryDelay
			m.st.LastPrimaryDelayMS = primaryDelay
			m.st.LastError = ""
			m.appendEventLocked(FailoverEvent{
				Time:    checkTime,
				Type:    "failback",
				From:    currentActive,
				To:      primary,
				Message: fmt.Sprintf("原主节点 %s 连续 %d 次探测恢复（%dms），已自动切回", nodeDisplayName(s, primary), recCount, primaryDelay),
			})
			m.mu.Unlock()
			log.Printf("failover: failback (%s -> %s, %dms)", currentActive, primary, primaryDelay)
		}
	}

	return nextInterval
}

// failoverCandidates returns the ordered list of nodes to try when activeNode
// has reached FailureThreshold.
//   - When activeNode is primary: [backup1, backup2, ...]
//   - When activeNode is a backup and autoFailback is true: try primary first,
//     then subsequent backups, then earlier backups.
//   - When activeNode is a backup and autoFailback is false: try subsequent
//     backups first, then earlier backups, then primary as last resort.
func failoverCandidates(chain []string, activeNode string, autoFailback bool) []string {
	idx := slices.Index(chain, activeNode)
	if idx <= 0 {
		if len(chain) <= 1 {
			return nil
		}
		return append([]string(nil), chain[1:]...)
	}
	candidates := make([]string, 0, len(chain)-1)
	if autoFailback {
		candidates = append(candidates, chain[0])
	}
	if idx+1 < len(chain) {
		candidates = append(candidates, chain[idx+1:]...)
	}
	if idx > 1 {
		candidates = append(candidates, chain[1:idx]...)
	}
	if !autoFailback {
		candidates = append(candidates, chain[0])
	}
	return candidates
}

func nodeDisplayName(s Store, id string) string {
	for _, n := range s.Nodes {
		if n.ID == id {
			if strings.TrimSpace(n.Name) != "" {
				return n.Name
			}
			return n.ID
		}
	}
	return id
}

func (m *failoverManager) checkNow(ctx context.Context) FailoverStatus {
	_ = m.step(ctx)
	return m.status()
}

func (m *failoverManager) failbackNow(ctx context.Context) (FailoverStatus, error) {
	m.checkMu.Lock()
	defer m.checkMu.Unlock()

	s, err := m.loadStoreFn()
	if err != nil {
		return m.status(), err
	}
	chain, managing, _ := m.syncConfigState(s)
	if !managing {
		return m.status(), fmt.Errorf("failover is not active")
	}
	if !m.proxyRunningFn() {
		return m.status(), fmt.Errorf("proxy service is not running")
	}
	primary := chain[0]
	if err := m.selectFn(failoverOutboundTag, primary); err != nil {
		return m.status(), err
	}
	now := m.nowFn()
	m.mu.Lock()
	prev := m.st.ActiveNodeID
	m.st.ActiveNodeID = primary
	m.st.State = "healthy"
	m.st.ConsecutiveFailures = 0
	m.st.PrimaryRecoveryCount = 0
	m.st.LastSwitchAt = now
	m.st.LastError = ""
	if prev != "" && prev != primary {
		m.appendEventLocked(FailoverEvent{
			Time:    now,
			Type:    "manual_reset",
			From:    prev,
			To:      primary,
			Message: fmt.Sprintf("手动切回原主节点 %s", nodeDisplayName(s, primary)),
		})
	}
	m.mu.Unlock()
	return m.status(), nil
}

func (m *failoverManager) run(ctx context.Context) {
	if s, err := m.loadStoreFn(); err == nil {
		_, _, _ = m.syncConfigState(s)
	}
	grace := time.NewTimer(failoverStartupGrace)
	select {
	case <-ctx.Done():
		grace.Stop()
		return
	case <-m.notifyCh:
		grace.Stop()
	case <-grace.C:
	}

	for {
		interval := m.step(ctx)
		if interval < 10*time.Second {
			interval = 10 * time.Second
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-m.notifyCh:
			timer.Stop()
		case <-timer.C:
		}
	}
}

func apiFailoverStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if s, err := loadAPIStoreSnapshot(); err == nil {
		_, _, _ = defaultFailover.syncConfigState(s)
	}
	json.NewEncoder(w).Encode(defaultFailover.status())
}

func apiFailover(w http.ResponseWriter, r *http.Request, s Store) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var cfg FailoverSettings
	if err := decodeJSONBody(r, &cfg); err != nil {
		http.Error(w, "invalid failover settings", http.StatusBadRequest)
		return
	}
	if err := validateFailoverSettings(&cfg, s); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.Failover = cfg
	if err := persistStore(s, true); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, _, _ = defaultFailover.syncConfigState(s)
	defaultFailover.notify()
	json.NewEncoder(w).Encode(map[string]any{
		"failover": s.Failover,
		"status":   defaultFailover.status(),
	})
}

func apiFailoverCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	json.NewEncoder(w).Encode(defaultFailover.checkNow(r.Context()))
}

func apiFailoverFailback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	status, err := defaultFailover.failbackNow(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	json.NewEncoder(w).Encode(status)
}
