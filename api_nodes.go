package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

func apiNodeGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	id := r.URL.Query().Get("id")
	s, err := loadAPIStoreSnapshot()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, n := range s.Nodes {
		if n.ID == id {
			json.NewEncoder(w).Encode(n)
			return
		}
	}
	http.Error(w, "node not found", http.StatusNotFound)
}

func apiNodeTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var v struct {
		ID     string `json:"id"`
		Method string `json:"method"`
		URL    string `json:"url"`
	}
	if err := decodeOptionalJSONBody(r, &v); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if v.ID == "" {
		v.ID = r.URL.Query().Get("id")
	}
	if v.Method == "" {
		v.Method = r.URL.Query().Get("method")
	}
	s, err := loadAPIStoreSnapshot()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var target *Node
	for i := range s.Nodes {
		if s.Nodes[i].ID == v.ID {
			target = &s.Nodes[i]
			break
		}
	}
	if target == nil {
		http.Error(w, "node not found", http.StatusNotFound)
		return
	}
	if v.Method == "ping" && strings.HasPrefix(target.Server, "-") {
		http.Error(w, "invalid host", http.StatusBadRequest)
		return
	}
	ms, testErr := runSingleNodeTest(*target, v.Method, v.URL)
	if testErr != nil {
		http.Error(w, testErr.Error(), http.StatusBadGateway)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"method": v.Method, "ms": ms, "delay": ms})
}

func apiNodeBatchTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		IDs    []string `json:"ids"`
		Method string   `json:"method"`
		URL    string   `json:"url"`
	}
	if err := decodeOptionalJSONBody(r, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	method := req.Method
	if method == "" {
		method = "tcp"
	}
	if method != "ping" && method != "tcp" && method != "urltest" {
		http.Error(w, "invalid method", http.StatusBadRequest)
		return
	}
	s, err := loadAPIStoreSnapshot()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	idFilter := make(map[string]bool)
	for _, id := range req.IDs {
		idFilter[id] = true
	}
	var nodesToTest []Node
	for _, n := range s.Nodes {
		if len(idFilter) == 0 || idFilter[n.ID] {
			nodesToTest = append(nodesToTest, n)
		}
	}
	type testResult struct {
		MS    int64  `json:"ms"`
		Error string `json:"error,omitempty"`
	}
	results := make(map[string]testResult)
	var resultsMu sync.Mutex

	concurrency := 20
	if len(nodesToTest) < concurrency {
		concurrency = len(nodesToTest)
	}
	if concurrency < 1 {
		concurrency = 1
	}
	ch := make(chan Node, len(nodesToTest))
	for _, n := range nodesToTest {
		ch <- n
	}
	close(ch)

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := range ch {
				select {
				case <-r.Context().Done():
					return
				default:
				}
				ms, testErr := runSingleNodeTest(n, method, req.URL)
				resultsMu.Lock()
				if testErr != nil {
					results[n.ID] = testResult{MS: -1, Error: testErr.Error()}
				} else {
					results[n.ID] = testResult{MS: ms}
				}
				resultsMu.Unlock()
			}
		}()
	}
	wg.Wait()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"method":  method,
		"results": results,
	})
}

func apiNode(w http.ResponseWriter, r *http.Request, s Store) {
	if r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var n Node
	if decodeJSONBody(r, &n) != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	if err := validateNode(&n); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if n.ID == "" {
		n.ID = fmt.Sprintf("node-%d", time.Now().UnixNano())
	} else {
		n.ID = strings.TrimSpace(n.ID)
		lowerID := strings.ToLower(n.ID)
		if lowerID == "direct" || lowerID == "block" || lowerID == "dns-in" || lowerID == "tproxy-in" || strings.HasPrefix(lowerID, "tproxy-mac-") {
			http.Error(w, "reserved node id", 400)
			return
		}
		for _, existing := range s.Nodes {
			if existing.ID == n.ID {
				http.Error(w, "duplicate node id", 400)
				return
			}
		}
	}
	n.Enabled = true
	n.SortOrder = len(s.Nodes)
	s.Nodes = append(s.Nodes, n)
	if err := persistStore(s, true); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(n)
}

func apiNodeDelete(w http.ResponseWriter, r *http.Request, s Store) {
	if r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var v struct{ ID string }
	if err := decodeOptionalJSONBody(r, &v); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	if v.ID == "" {
		v.ID = r.URL.Query().Get("id")
	}
	found := false
	for i := range s.Nodes {
		if s.Nodes[i].ID == v.ID {
			s.Nodes = append(s.Nodes[:i], s.Nodes[i+1:]...)
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "node not found", 404)
		return
	}
	if err := persistStore(s, true); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(s)
}

func apiNodeUpdate(w http.ResponseWriter, r *http.Request, s Store) {
	if r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var n Node
	if decodeJSONBody(r, &n) != nil || n.ID == "" {
		http.Error(w, "invalid node", 400)
		return
	}
	index := -1
	for i := range s.Nodes {
		if s.Nodes[i].ID == n.ID {
			index = i
			break
		}
	}
	if index < 0 {
		http.Error(w, "node not found", 404)
		return
	}
	previous := s.Nodes[index]
	if n.Password == "******" {
		n.Password = s.Nodes[index].Password
	}
	if n.UUID == "******" {
		n.UUID = s.Nodes[index].UUID
	}
	if n.ObfsPassword == "******" {
		n.ObfsPassword = s.Nodes[index].ObfsPassword
	}
	n.SubscriptionID = previous.SubscriptionID
	if strings.TrimSpace(n.Group) == "" {
		n.Group = previous.Group
	}
	if n.SubscriptionID != "" {
		if n.Name != previous.Name {
			n.NameOverride = n.Name
		} else {
			n.NameOverride = previous.NameOverride
		}
		if n.Group != previous.Group {
			n.GroupOverride = n.Group
		} else {
			n.GroupOverride = previous.GroupOverride
		}
	}
	n.SortOrder = previous.SortOrder
	n.NaivePort = previous.NaivePort
	if err := validateNode(&n); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	s.Nodes[index] = n
	if err := persistStore(s, true); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(n)
}

func apiNodeCopy(w http.ResponseWriter, r *http.Request, s Store) {
	if r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var v struct{ ID string }
	if err := decodeJSONBody(r, &v); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	for _, n := range s.Nodes {
		if n.ID == v.ID {
			n.ID = fmt.Sprintf("node-%d", time.Now().UnixNano())
			n.Name += " - 副本"
			n.SubscriptionID = ""
			n.Group = "手动节点"
			n.Enabled = true
			n.SortOrder = len(s.Nodes)
			s.Nodes = append(s.Nodes, n)
			if err := persistStore(s, true); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			json.NewEncoder(w).Encode(n)
			return
		}
	}
	http.Error(w, "node not found", 404)
}

func apiNodeToggle(w http.ResponseWriter, r *http.Request, s Store) {
	if r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var v struct {
		ID      string
		Enabled bool
	}
	if err := decodeJSONBody(r, &v); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	found := false
	for i := range s.Nodes {
		if s.Nodes[i].ID == v.ID {
			s.Nodes[i].Enabled = v.Enabled
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "node not found", 404)
		return
	}
	if err := persistStore(s, true); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(s)
}

func apiNodeBatchToggle(w http.ResponseWriter, r *http.Request, s Store) {
	if r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var v struct {
		IDs     []string
		Enabled bool
	}
	if decodeJSONBody(r, &v) != nil || len(v.IDs) == 0 {
		http.Error(w, "node ids are required", 400)
		return
	}
	ids := make(map[string]bool, len(v.IDs))
	for _, id := range v.IDs {
		ids[id] = true
	}
	updated := 0
	for i := range s.Nodes {
		if ids[s.Nodes[i].ID] {
			s.Nodes[i].Enabled = v.Enabled
			updated++
		}
	}
	if updated == 0 {
		http.Error(w, "nodes not found", 404)
		return
	}
	if err := persistStore(s, true); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"updated": updated, "enabled": v.Enabled})
}

func apiNodeBatchDelete(w http.ResponseWriter, r *http.Request, s Store) {
	if r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var v struct{ IDs []string }
	if decodeJSONBody(r, &v) != nil || len(v.IDs) == 0 {
		http.Error(w, "node ids are required", 400)
		return
	}
	ids := map[string]bool{}
	for _, id := range v.IDs {
		ids[id] = true
	}
	before := len(s.Nodes)
	kept := s.Nodes[:0]
	for _, n := range s.Nodes {
		if !ids[n.ID] {
			kept = append(kept, n)
		}
	}
	s.Nodes = kept
	if len(s.Nodes) == before {
		http.Error(w, "nodes not found", 404)
		return
	}
	if err := persistStore(s, true); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(s)
}

func apiNodeReorder(w http.ResponseWriter, r *http.Request, s Store) {
	if r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var v struct{ IDs []string }
	if decodeJSONBody(r, &v) != nil || len(v.IDs) == 0 {
		http.Error(w, "node ids are required", 400)
		return
	}
	byID := map[string]Node{}
	for _, n := range s.Nodes {
		byID[n.ID] = n
	}
	ordered := make([]Node, 0, len(s.Nodes))
	for _, id := range v.IDs {
		if n, ok := byID[id]; ok {
			n.SortOrder = len(ordered)
			ordered = append(ordered, n)
			delete(byID, id)
		}
	}
	for _, n := range s.Nodes {
		if rest, ok := byID[n.ID]; ok {
			rest.SortOrder = len(ordered)
			ordered = append(ordered, rest)
		}
	}
	s.Nodes = ordered
	if err := persistStore(s, true); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(s)
}

func apiNodeSelect(w http.ResponseWriter, r *http.Request, s Store) {
	if r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var v struct{ ID string }
	if err := decodeJSONBody(r, &v); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	found := false
	for _, n := range s.Nodes {
		if n.ID == v.ID && n.Enabled {
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "node not found", 404)
		return
	}
	s.SelectedNode = v.ID
	if err := persistStore(s, true); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(s)
}

func apiNodeImport(w http.ResponseWriter, r *http.Request, s Store) {
	if r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var v struct{ Links string }
	if decodeJSONBody(r, &v) != nil {
		http.Error(w, "invalid body", 400)
		return
	}
	nodes := parseSubscription(v.Links)
	if len(nodes) == 0 {
		http.Error(w, "no supported links", http.StatusUnprocessableEntity)
		return
	}
	for i := range nodes {
		nodes[i].SubscriptionID = ""
		if err := validateNode(&nodes[i]); err != nil {
			http.Error(w, fmt.Sprintf("invalid imported node: %v", err), http.StatusUnprocessableEntity)
			return
		}
	}
	s.Nodes = append(s.Nodes, nodes...)
	if err := persistStore(s, true); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"imported": len(nodes)})
}

func runSingleNodeTest(n Node, method, customURL string) (int64, error) {
	host := strings.TrimSpace(n.Server)
	if host == "" {
		return 0, fmt.Errorf("empty host")
	}
	start := time.Now()
	switch method {
	case "ping":
		if strings.HasPrefix(host, "-") {
			return 0, fmt.Errorf("invalid host")
		}
		out, err := runCommandTimeout(3*time.Second, "ping", "-c", "1", "-W", "2", host)
		if err != nil {
			return 0, fmt.Errorf("ping failed: %s", strings.TrimSpace(string(out)))
		}
		return time.Since(start).Milliseconds(), nil
	case "tcp":
		port := n.Port
		if port <= 0 || port > 65535 {
			return 0, fmt.Errorf("invalid port %d", port)
		}
		addr := net.JoinHostPort(host, strconv.Itoa(port))
		d := net.Dialer{Timeout: 3 * time.Second}
		conn, err := d.Dial("tcp", addr)
		if err != nil {
			return 0, err
		}
		_ = conn.Close()
		return time.Since(start).Milliseconds(), nil
	case "urltest":
		targetURL := customURL
		if targetURL == "" {
			targetURL = "https://www.gstatic.com/generate_204"
		}
		delay, err := clashDelay(n.ID, targetURL)
		if err != nil {
			return 0, err
		}
		return delay, nil
	default:
		return 0, fmt.Errorf("invalid method")
	}
}
