package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

func apiStrategyStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	s, err := loadAPIStoreSnapshot()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"groups": strategyRuntimeStatuses(s)})
}

func apiStrategyTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var request struct{ ID string }
	if decodeJSONBody(r, &request) != nil || request.ID == "" {
		http.Error(w, "strategy id is required", http.StatusBadRequest)
		return
	}
	s, err := loadAPIStoreSnapshot()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var group *StrategyGroup
	for i := range s.StrategyGroups {
		if s.StrategyGroups[i].ID == request.ID {
			group = &s.StrategyGroups[i]
			break
		}
	}
	if group == nil {
		http.Error(w, "strategy not found", http.StatusNotFound)
		return
	}
	delay, err := clashDelay(group.ID, group.TestURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"id": group.ID, "ms": delay})
}

func apiStrategy(w http.ResponseWriter, r *http.Request, s Store) {
	if r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var group StrategyGroup
	if decodeJSONBody(r, &group) != nil {
		http.Error(w, "invalid strategy", 400)
		return
	}
	creating := group.ID == ""
	if creating {
		group.ID = fmt.Sprintf("strategy-%d", time.Now().UnixNano())
	}
	if group.ID == "direct" || group.ID == "block" {
		http.Error(w, "reserved strategy id", 400)
		return
	}
	if err := validateStrategyGroup(&group, s); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if creating {
		s.StrategyGroups = append(s.StrategyGroups, group)
	} else {
		index := -1
		for i := range s.StrategyGroups {
			if s.StrategyGroups[i].ID == group.ID {
				index = i
				break
			}
		}
		if index < 0 {
			http.Error(w, "strategy not found", 404)
			return
		}
		s.StrategyGroups[index] = group
	}
	if err := persistStore(s, true); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(group)
}

func apiStrategyDelete(w http.ResponseWriter, r *http.Request, s Store) {
	if r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var v struct{ ID string }
	if decodeJSONBody(r, &v) != nil || v.ID == "" {
		http.Error(w, "strategy id is required", 400)
		return
	}
	before := len(s.StrategyGroups)
	kept := s.StrategyGroups[:0]
	for _, group := range s.StrategyGroups {
		if group.ID != v.ID {
			kept = append(kept, group)
		}
	}
	s.StrategyGroups = kept
	if len(s.StrategyGroups) == before {
		http.Error(w, "strategy not found", 404)
		return
	}
	if err := persistStore(s, true); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(s)
}

func apiStrategySelect(w http.ResponseWriter, r *http.Request, s Store) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var request struct{ ID, NodeID string }
	if decodeJSONBody(r, &request) != nil || request.ID == "" || request.NodeID == "" {
		http.Error(w, "strategy and node ids are required", http.StatusBadRequest)
		return
	}
	found := false
	for i := range s.StrategyGroups {
		group := &s.StrategyGroups[i]
		if group.ID != request.ID || group.Type != "selector" {
			continue
		}
		for _, member := range group.NodeIDs {
			if member == request.NodeID {
				group.Selected = request.NodeID
				found = true
				break
			}
		}
	}
	if !found {
		http.Error(w, "selector or member not found", http.StatusNotFound)
		return
	}
	if err := persistStore(s, true); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(s)
}
