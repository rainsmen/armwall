package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func apiSubscriptionUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if err := updateSubscriptionsWithForceContext(r.Context(), true); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"updated": true})
}

func apiSubscriptionUpdateOne(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var v struct{ ID string }
	if decodeJSONBody(r, &v) != nil || v.ID == "" {
		http.Error(w, "subscription id is required", 400)
		return
	}
	s, err := loadAPIStoreSnapshot()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	var sub *Subscription
	for i := range s.Subscriptions {
		if s.Subscriptions[i].ID == v.ID {
			sub = &s.Subscriptions[i]
			break
		}
	}
	if sub == nil {
		http.Error(w, "subscription not found", 404)
		return
	}
	targetURL := sub.URL
	fetchStart := time.Now()
	nodes, err := fetchSubscriptionFn(r.Context(), targetURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if len(nodes) == 0 {
		http.Error(w, "subscription contains no supported nodes", http.StatusUnprocessableEntity)
		return
	}
	mu.Lock()
	if err := r.Context().Err(); err != nil {
		mu.Unlock()
		http.Error(w, err.Error(), 499)
		return
	}
	persistErr := withStoreFileLockContext(r.Context(), func() error {
		current, loadErr := loadStore()
		if loadErr != nil {
			return loadErr
		}
		var curSub *Subscription
		for i := range current.Subscriptions {
			if current.Subscriptions[i].ID == v.ID {
				curSub = &current.Subscriptions[i]
				break
			}
		}
		if curSub == nil {
			return fmt.Errorf("subscription not found")
		}
		if curSub.URL != targetURL {
			return fmt.Errorf("subscription URL changed during fetch")
		}
		if !curSub.LastUpdated.IsZero() && curSub.LastUpdated.After(fetchStart) {
			return fmt.Errorf("subscription was updated by another request")
		}
		nodes = reconcileSubscriptionNodes(current.Nodes, nodes, *curSub)
		current.Nodes = replaceSubscriptionNodes(current.Nodes, v.ID, nodes)
		curSub.LastUpdated = time.Now()
		return persistStore(current, true)
	})
	mu.Unlock()
	if persistErr != nil {
		http.Error(w, persistErr.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"updated": v.ID, "nodes": len(nodes)})
}

func apiSubscription(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var v struct {
		ID          string `json:"id"`
		URL         string `json:"url"`
		Name        string `json:"name"`
		UpdateHours int    `json:"update_hours"`
		Enabled     *bool  `json:"enabled"`
		LastUpdated any    `json:"last_updated"`
	}
	if decodeJSONBody(r, &v) != nil || !strings.HasPrefix(strings.TrimSpace(v.URL), "https://") {
		http.Error(w, "invalid url", 400)
		return
	}
	v.URL = strings.TrimSpace(v.URL)
	fetchStart := time.Now()
	nodes, err := fetchSubscriptionFn(r.Context(), v.URL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if len(nodes) == 0 {
		http.Error(w, "subscription contains no supported nodes", http.StatusUnprocessableEntity)
		return
	}
	mu.Lock()
	if err := r.Context().Err(); err != nil {
		mu.Unlock()
		http.Error(w, err.Error(), 499)
		return
	}
	persistErr := withStoreFileLockContext(r.Context(), func() error {
		s, loadErr := loadStore()
		if loadErr != nil {
			return loadErr
		}
		var sub *Subscription
		for i := range s.Subscriptions {
			if s.Subscriptions[i].URL == v.URL {
				sub = &s.Subscriptions[i]
				break
			}
		}
		if sub == nil {
			name := strings.TrimSpace(v.Name)
			if name == "" {
				name = fmt.Sprintf("订阅 %d", len(s.Subscriptions)+1)
			}
			hours := v.UpdateHours
			if hours < 1 || hours > 168 {
				hours = 6
			}
			subEnabled := true
			if v.Enabled != nil {
				subEnabled = *v.Enabled
			}
			s.Subscriptions = append(s.Subscriptions, Subscription{ID: fmt.Sprintf("subsrc-%d", time.Now().UnixNano()), Name: name, URL: v.URL, UpdateHours: hours, Enabled: subEnabled})
			sub = &s.Subscriptions[len(s.Subscriptions)-1]
		} else if !sub.LastUpdated.IsZero() && sub.LastUpdated.After(fetchStart) {
			return fmt.Errorf("subscription was updated by another request")
		}
		nodes = reconcileSubscriptionNodes(s.Nodes, nodes, *sub)
		sub.LastUpdated = time.Now()
		s.Nodes = replaceSubscriptionNodes(s.Nodes, sub.ID, nodes)
		return persistStore(s, true)
	})
	mu.Unlock()
	if persistErr != nil {
		http.Error(w, persistErr.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"imported": len(nodes)})
}

func apiSubscriptionClear(w http.ResponseWriter, r *http.Request, s Store) {
	if r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	kept := s.Nodes[:0]
	for _, n := range s.Nodes {
		if n.SubscriptionID == "" {
			kept = append(kept, n)
		}
	}
	s.Nodes = kept
	s.SubscriptionURLs = nil
	s.Subscriptions = nil
	if err := persistStore(s, true); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"cleared": true})
}

func apiSubscriptionEdit(w http.ResponseWriter, r *http.Request, s Store) {
	if r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var v Subscription
	if decodeJSONBody(r, &v) != nil || v.ID == "" || !strings.HasPrefix(v.URL, "https://") {
		http.Error(w, "invalid subscription", 400)
		return
	}
	v.Name = strings.TrimSpace(v.Name)
	if v.Name == "" || v.UpdateHours < 1 || v.UpdateHours > 168 {
		http.Error(w, "name and update interval 1-168 are required", 400)
		return
	}
	for _, sub := range s.Subscriptions {
		if sub.ID != v.ID && sub.URL == v.URL {
			http.Error(w, "subscription url already exists", http.StatusConflict)
			return
		}
	}
	found := false
	for i := range s.Subscriptions {
		if s.Subscriptions[i].ID == v.ID {
			oldName := s.Subscriptions[i].Name
			if v.LastUpdated.IsZero() {
				v.LastUpdated = s.Subscriptions[i].LastUpdated
			}
			s.Subscriptions[i] = v
			for j := range s.Nodes {
				if s.Nodes[j].SubscriptionID == v.ID && s.Nodes[j].Group == oldName && s.Nodes[j].GroupOverride == "" {
					s.Nodes[j].Group = v.Name
				}
			}
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "subscription not found", 404)
		return
	}
	if err := persistStore(s, false); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(v)
}

func apiSubscriptionDelete(w http.ResponseWriter, r *http.Request, s Store) {
	if r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var v struct{ ID string }
	if decodeJSONBody(r, &v) != nil || v.ID == "" {
		http.Error(w, "subscription id is required", 400)
		return
	}
	before := len(s.Subscriptions)
	subs := s.Subscriptions[:0]
	for _, sub := range s.Subscriptions {
		if sub.ID != v.ID {
			subs = append(subs, sub)
		}
	}
	s.Subscriptions = subs
	if len(s.Subscriptions) == before {
		http.Error(w, "subscription not found", 404)
		return
	}
	nodes := s.Nodes[:0]
	for _, n := range s.Nodes {
		if n.SubscriptionID != v.ID {
			nodes = append(nodes, n)
		}
	}
	s.Nodes = nodes
	if err := persistStore(s, true); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(s)
}

func apiSubscriptionToggle(w http.ResponseWriter, r *http.Request, s Store) {
	if r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var v struct {
		ID      string
		Enabled bool
	}
	if decodeJSONBody(r, &v) != nil || v.ID == "" {
		http.Error(w, "subscription id is required", 400)
		return
	}
	found := false
	for i := range s.Subscriptions {
		if s.Subscriptions[i].ID == v.ID {
			s.Subscriptions[i].Enabled = v.Enabled
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "subscription not found", 404)
		return
	}
	if err := persistStore(s, false); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(s)
}

func apiSubscriptionSchedule(w http.ResponseWriter, r *http.Request, s Store) {
	if r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var v struct{ Hours int }
	if decodeJSONBody(r, &v) != nil || v.Hours < 1 || v.Hours > 168 {
		http.Error(w, "hours must be 1-168", 400)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"accepted": true, "schedule": "per-subscription", "hours": v.Hours})
}
