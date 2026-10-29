package main

import (
	"fmt"
	"log"
)

func migrateLegacy(s Store) Store {
	if len(s.Subscriptions) == 0 {
		for i, u := range s.SubscriptionURLs {
			s.Subscriptions = append(s.Subscriptions, Subscription{ID: fmt.Sprintf("subsrc-%d", i+1), Name: fmt.Sprintf("订阅 %d", i+1), URL: u, UpdateHours: 6, Enabled: true})
		}
	}
	for i := range s.Nodes {
		s.Nodes[i].Enabled = true
		if s.Nodes[i].SubscriptionID == "" && len(s.Subscriptions) > 0 && len(s.SubscriptionURLs) > 0 && len(s.Nodes[i].ID) >= 4 && s.Nodes[i].ID[:4] == "sub-" {
			s.Nodes[i].SubscriptionID = s.Subscriptions[0].ID
			s.Nodes[i].Group = s.Subscriptions[0].Name
		}
		s.Nodes[i].SortOrder = i
	}
	return s
}

func normalizeStore(s *Store) {
	normalizeRuleSettings(s)
	ensureDefaultBool(&s.AdBlockEnabled, true)
	if err := assignNaivePorts(s); err != nil {
		log.Printf("assignNaivePorts warning: %v", err)
	}
	if s.SchemaVersion < 1 {
		for i := range s.StrategyGroups {
			if s.StrategyGroups[i].Type == "fallback" {
				s.StrategyGroups[i].Type = "urltest"
			}
		}
		s.SchemaVersion = 1
	}
	s.SubscriptionURLs = s.SubscriptionURLs[:0]
	for _, sub := range s.Subscriptions {
		s.SubscriptionURLs = append(s.SubscriptionURLs, sub.URL)
	}
	selectedOK := false
	existingNodes := make(map[string]bool, len(s.Nodes))
	for i := range s.Nodes {
		s.Nodes[i].SortOrder = i
		existingNodes[s.Nodes[i].ID] = true
		if s.Nodes[i].ID == s.SelectedNode && s.Nodes[i].Enabled {
			selectedOK = true
		}
	}
	existingOutbounds := map[string]bool{"direct": true}
	for id := range existingNodes {
		existingOutbounds[id] = true
	}
	for i := range s.StrategyGroups {
		group := &s.StrategyGroups[i]
		kept := group.NodeIDs[:0]
		seen := map[string]bool{}
		for _, id := range group.NodeIDs {
			if existingNodes[id] && !seen[id] {
				kept = append(kept, id)
				seen[id] = true
			}
		}
		group.NodeIDs = kept
		if !seen[group.Selected] {
			group.Selected = ""
			if len(group.NodeIDs) > 0 {
				group.Selected = group.NodeIDs[0]
			}
		}
		existingOutbounds[group.ID] = true
	}
	if !existingOutbounds[s.TCPOutbound] {
		s.TCPOutbound = ""
	}
	if s.UDPOutbound != "same" && !existingOutbounds[s.UDPOutbound] {
		s.UDPOutbound = ""
	}
	for i := range s.ACLRules {
		if !existingOutbounds[s.ACLRules[i].Outbound] && s.ACLRules[i].Outbound != "block" {
			s.ACLRules[i].Enabled = false
		}
	}
	if selectedOK {
		return
	}
	s.SelectedNode = ""
	for _, node := range s.Nodes {
		if node.Enabled {
			s.SelectedNode = node.ID
			break
		}
	}
}
