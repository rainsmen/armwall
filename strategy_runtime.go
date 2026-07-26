package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type strategyRuntimeStatus struct {
	ID           string           `json:"id"`
	Available    bool             `json:"available"`
	Selected     string           `json:"selected,omitempty"`
	DelayMS      int64            `json:"delay_ms,omitempty"`
	MemberDelays map[string]int64 `json:"member_delays,omitempty"`
}

type clashProxyInfo struct {
	Now     string `json:"now"`
	History []struct {
		Delay int64 `json:"delay"`
	} `json:"history"`
}

var clashAPIBase = "http://127.0.0.1:9090"

func latestClashDelay(proxy clashProxyInfo) int64 {
	for i := len(proxy.History) - 1; i >= 0; i-- {
		if proxy.History[i].Delay > 0 {
			return proxy.History[i].Delay
		}
	}
	return 0
}

func strategyRuntimeStatuses(s Store) []strategyRuntimeStatus {
	statuses := make([]strategyRuntimeStatus, 0, len(s.StrategyGroups))
	for _, group := range s.StrategyGroups {
		statuses = append(statuses, strategyRuntimeStatus{ID: group.ID, MemberDelays: map[string]int64{}})
	}
	if len(statuses) == 0 {
		return statuses
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(clashAPIBase + "/proxies")
	if err != nil {
		return statuses
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return statuses
	}
	var response struct {
		Proxies map[string]clashProxyInfo `json:"proxies"`
	}
	if json.NewDecoder(resp.Body).Decode(&response) != nil {
		return statuses
	}
	for i, group := range s.StrategyGroups {
		proxy, ok := response.Proxies[group.ID]
		if !ok {
			continue
		}
		statuses[i].Available = true
		statuses[i].Selected = proxy.Now
		statuses[i].DelayMS = latestClashDelay(proxy)
		for _, member := range group.NodeIDs {
			if info, exists := response.Proxies[member]; exists {
				statuses[i].MemberDelays[member] = latestClashDelay(info)
			}
		}
		if statuses[i].DelayMS == 0 && proxy.Now != "" {
			statuses[i].DelayMS = statuses[i].MemberDelays[proxy.Now]
		}
	}
	return statuses
}

func clashDelay(tag, testURL string) (int64, error) {
	if testURL == "" {
		testURL = "https://www.gstatic.com/generate_204"
	}
	endpoint := clashAPIBase + "/proxies/" + url.PathEscape(tag) + "/delay?url=" + url.QueryEscape(testURL) + "&timeout=10000"
	client := &http.Client{Timeout: 12 * time.Second}
	resp, err := client.Get(endpoint)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	var result struct {
		Delay int64 `json:"delay"`
		MS    int64 `json:"ms"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("invalid urltest response")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("urltest failed: %d", resp.StatusCode)
	}
	if result.MS <= 0 {
		result.MS = result.Delay
	}
	if result.MS <= 0 {
		return 0, fmt.Errorf("urltest returned no delay")
	}
	return result.MS, nil
}
