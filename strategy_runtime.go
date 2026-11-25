package main

import (
	"bytes"
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

func clashRequest(method, path string) (*http.Request, error) {
	req, err := http.NewRequest(method, clashAPIBase+path, nil)
	if err != nil {
		return nil, err
	}
	if secret := currentClashAPISecret(); secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	return req, nil
}

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
	req, err := clashRequest(http.MethodGet, "/proxies")
	if err != nil {
		return statuses
	}
	resp, err := client.Do(req)
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
	return clashDelayTimeout(tag, testURL, 10*time.Second)
}

func clashDelayTimeout(tag, testURL string, timeout time.Duration) (int64, error) {
	if testURL == "" {
		testURL = "https://www.gstatic.com/generate_204"
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	timeoutMS := timeout.Milliseconds()
	if timeoutMS < 1000 {
		timeoutMS = 1000
	}
	endpoint := fmt.Sprintf("%s/proxies/%s/delay?url=%s&timeout=%d", clashAPIBase, url.PathEscape(tag), url.QueryEscape(testURL), timeoutMS)
	client := &http.Client{Timeout: timeout + 2*time.Second}
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, err
	}
	if secret := currentClashAPISecret(); secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("urltest failed: %d", resp.StatusCode)
	}
	var result struct {
		Delay int64 `json:"delay"`
		MS    int64 `json:"ms"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("invalid urltest response")
	}
	if result.MS <= 0 {
		result.MS = result.Delay
	}
	if result.MS <= 0 {
		return 0, fmt.Errorf("urltest returned no delay")
	}
	return result.MS, nil
}

func clashProxyNow(tag string) (string, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	req, err := clashRequest(http.MethodGet, "/proxies/"+url.PathEscape(tag))
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("clash proxy lookup failed: %d", resp.StatusCode)
	}
	var info clashProxyInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return "", err
	}
	return info.Now, nil
}

func clashSelectProxy(groupTag, targetTag string) error {
	body, err := json.Marshal(map[string]string{"name": targetTag})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPut, clashAPIBase+"/proxies/"+url.PathEscape(groupTag), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if secret := currentClashAPISecret(); secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("clash select proxy failed: %d", resp.StatusCode)
	}
	return nil
}
