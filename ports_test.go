package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"
)

func TestNaivePortsRemainStableAcrossReorderAndAddition(t *testing.T) {
	s := Store{Nodes: []Node{
		{ID: "naive-a", Type: "naive", Server: "a.example", Port: 443, Enabled: true, NaivePort: 12000},
		{ID: "naive-b", Type: "naive", Server: "b.example", Port: 443, Enabled: true, NaivePort: 12001},
	}}
	first := naiveBindings(s)
	reordered := Store{Nodes: []Node{s.Nodes[1], s.Nodes[0], {ID: "naive-c", Type: "naive", Server: "c.example", Port: 443, Enabled: true}}}
	second := naiveBindings(reordered)
	ports := make(map[string]int)
	for _, binding := range second {
		ports[binding.Node.ID] = binding.Port
	}
	if ports["naive-a"] != first[0].Port || ports["naive-b"] != first[1].Port || ports["naive-c"] != 12002 {
		t.Fatalf("ports changed or new port collided: first=%+v second=%+v", first, second)
	}
}

func TestNaivePortAllocationSkipsExistingRuntimeListeners(t *testing.T) {
	oldNaiveProxyPort := naiveProxyPort
	naiveProxyPort = 12000
	t.Cleanup(func() { naiveProxyPort = oldNaiveProxyPort })
	s := Store{ProxyPort: 12000, Nodes: []Node{{ID: "naive-a", Type: "naive", Server: "a.example", Port: 443, Enabled: true}}}
	if err := assignNaivePorts(&s); err != nil {
		t.Fatal(err)
	}
	if s.Nodes[0].NaivePort != 12001 {
		t.Fatalf("allocated port=%d, want next free port 12001", s.Nodes[0].NaivePort)
	}
}

func TestValidateRuntimePortsDoesNotSilentlyRemapPersistedConflict(t *testing.T) {
	oldTProxyPort, oldNaiveProxyPort := tproxyPort, naiveProxyPort
	t.Cleanup(func() { tproxyPort, naiveProxyPort = oldTProxyPort, oldNaiveProxyPort })
	tproxyPort = 11081
	naiveProxyPort = 12000
	s := Store{ProxyPort: 12000, Nodes: []Node{{ID: "naive-a", Type: "naive", Server: "a.example", Port: 443, Enabled: true, NaivePort: 12000}}}
	if err := validateRuntimePorts(s); err == nil {
		t.Fatal("expected persisted Naive/Proxy collision to be rejected")
	}
	if s.Nodes[0].NaivePort != 12000 {
		t.Fatalf("persisted port was silently remapped: %d", s.Nodes[0].NaivePort)
	}
}

func TestProxyPortAPIUsesTransactionalReload(t *testing.T) {
	setupAPITest(t, Store{Mode: "global", ProxyPort: 11080, Nodes: []Node{{ID: "n1", Name: "node", Type: "anytls", Server: "example.com", Port: 443, Password: "secret", TLS: true, Enabled: true}}})
	recorder := callAPI(t, "/api/settings", `{"proxyPort":12080}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if got := load().ProxyPort; got != 12080 {
		t.Fatalf("stored proxy port=%d, want 12080", got)
	}
	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var generated map[string]any
	if json.Unmarshal(configBytes, &generated) != nil {
		t.Fatalf("invalid generated config: %s", configBytes)
	}
	inbounds := generated["inbounds"].([]any)
	if inbounds[0].(map[string]any)["listen_port"] != float64(12080) {
		t.Fatalf("runtime config did not use new port: %+v", inbounds[0])
	}
}

func TestSettingsAPIRejectsConflictingPorts(t *testing.T) {
	setupAPITest(t, Store{Mode: "global", ProxyPort: 11080})
	for _, port := range []int{8080, 9090, 11081, 53, 22} {
		recorder := callAPI(t, "/api/settings", fmt.Sprintf(`{"proxyPort":%d}`, port))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for conflicting port %d, got %d", port, recorder.Code)
		}
	}
}

func TestValidateRuntimePortsRejectsGeneratedListenerConflicts(t *testing.T) {
	oldTProxyPort, oldNaiveProxyPort := tproxyPort, naiveProxyPort
	t.Cleanup(func() { tproxyPort, naiveProxyPort = oldTProxyPort, oldNaiveProxyPort })

	tproxyPort = 12000
	naiveProxyPort = 13000
	if err := validateRuntimePorts(Store{ProxyPort: 12000}); err == nil {
		t.Fatal("expected proxy/TProxy conflict")
	}

	tproxyPort = 12000
	naiveProxyPort = 12001
	s := Store{
		ProxyPort: 11080,
		ACLRules:  []ACLRule{{Enabled: true, SourceMACs: []string{"00:11:22:33:44:55"}}},
		Nodes:     []Node{{Type: "naive", Enabled: true, Server: "example.com", Port: 443, NaivePort: 12001}},
	}
	if err := validateRuntimePorts(s); err == nil {
		t.Fatal("expected NaiveProxy/MAC ACL derived port conflict")
	}
}

func TestValidateRuntimePortsCoversWebDNSAndClash(t *testing.T) {
	oldAccess, oldListen := os.Getenv("ARMWALL_WEB_ACCESS"), os.Getenv("ARMWALL_LISTEN")
	t.Cleanup(func() {
		os.Setenv("ARMWALL_WEB_ACCESS", oldAccess)
		os.Setenv("ARMWALL_LISTEN", oldListen)
	})
	os.Setenv("ARMWALL_WEB_ACCESS", "custom")
	os.Setenv("ARMWALL_LISTEN", "127.0.0.1:9090")
	if err := validateRuntimePorts(Store{ProxyPort: 11080}); err == nil {
		t.Fatal("expected Web/Clash conflict")
	}
	os.Setenv("ARMWALL_LISTEN", "127.0.0.1:18080")
	if err := validateRuntimePorts(Store{ProxyPort: 11080, DNS: DNSSettings{Enabled: true, ListenAddress: "127.0.0.1", ListenPort: 11080}}); err == nil {
		t.Fatal("expected DNS/Mixed conflict")
	}
}

func TestProxyPortConcurrentAccess(t *testing.T) {
	oldPort := getProxyPort()
	defer setProxyPort(oldPort)

	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					p := getProxyPort()
					if p <= 0 {
						t.Errorf("invalid port read: %d", p)
					}
					_ = config(Store{Mode: "global", ProxyPort: p})
				}
			}
		}()
	}

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					setProxyPort(1080 + (id % 100))
					time.Sleep(time.Millisecond)
				}
			}
		}(i)
	}

	wg.Wait()
}
