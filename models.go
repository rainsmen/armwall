package main

import (
	"time"
)

type Node struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Type             string `json:"type"`
	Server           string `json:"server"`
	UUID             string `json:"uuid"`
	Password         string `json:"password"`
	Port             int    `json:"port"`
	TLS              bool   `json:"tls"`
	ServerName       string `json:"server_name"`
	Insecure         bool   `json:"insecure"`
	Username         string `json:"username"`
	Method           string `json:"method"`
	Security         string `json:"security"`
	AlterID          int    `json:"alter_id"`
	Flow             string `json:"flow"`
	Transport        string `json:"transport"`
	Host             string `json:"host"`
	Path             string `json:"path"`
	ServiceName      string `json:"service_name"`
	ALPN             string `json:"alpn"`
	Fingerprint      string `json:"fingerprint"`
	RealityPublicKey string `json:"reality_public_key"`
	RealityShortID   string `json:"reality_short_id"`
	Obfs             string `json:"obfs"`
	ObfsPassword     string `json:"obfs_password"`
	UpMbps           int    `json:"up_mbps"`
	DownMbps         int    `json:"down_mbps"`
	Plugin           string `json:"plugin"`
	PluginOpts       string `json:"plugin_opts"`
	Group            string `json:"group"`
	SubscriptionID   string `json:"subscription_id"`
	Enabled          bool   `json:"enabled"`
	SortOrder        int    `json:"sort_order"`
	NameOverride     string `json:"name_override,omitempty"`
	GroupOverride    string `json:"group_override,omitempty"`
	NaivePort        int    `json:"naive_port,omitempty"`
}

type StrategyGroup struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	NodeIDs     []string `json:"node_ids"`
	Selected    string   `json:"selected"`
	TestURL     string   `json:"test_url"`
	IntervalSec int      `json:"interval_sec"`
	ToleranceMS int      `json:"tolerance_ms"`
}

type ACLRule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Enabled     bool     `json:"enabled"`
	SourceCIDRs []string `json:"source_cidrs"`
	SourceMACs  []string `json:"source_macs"`
	Network     string   `json:"network"`
	PortRanges  []string `json:"port_ranges"`
	Outbound    string   `json:"outbound"`
}

type macACLBinding struct {
	ACLID      string
	Tag        string
	Port       int
	MACs       []string
	Network    string
	PortRanges []string
	Outbound   string
}

type naiveBinding struct {
	Node   Node
	Port   int
	Config string
}

type DNSSettings struct {
	Enabled       bool   `json:"enabled"`
	ListenAddress string `json:"listen_address"`
	ListenPort    int    `json:"listen_port"`
	RemoteServer  string `json:"remote_server"`
	RemoteSNI     string `json:"remote_sni"`
	DirectServer  string `json:"direct_server"`
	Strategy      string `json:"strategy"`
	Hijack        bool   `json:"hijack"`
	FakeIP        bool   `json:"fake_ip"`
}

type RuleUpdateSetting struct {
	BackupURL   string    `json:"backup_url"`
	AutoUpdate  bool      `json:"auto_update"`
	UpdateHours int       `json:"update_hours"`
	LastUpdated time.Time `json:"last_updated"`
}

type Store struct {
	Revision         int64                        `json:"revision,omitempty"`
	SchemaVersion    int                          `json:"schema_version,omitempty"`
	Nodes            []Node                       `json:"nodes"`
	SubscriptionURLs []string                     `json:"subscription_urls"`
	Mode             string                       `json:"mode"`
	ProxyPort        int                          `json:"proxy_port"`
	SelectedNode     string                       `json:"selected_node"`
	UpdateHours      int                          `json:"update_hours"`
	LogLevel         string                       `json:"log_level"`
	RuleUpdateHours  int                          `json:"rule_update_hours"`
	RuleBackups      map[string]string            `json:"rule_backups"`
	RuleSettings     map[string]RuleUpdateSetting `json:"rule_settings"`
	Subscriptions    []Subscription               `json:"subscriptions"`
	StrategyGroups   []StrategyGroup              `json:"strategy_groups"`
	TCPOutbound      string                       `json:"tcp_outbound"`
	UDPOutbound      string                       `json:"udp_outbound"`
	ACLRules         []ACLRule                    `json:"acl_rules"`
	DNS              DNSSettings                  `json:"dns"`
	AdBlockEnabled   *bool                        `json:"ad_block_enabled,omitempty"`
}
