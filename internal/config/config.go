// Package config holds paths and the user configuration (~/.xmon/config.yaml).
package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Mode is the global intervention level (inherited from cc-monitor).
type Mode string

const (
	ModeActive  Mode = "active"  // decide and enforce
	ModePaused  Mode = "paused"  // decide and record, never block or prompt
	ModeStopped Mode = "stopped" // don't intervene or record
)

// GLM configures the semantic audit engine.
type GLM struct {
	Enabled         bool    `yaml:"enabled"`
	Endpoint        string  `yaml:"endpoint"` // OpenAI-compatible base URL
	Model           string  `yaml:"model"`
	APIKeyEnv       string  `yaml:"api_key_env"`
	TimeoutMS       int     `yaml:"timeout_ms"`
	Redact          bool    `yaml:"redact"`
	DisableThinking bool    `yaml:"disable_thinking"`
	MinConfidence   float64 `yaml:"min_confidence"`
	ReviewUnmatched bool    `yaml:"review_unmatched"` // also send rule-less exec.shell calls
}

// Config is the user configuration.
type Config struct {
	Mode      Mode   `yaml:"mode"`
	UIAddr    string `yaml:"ui_addr"`
	ProxyAddr string `yaml:"proxy_addr"`
	Proxy     struct {
		FailOpen     bool              `yaml:"fail_open"`
		DLPAction    string            `yaml:"dlp_action"` // alert | redact
		Routes       map[string]string `yaml:"routes"`
		ConfirmPingS int               `yaml:"confirm_ping_s"`
	} `yaml:"proxy"`
	GLM      GLM `yaml:"glm"`
	Approval struct {
		TimeoutS      int  `yaml:"timeout_s"`
		DesktopNotify bool `yaml:"desktop_notify"`
	} `yaml:"approval"`
	Storage struct {
		RetentionDays int   `yaml:"retention_days"`
		MaxEvents     int64 `yaml:"max_events"`
	} `yaml:"storage"`
	Probe struct {
		Enabled string `yaml:"enabled"` // auto | off
		Enforce bool   `yaml:"enforce"` // L1 kernel-level blocking (future)
	} `yaml:"probe"`
	Usage struct {
		// AnthropicEnabled lets the daemon read Claude Code's local OAuth token and ask
		// Anthropic how much of the plan quota is used (see internal/usage). On by default;
		// set it to false to make no such request.
		AnthropicEnabled bool `yaml:"anthropic_enabled"`
	} `yaml:"usage"`
}

// DefaultRoutes maps provider ids to upstream base URLs.
var DefaultRoutes = map[string]string{
	"anthropic":     "https://api.anthropic.com",
	"openai":        "https://api.openai.com/v1",
	"zai":           "https://api.z.ai/api/paas/v4",
	"zai-anthropic": "https://api.z.ai/api/anthropic",
	// Z.ai's CLI is Gemini CLI pointed at this Gemini-compatible endpoint.
	"zai-gemini": "https://api.z.ai/api/geminiv1beta",
	"gemini":     "https://generativelanguage.googleapis.com",
	"google":     "https://generativelanguage.googleapis.com",
	"bigmodel":   "https://open.bigmodel.cn/api/paas/v4",
	"deepseek":   "https://api.deepseek.com",
	"openrouter": "https://openrouter.ai/api/v1",
}

// Default returns the default configuration.
func Default() *Config {
	c := &Config{Mode: ModeActive, UIAddr: "127.0.0.1:7788", ProxyAddr: "127.0.0.1:7789"}
	c.Proxy.DLPAction = "alert"
	c.Proxy.ConfirmPingS = 10
	c.Proxy.Routes = map[string]string{}
	c.GLM = GLM{
		Enabled:         false, // cloud analysis is opt-in (DESIGN.md §12.6)
		Endpoint:        "https://api.z.ai/api/paas/v4",
		Model:           "glm-4.5",
		APIKeyEnv:       "ZAI_API_KEY",
		TimeoutMS:       3000,
		Redact:          true,
		DisableThinking: true,
		MinConfidence:   0.85,
	}
	c.Approval.TimeoutS = 90
	c.Approval.DesktopNotify = true
	c.Storage.RetentionDays = 30
	c.Storage.MaxEvents = 1_000_000
	c.Probe.Enabled = "auto"
	c.Usage.AnthropicEnabled = true
	return c
}

// Home is the data directory ($XMON_HOME or ~/.xmon).
func Home() string {
	if h := os.Getenv("XMON_HOME"); h != "" {
		return h
	}
	h, err := os.UserHomeDir()
	if err != nil {
		h = "."
	}
	return filepath.Join(h, ".xmon")
}

// Paths under Home.
func ConfigPath() string { return filepath.Join(Home(), "config.yaml") }
func DBPath() string     { return filepath.Join(Home(), "events.db") }
func SocketPath() string { return filepath.Join(Home(), "xmond.sock") }
func TokenPath() string  { return filepath.Join(Home(), "token") }
func SpoolDir() string   { return filepath.Join(Home(), "spool") }
func LogPath() string    { return filepath.Join(Home(), "xmond.log") }
func PIDPath() string    { return filepath.Join(Home(), "xmond.pid") }

// EnsureHome creates the data directory with owner-only permissions.
func EnsureHome() error {
	if err := os.MkdirAll(Home(), 0o700); err != nil {
		return err
	}
	_ = os.Chmod(Home(), 0o700)
	return os.MkdirAll(SpoolDir(), 0o700)
}

// Load reads config.yaml over the defaults; a missing file is not an error.
func Load() (*Config, error) {
	c := Default()
	b, err := os.ReadFile(ConfigPath())
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err := yaml.Unmarshal(b, c); err != nil {
		return Default(), err
	}
	if c.Proxy.Routes == nil {
		c.Proxy.Routes = map[string]string{}
	}
	return c, nil
}

// SaveMode records the mode in config.yaml and leaves every other key as the
// user wrote it (comments included). Writing the whole struct instead would
// freeze every built-in default into the file, so a later change of default
// (e.g. usage.anthropic_enabled) would never reach that user.
func SaveMode(m Mode) error {
	b, err := os.ReadFile(ConfigPath())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var doc yaml.Node
	if len(strings.TrimSpace(string(b))) > 0 {
		if err := yaml.Unmarshal(b, &doc); err != nil {
			return err
		}
	}
	if len(doc.Content) == 0 {
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return errors.New("config.yaml: top level is not a mapping")
	}
	set := false
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "mode" {
			root.Content[i+1].SetString(string(m))
			set = true
		}
	}
	if !set {
		k, v := &yaml.Node{}, &yaml.Node{}
		k.SetString("mode")
		v.SetString(string(m))
		root.Content = append([]*yaml.Node{k, v}, root.Content...)
	}
	out, err := yaml.Marshal(&doc)
	if err != nil {
		return err
	}
	return os.WriteFile(ConfigPath(), out, 0o600)
}

// Route returns the upstream base URL for provider.
func (c *Config) Route(provider string) (string, bool) {
	if u, ok := c.Proxy.Routes[provider]; ok && u != "" {
		return strings.TrimRight(u, "/"), true
	}
	u, ok := DefaultRoutes[provider]
	return u, ok
}

// Token returns the UI/API token, creating it on first use.
func Token() (string, error) {
	if b, err := os.ReadFile(TokenPath()); err == nil && len(strings.TrimSpace(string(b))) >= 32 {
		return strings.TrimSpace(string(b)), nil
	}
	var r [24]byte
	if _, err := rand.Read(r[:]); err != nil {
		return "", err
	}
	t := hex.EncodeToString(r[:])
	if err := os.WriteFile(TokenPath(), []byte(t+"\n"), 0o600); err != nil {
		return "", err
	}
	return t, nil
}
