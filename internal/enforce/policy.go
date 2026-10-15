// Package enforce is the L1 kernel-level enforcement layer (DESIGN.md §11).
//
// Regex rules can't run in a kernel hook, so enforcement uses a separate,
// static Policy of path prefixes and executable names. The same Policy drives
// every platform backend:
//
//	macOS   sandbox-exec profile (managed mode, no entitlement needed)
//	Linux   Landlock, applied to the agent tree at launch (managed mode)
//	all     kill-after-exec tier fed by the L1 probe (racy, but works on
//	        already-running processes and every platform)
//
// Hard-deny here is deliberately conservative: unlike an L4 "confirm" rule, a
// sandbox denial cannot be approved by the user at run time, so the defaults
// only cover paths an agent has no legitimate reason to write.
package enforce

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Policy is the static enforcement policy pushed down to the OS layer.
type Policy struct {
	Version int `json:"version"`
	// DenyWrite lists path prefixes agents must never write, create, rename or
	// delete (deny-list model: macOS sandbox, kill tier cannot enforce this).
	DenyWrite []string `json:"deny_write"`
	// DenyRead lists path prefixes whose contents agents must not read.
	DenyRead []string `json:"deny_read"`
	// DenyExec lists executables agents must not run. An entry without a slash
	// is a basename ("nc"); otherwise it is a path prefix.
	DenyExec []string `json:"deny_exec"`
	// WritableRoots is the allow-list model used by Landlock, which cannot carve
	// exceptions out of a granted directory: writes are only possible beneath
	// these roots. The project root is added at launch time.
	WritableRoots []string `json:"writable_roots"`
	// LoopbackOnlyPrograms lists agent executables whose own network access is
	// limited to loopback (i.e. to the X-Monitor proxy), so they cannot bypass
	// L4 by connecting to an LLM directly. Enforced via the Windows firewall
	// (backed by WFP). Child tools such as git keep working: the rule is
	// per-program, not per-tree.
	LoopbackOnlyPrograms []string `json:"loopback_only_programs"`
}

// Default builds the built-in policy for a user's home directory.
func Default(home string) *Policy {
	h := func(rel ...string) string { return filepath.Join(append([]string{home}, rel...)...) }
	return &Policy{
		Version: 1,
		DenyWrite: []string{
			// the monitor itself (self-protection, DESIGN.md §17)
			h(".xmon"),
			// credentials
			h(".ssh"), h(".aws"), h(".gnupg"), h(".kube"), h(".config", "gh"), h(".netrc"),
			// persistence locations
			h(".bashrc"), h(".bash_profile"), h(".profile"), h(".zshrc"), h(".zshenv"), h(".zprofile"),
			h("Library", "LaunchAgents"), h(".config", "systemd"), h(".config", "autostart"),
			"/Library/LaunchAgents", "/Library/LaunchDaemons", "/etc/cron.d", "/etc/cron.daily",
			"/var/spool/cron", "/etc/systemd", "/etc/sudoers", "/etc/sudoers.d",
			// agent hook / permission config: editing these can switch monitoring off
			h(".claude", "settings.json"), h(".claude", "hooks"),
			h(".codex", "config.toml"), h(".gemini", "settings.json"), h(".cursor", "hooks.json"),
		},
		DenyRead: []string{
			// the approval token: an agent that reads it could approve itself
			h(".xmon"),
		},
		DenyExec: []string{"nc", "ncat", "netcat", "socat"},
		WritableRoots: []string{
			"/tmp", "/var/tmp", "/dev",
			h(".cache"), h(".npm"), h(".cargo"), h(".rustup"), h("go"), h(".local", "share"),
			h(".claude"), h(".claude.json"), h(".codex"), h(".gemini"), h(".cursor"),
		},
	}
}

// Path returns the policy file location under the data directory.
func Path(dataDir string) string { return filepath.Join(dataDir, "enforce-policy.json") }

// Load reads a policy file; a missing file yields the default policy.
func Load(file, home string) (*Policy, error) {
	b, err := os.ReadFile(file)
	if os.IsNotExist(err) {
		return Default(home), nil
	}
	if err != nil {
		return nil, err
	}
	p := &Policy{}
	if err := json.Unmarshal(b, p); err != nil {
		return nil, err
	}
	return p, nil
}

// Save writes the policy atomically with owner-only permissions.
func (p *Policy) Save(file string) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	tmp := file + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, file)
}

// canon resolves symlinks for the longest existing prefix of p (macOS /tmp is
// really /private/tmp; sandbox profiles match resolved paths).
func canon(p string) string {
	p = filepath.Clean(p)
	rest := ""
	cur := p
	for {
		if r, err := filepath.EvalSymlinks(cur); err == nil {
			if rest == "" {
				return r
			}
			return filepath.Join(r, rest)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return p
		}
		if rest == "" {
			rest = filepath.Base(cur)
		} else {
			rest = filepath.Join(filepath.Base(cur), rest)
		}
		cur = parent
	}
}

// both returns p and its symlink-resolved form (deduplicated).
func both(p string) []string {
	c := canon(p)
	if c == p {
		return []string{p}
	}
	return []string{p, c}
}

// MatchExec reports whether a command line starts with a denied executable and
// returns the matching policy entry. command is argv text or a bare path.
func (p *Policy) MatchExec(command string) (string, bool) {
	fields := strings.Fields(strings.TrimSpace(command))
	if len(fields) == 0 {
		return "", false
	}
	first := fields[0]
	base := path.Base(filepath.ToSlash(first))
	for _, d := range p.DenyExec {
		if d == "" {
			continue
		}
		if !strings.Contains(d, "/") {
			if base == d {
				return d, true
			}
			continue
		}
		if first == d || strings.HasPrefix(first, strings.TrimRight(d, "/")+"/") {
			return d, true
		}
	}
	return "", false
}

// Cache serves the policy file with a short TTL so hot paths (one lookup per
// observed exec) don't hit the disk each time, while edits still apply within
// a couple of seconds without restarting the daemon.
type Cache struct {
	File, Home string

	mu    sync.Mutex
	p     *Policy
	mtime time.Time
	last  time.Time
}

// Get returns the current policy; on a read error it keeps the last good one.
func (c *Cache) Get() *Policy {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.p != nil && time.Since(c.last) < 2*time.Second {
		return c.p
	}
	c.last = time.Now()
	st, err := os.Stat(c.File)
	if err == nil && c.p != nil && st.ModTime().Equal(c.mtime) {
		return c.p
	}
	p, lerr := Load(c.File, c.Home)
	if lerr != nil {
		if c.p == nil {
			c.p = Default(c.Home)
		}
		return c.p
	}
	c.p = p
	if err == nil {
		c.mtime = st.ModTime()
	}
	return c.p
}
