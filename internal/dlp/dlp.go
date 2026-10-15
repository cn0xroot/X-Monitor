// Package dlp detects and redacts secrets in text that is about to leave the
// machine: LLM request bodies (DESIGN.md §7.6) and GLM audit prompts (§12.6).
package dlp

import (
	"os"
	"regexp"
	"sort"
	"strings"
)

// Finding is one detected secret (the value itself is never stored).
type Finding struct {
	Kind  string `json:"kind"`
	Start int    `json:"-"`
	End   int    `json:"-"`
	Hint  string `json:"hint"` // first 4 chars + length, safe to log
}

type detector struct {
	kind string
	re   *regexp.Regexp
	grp  int // capture group holding the secret (0 = whole match)
}

var detectors = []detector{
	{"private_key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----|$)`), 0},
	{"aws_access_key", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), 0},
	{"github_token", regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{20,})\b`), 0},
	{"anthropic_key", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}`), 0},
	{"openai_key", regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}`), 0},
	{"slack_token", regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}`), 0},
	{"google_api_key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`), 0},
	{"npm_token", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`), 0},
	{"stripe_key", regexp.MustCompile(`\b[sr]k_live_[0-9a-zA-Z]{24,}\b`), 0},
	{"gitlab_token", regexp.MustCompile(`\bglpat-[0-9A-Za-z_-]{20,}\b`), 0},
	{"aliyun_key", regexp.MustCompile(`\bLTAI[0-9A-Za-z]{12,20}\b`), 0},
	// Z.ai / Zhipu keys look like <32 hex>.<16 alnum>
	{"zhipu_key", regexp.MustCompile(`\b[0-9a-f]{32}\.[0-9A-Za-z]{16}\b`), 0},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), 0},
	// KEY=value assignments typical of .env files and configs.
	{"credential_assignment", regexp.MustCompile(`(?im)\b(?:[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY)[A-Z0-9_]*)\s*[:=]\s*["']?([^\s"'#]{8,})`), 1},
}

// Scan returns non-overlapping findings in s, in order.
func Scan(s string) []Finding {
	var fs []Finding
	for _, d := range detectors {
		for _, m := range d.re.FindAllStringSubmatchIndex(s, -1) {
			st, en := m[0], m[1]
			if d.grp > 0 && len(m) > 2*d.grp+1 && m[2*d.grp] >= 0 {
				st, en = m[2*d.grp], m[2*d.grp+1]
			}
			if d.kind == "credential_assignment" && placeholder(s[st:en]) {
				continue
			}
			fs = append(fs, Finding{Kind: d.kind, Start: st, End: en, Hint: hint(s[st:en])})
		}
	}
	sort.Slice(fs, func(i, j int) bool { return fs[i].Start < fs[j].Start })
	var out []Finding
	last := -1
	for _, f := range fs {
		if f.Start < last {
			continue
		}
		out = append(out, f)
		last = f.End
	}
	return out
}

func placeholder(v string) bool {
	l := strings.ToLower(v)
	for _, p := range []string{"xxxx", "changeme", "your_", "your-", "<", "${", "example", "placeholder", "redacted", "****"} {
		if strings.Contains(l, p) {
			return true
		}
	}
	return false
}

func hint(v string) string {
	r := []rune(v)
	pre := 4
	if len(r) < pre {
		pre = len(r)
	}
	return string(r[:pre]) + "…(" + itoa(len(r)) + ")"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// Redact replaces every finding with [REDACTED:kind].
func Redact(s string) (string, []Finding) {
	fs := Scan(s)
	if len(fs) == 0 {
		return s, nil
	}
	var b strings.Builder
	prev := 0
	for _, f := range fs {
		b.WriteString(s[prev:f.Start])
		b.WriteString("[REDACTED:" + f.Kind + "]")
		prev = f.End
	}
	b.WriteString(s[prev:])
	return b.String(), fs
}

// Anonymize redacts secrets and also folds $HOME and the user name, for text
// sent to a cloud model.
func Anonymize(s string) string {
	s, _ = Redact(s)
	if h, err := os.UserHomeDir(); err == nil && len(h) > 1 {
		s = strings.ReplaceAll(s, h, "~")
	}
	if u := os.Getenv("USER"); len(u) > 2 {
		s = strings.ReplaceAll(s, u, "<user>")
	}
	if hn, err := os.Hostname(); err == nil && len(hn) > 2 {
		s = strings.ReplaceAll(s, hn, "<host>")
	}
	return s
}

// Kinds returns the distinct finding kinds.
func Kinds(fs []Finding) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range fs {
		if !seen[f.Kind] {
			seen[f.Kind] = true
			out = append(out, f.Kind)
		}
	}
	return out
}
