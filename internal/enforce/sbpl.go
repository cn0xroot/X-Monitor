package enforce

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// sbplQuote renders s as an SBPL string literal.
func sbplQuote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(s) + `"`
}

// sbplPath renders a path filter: subpath (matches the path and everything
// below it) for directories and prefixes, literal for single files is not
// needed because subpath of a file matches just that file.
func sbplPath(p string) string { return "(subpath " + sbplQuote(p) + ")" }

// uniqSorted removes duplicates and sorts for a stable, diffable profile.
func uniqSorted(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if x != "" && !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

// resolveExec turns a DenyExec entry into absolute paths SBPL can match:
// basenames are looked up on PATH (and their symlink targets added).
func resolveExec(entry string) []string {
	if strings.Contains(entry, "/") {
		return both(entry)
	}
	var out []string
	if p, err := exec.LookPath(entry); err == nil {
		if abs, err := filepath.Abs(p); err == nil {
			out = append(out, both(abs)...)
		}
	}
	return out
}

// SandboxProfile renders the macOS sandbox-exec (SBPL) profile for p. Rules are
// deny-overlays on top of "allow default", so unrelated behavior is untouched.
// projectRoot is always writable: if a deny prefix would cover it, the allow
// rule that follows wins (SBPL is last-match-wins).
func SandboxProfile(p *Policy, projectRoot string) string {
	var b strings.Builder
	b.WriteString("(version 1)\n(allow default)\n")

	var w []string
	for _, d := range p.DenyWrite {
		w = append(w, both(d)...)
	}
	if w = uniqSorted(w); len(w) > 0 {
		b.WriteString("(deny file-write*\n")
		for _, d := range w {
			fmt.Fprintf(&b, "  %s\n", sbplPath(d))
		}
		b.WriteString(")\n")
	}

	var r []string
	for _, d := range p.DenyRead {
		r = append(r, both(d)...)
	}
	if r = uniqSorted(r); len(r) > 0 {
		// file-read-data only: stat() and connecting to a Unix socket inside the
		// directory (the hook channel) must keep working.
		b.WriteString("(deny file-read-data\n")
		for _, d := range r {
			fmt.Fprintf(&b, "  %s\n", sbplPath(d))
		}
		b.WriteString(")\n")
	}

	var x []string
	for _, d := range p.DenyExec {
		x = append(x, resolveExec(d)...)
	}
	if x = uniqSorted(x); len(x) > 0 {
		b.WriteString("(deny process-exec\n")
		for _, d := range x {
			fmt.Fprintf(&b, "  (literal %s)\n", sbplQuote(d))
		}
		b.WriteString(")\n")
	}

	if projectRoot != "" {
		for _, d := range uniqSorted(both(projectRoot)) {
			fmt.Fprintf(&b, "(allow file-write* %s)\n", sbplPath(d))
		}
		// ...but never re-open the monitor's own directory or credentials.
		var keep []string
		for _, d := range p.DenyWrite {
			for _, c := range both(d) {
				if underPath(c, projectRoot) || underPath(c, canon(projectRoot)) {
					keep = append(keep, c)
				}
			}
		}
		if keep = uniqSorted(keep); len(keep) > 0 {
			b.WriteString("(deny file-write*\n")
			for _, d := range keep {
				fmt.Fprintf(&b, "  %s\n", sbplPath(d))
			}
			b.WriteString(")\n")
		}
	}
	return b.String()
}

func underPath(p, root string) bool {
	root = strings.TrimRight(root, "/")
	return p == root || strings.HasPrefix(p, root+"/")
}
