// Package workdir detects tool calls that touch paths outside the current
// project, and classifies them by tier (homeDotfile / otherUserHome / system /
// otherProject) and access (read / write).
//
// Ported from cc-monitor (cc_monitor/workdir.py, MIT License); see NOTICE.
// Tool names are replaced by canonical classes so it works for every agent.
package workdir

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"xmonitor/internal/shellparse"
	"xmonitor/internal/toolclass"
)

// Tiers.
const (
	TierHomeDotfile = "homeDotfile"
	TierOtherUser   = "otherUserHome"
	TierSystem      = "system"
	TierOther       = "otherProject"
)

// Access kinds.
const (
	AccessRead  = "read"
	AccessWrite = "write"
)

var AllTiers = []string{TierHomeDotfile, TierOtherUser, TierSystem, TierOther}

var (
	systemRoots = []string{
		"/etc", "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/boot", "/var", "/opt",
		"/proc", "/sys", "/run", "/srv", "/snap", "/nix", "/cores",
		"/System", "/Library", "/Applications", "/private", "/Network", "/Volumes",
	}
	userHomeParents = []string{"/home", "/Users"}
	DefaultIgnore   = []string{"/tmp", "/var/tmp", "/private/tmp", "/private/var/folders", "/dev"}
	homeIgnore      = []string{".claude/projects", ".codex/sessions", ".gemini/tmp"}
	systemReadQuiet = []string{
		"/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/opt", "/snap", "/nix",
		"/System", "/Library", "/Applications",
	}
	homeReadQuiet  = []string{".cache"}
	projectMarkers = []string{".git", ".hg", ".svn", "CLAUDE.md", ".claude", "AGENTS.md", ".codex", ".cursor", "GEMINI.md", ".zai"}

	writeAllCmds = set("rm", "rmdir", "touch", "mkdir", "chmod", "chown", "chgrp", "truncate", "shred", "unlink", "tee",
		"dd", "patch", "chattr", "setfacl", "mkfifo", "mknod")
	writeLastCmds    = set("cp", "mv", "ln", "rsync", "install", "scp")
	gitWriteLastSubs = set("clone", "init")

	redirectTokRE = regexp.MustCompile(`^(\d*)(>>|>\||>|&>>|&>)(.*)$`)
	heredocRE     = regexp.MustCompile(`<<-?\s*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?`)
	optAssignRE   = regexp.MustCompile(`^--?[A-Za-z][\w-]*=(.+)$`)
	envAssignRE   = regexp.MustCompile(`^[A-Za-z_]\w*=(.*)$`)
)

func set(xs ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// Hit is one out-of-workspace path touched by a tool call.
type Hit struct {
	Path   string
	Tier   string
	Access string
}

// Display renders the path with $HOME folded to ~.
func (h Hit) Display() string {
	home := Home()
	if under(h.Path, home) && home != "/" {
		return "~" + h.Path[len(home):]
	}
	return h.Path
}

// Home returns $HOME without a trailing slash.
func Home() string {
	h := os.Getenv("HOME")
	if h == "" {
		h, _ = os.UserHomeDir()
	}
	h = strings.TrimRight(h, "/")
	if h == "" {
		return "/"
	}
	return h
}

func norm(p string) string {
	p = path.Clean(p)
	if p != "/" {
		p = strings.TrimRight(p, "/")
	}
	if p == "" {
		return "/"
	}
	return p
}

// canon resolves symlinks for the longest existing prefix (like os.path.realpath).
func canon(p string) string {
	p = norm(p)
	rest := ""
	cur := p
	for {
		if r, err := filepath.EvalSymlinks(cur); err == nil {
			if rest == "" {
				return norm(r)
			}
			return norm(r + "/" + rest)
		}
		parent := path.Dir(cur)
		if parent == cur {
			return p
		}
		base := path.Base(cur)
		if rest == "" {
			rest = base
		} else {
			rest = base + "/" + rest
		}
		cur = parent
	}
}

func under(p, root string) bool {
	if root == "/" {
		return strings.HasPrefix(p, "/")
	}
	return p == root || strings.HasPrefix(p, root+"/")
}

func ignoredRoots(homes []string) []string {
	roots := append([]string{}, DefaultIgnore...)
	if t := os.Getenv("TMPDIR"); t != "" {
		roots = append(roots, canon(t))
	}
	for _, h := range homes {
		for _, rel := range homeIgnore {
			roots = append(roots, h+"/"+rel)
		}
	}
	return roots
}

func readQuietRoots(homes []string) []string {
	roots := append([]string{}, systemReadQuiet...)
	for _, h := range homes {
		for _, rel := range homeReadQuiet {
			roots = append(roots, h+"/"+rel)
		}
	}
	return roots
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// ProjectRoot walks up from cwd and returns the top-most directory below $HOME
// that carries a project marker; cwd itself when none is found.
func ProjectRoot(cwd string) string {
	cwd = norm(cwd)
	stop := map[string]bool{"/": true}
	for _, h := range sessionHomes(cwd) {
		stop[h] = true
	}
	best := ""
	cur := cwd
	for !stop[cur] && cur != "/" {
		for _, m := range projectMarkers {
			if exists(path.Join(cur, m)) {
				best = cur
				break
			}
		}
		parent := path.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	if best == "" {
		return cwd
	}
	return best
}

// additionalDirectories reads Claude Code's permissions.additionalDirectories.
func additionalDirectories(cwd string) []string {
	home := Home()
	var dirs []string
	for _, f := range []string{
		path.Join(cwd, ".claude", "settings.local.json"),
		path.Join(cwd, ".claude", "settings.json"),
		path.Join(home, ".claude", "settings.json"),
	} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var data struct {
			Permissions struct {
				AdditionalDirectories []string `json:"additionalDirectories"`
			} `json:"permissions"`
		}
		if json.Unmarshal(b, &data) != nil {
			continue
		}
		for _, d := range data.Permissions.AdditionalDirectories {
			if strings.TrimSpace(d) == "" {
				continue
			}
			d = expandUser(d)
			if !strings.HasPrefix(d, "/") {
				d = path.Join(cwd, d)
			}
			dirs = append(dirs, canon(d))
		}
	}
	return dirs
}

func expandUser(p string) string {
	if p == "~" {
		return Home()
	}
	if strings.HasPrefix(p, "~/") {
		return Home() + p[1:]
	}
	return p
}

func sessionHomes(cwd string) []string {
	homes := []string{Home()}
	add := func(h string) {
		for _, x := range homes {
			if x == h {
				return
			}
		}
		homes = append(homes, h)
	}
	for _, parent := range userHomeParents {
		if under(cwd, parent) && cwd != parent {
			user := strings.SplitN(cwd[len(parent)+1:], "/", 2)[0]
			add(parent + "/" + user)
		}
	}
	if under(cwd, "/root") {
		add("/root")
	}
	return homes
}

// Classify returns the tier of an absolute path relative to cwd, or "" when it
// is inside the workspace or ignored. ignored==nil means the defaults.
func Classify(p, cwd string, allowed, ignored, homes []string) string {
	if under(p, cwd) {
		return ""
	}
	for _, r := range allowed {
		if under(p, r) {
			return ""
		}
	}
	if ignored == nil {
		ignored = ignoredRoots(nil)
	}
	for _, r := range ignored {
		if under(p, r) {
			return ""
		}
	}
	if homes == nil {
		homes = sessionHomes(cwd)
	}
	for _, h := range homes {
		if under(p, h) {
			rel := strings.TrimLeft(p[len(h):], "/")
			first := strings.SplitN(rel, "/", 2)[0]
			if strings.HasPrefix(first, ".") {
				return TierHomeDotfile
			}
			return TierOther
		}
	}
	if p == "/" {
		return TierSystem
	}
	if under(p, "/root") {
		return TierOtherUser
	}
	for _, parent := range userHomeParents {
		if p != parent && under(p, parent) {
			return TierOtherUser
		}
	}
	for _, r := range systemRoots {
		if under(p, r) {
			return TierSystem
		}
	}
	return TierOther
}

func expand(tok, shellCWD string) string {
	if tok == "" || strings.ContainsAny(tok, "\n\t ") || strings.Contains(tok, "://") {
		return ""
	}
	switch {
	case strings.HasPrefix(tok, "$HOME/") || strings.HasPrefix(tok, "${HOME}/") || tok == "$HOME" || tok == "${HOME}":
		tok = Home() + strings.TrimLeft(strings.SplitN(tok, "HOME", 2)[1], "}")
	case strings.HasPrefix(tok, "$PWD/") || strings.HasPrefix(tok, "${PWD}/") || tok == "$PWD" || tok == "${PWD}":
		tok = shellCWD + strings.TrimLeft(strings.SplitN(tok, "PWD", 2)[1], "}")
	case strings.HasPrefix(tok, "~"):
		e := expandUser(tok)
		if strings.HasPrefix(e, "~") {
			return "" // ~otheruser: unresolvable without passwd lookup
		}
		tok = e
	case strings.HasPrefix(tok, "$"):
		return ""
	}
	if strings.HasPrefix(tok, "/") {
		return norm(tok)
	}
	if tok == "." || tok == ".." || strings.HasPrefix(tok, "./") || strings.HasPrefix(tok, "../") || strings.Contains(tok, "/") {
		if strings.HasPrefix(tok, "-") {
			return ""
		}
		return norm(path.Join(shellCWD, tok))
	}
	return ""
}

func stripHeredoc(seg string) string {
	loc := heredocRE.FindStringIndex(seg)
	if loc == nil {
		return seg
	}
	rest := seg[loc[1]:]
	if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
		rest = rest[:nl]
	}
	return seg[:loc[0]] + " " + rest
}

func tokens(seg string) []string {
	seg = stripHeredoc(seg)
	if t, ok := shellparse.Split(seg); ok {
		return t
	}
	return strings.Fields(seg)
}

type cand struct {
	path   string
	access string
	isExec bool
}

func bashPaths(command, cwd string) []cand {
	var out []cand
	shellCWD := cwd
	for _, seg := range shellparse.IterSegments(command) {
		toks := tokens(seg)
		if len(toks) == 0 {
			continue
		}
		cmd := path.Base(toks[0])
		args := toks[1:]

		if cmd == "cd" || cmd == "pushd" {
			target := ""
			for _, a := range args {
				if !strings.HasPrefix(a, "-") {
					target = a
					break
				}
			}
			var nc string
			switch {
			case target == "":
				nc = Home()
			case target == "-":
				continue
			default:
				nc = expand(target, shellCWD)
				if nc == "" {
					nc = norm(path.Join(shellCWD, target))
				}
			}
			out = append(out, cand{nc, AccessRead, false})
			shellCWD = nc
			continue
		}

		if strings.Contains(toks[0], "/") {
			if p := expand(toks[0], shellCWD); p != "" {
				out = append(out, cand{p, AccessRead, true})
			}
		}

		writeAll := writeAllCmds[cmd]
		if cmd == "sed" || cmd == "perl" {
			for _, a := range args {
				if strings.HasPrefix(a, "-i") || a == "--in-place" {
					writeAll = true
				}
			}
		}
		if cmd == "find" {
			for _, a := range args {
				if a == "-delete" {
					writeAll = true
				}
			}
		}
		writeLast := writeLastCmds[cmd] || (cmd == "git" && len(args) > 0 && gitWriteLastSubs[args[0]])
		tarExtract, tarCreate := false, false
		if cmd == "tar" && len(args) > 0 {
			f := strings.TrimLeft(args[0], "-")
			tarExtract = strings.Contains(f, "x")
			tarCreate = strings.Contains(f, "c")
		}

		type pp struct {
			p    string
			last bool
		}
		var paths []pp
		pendingRedirect := false
		pendingFlag := ""
		lastPositional := -1
		for i, a := range args {
			if !strings.HasPrefix(a, "-") && !redirectTokRE.MatchString(a) && a != "<" && a != "<<<" {
				lastPositional = i
			}
		}
		for i, a := range args {
			if pendingRedirect {
				if p := expand(a, shellCWD); p != "" {
					out = append(out, cand{p, AccessWrite, false})
				}
				pendingRedirect = false
				continue
			}
			if pendingFlag != "" {
				flag := pendingFlag
				pendingFlag = ""
				if p := expand(a, shellCWD); p != "" {
					switch {
					case cmd == "tar" && flag == "-C":
						out = append(out, cand{p, ifs(tarExtract, AccessWrite, AccessRead), false})
					case cmd == "tar" && flag == "-f":
						out = append(out, cand{p, ifs(tarCreate, AccessWrite, AccessRead), false})
					case cmd == "unzip" && flag == "-d":
						out = append(out, cand{p, AccessWrite, false})
					default:
						paths = append(paths, pp{p, false})
					}
				}
				continue
			}
			if m := redirectTokRE.FindStringSubmatch(a); m != nil {
				if m[3] != "" {
					if p := expand(m[3], shellCWD); p != "" {
						out = append(out, cand{p, AccessWrite, false})
					}
				} else {
					pendingRedirect = true
				}
				continue
			}
			if a == "<" || a == "<<<" {
				continue
			}
			if cmd == "tar" && (a == "-C" || a == "-f" || a == "--directory" || a == "--file") {
				if a == "-C" || a == "--directory" {
					pendingFlag = "-C"
				} else {
					pendingFlag = "-f"
				}
				continue
			}
			if cmd == "unzip" && a == "-d" {
				pendingFlag = "-d"
				continue
			}
			if cmd == "git" && a == "-C" {
				pendingFlag = "-C"
				continue
			}
			if strings.HasPrefix(a, "-") {
				if om := optAssignRE.FindStringSubmatch(a); om != nil {
					if p := expand(om[1], shellCWD); p != "" {
						paths = append(paths, pp{p, false})
					}
				}
				continue
			}
			if em := envAssignRE.FindStringSubmatch(a); em != nil && !strings.HasPrefix(a, "/") {
				if p := expand(em[1], shellCWD); p != "" {
					paths = append(paths, pp{p, false})
				}
				continue
			}
			if p := expand(a, shellCWD); p != "" {
				paths = append(paths, pp{p, i == lastPositional})
			}
		}
		for _, x := range paths {
			if writeAll || (writeLast && x.last) {
				out = append(out, cand{x.p, AccessWrite, false})
			} else {
				out = append(out, cand{x.p, AccessRead, false})
			}
		}
	}
	return out
}

func ifs(c bool, a, b string) string {
	if c {
		return a
	}
	return b
}

var fileFields = []string{"file_path", "path", "notebook_path"}

// Scan returns every out-of-workspace path the call touches, in first-seen
// order, one entry per path (write wins over read).
func Scan(call toolclass.Call) []Hit {
	cwd := call.CWD
	if !strings.HasPrefix(cwd, "/") {
		return nil
	}
	cwd = norm(cwd)
	homes := sessionHomes(canon(cwd))
	root := ProjectRoot(cwd)
	rootReal := canon(root)
	allowed := additionalDirectories(cwd)
	if root != cwd {
		allowed = append(allowed, additionalDirectories(root)...)
	}
	ignored := ignoredRoots(homes)
	readQuiet := readQuietRoots(homes)

	var cands []cand
	switch call.Class {
	case toolclass.ExecShell:
		if c, ok := call.Args["command"].(string); ok && strings.TrimSpace(c) != "" {
			cands = bashPaths(c, cwd)
		}
	case toolclass.FSRead, toolclass.FSSearch, toolclass.FSWrite, toolclass.FSEdit, toolclass.FSDelete:
		access := AccessRead
		if call.Class == toolclass.FSWrite || call.Class == toolclass.FSEdit || call.Class == toolclass.FSDelete {
			access = AccessWrite
		}
		for _, k := range fileFields {
			v, ok := call.Args[k].(string)
			if !ok || strings.TrimSpace(v) == "" {
				continue
			}
			v = strings.TrimSpace(v)
			p := expand(v, cwd)
			if p == "" && !strings.HasPrefix(v, "-") {
				p = norm(path.Join(cwd, v))
			}
			if p != "" {
				cands = append(cands, cand{p, access, false})
			}
		}
	default:
		return nil
	}

	hits := map[string]*Hit{}
	var order []string
	for _, c := range cands {
		if under(c.path, root) || anyUnder(c.path, ignored) {
			continue
		}
		tier := Classify(canon(c.path), rootReal, allowed, ignored, homes)
		if tier == "" {
			continue
		}
		if c.isExec && tier == TierSystem {
			continue
		}
		if c.access == AccessRead && anyUnder(c.path, readQuiet) {
			continue
		}
		if h, ok := hits[c.path]; ok {
			if c.access == AccessWrite {
				h.Access = AccessWrite
			}
			continue
		}
		hits[c.path] = &Hit{c.path, tier, c.access}
		order = append(order, c.path)
	}
	out := make([]Hit, 0, len(order))
	for _, p := range order {
		out = append(out, *hits[p])
	}
	return out
}

func anyUnder(p string, roots []string) bool {
	for _, r := range roots {
		if under(p, r) {
			return true
		}
	}
	return false
}

// Select filters hits by tiers, access (read/write/any) and extra ignore paths.
func Select(hits []Hit, scopes []string, access string, ignorePaths []string) []Hit {
	sc := map[string]bool{}
	for _, s := range scopes {
		sc[s] = true
	}
	if len(sc) == 0 {
		for _, s := range AllTiers {
			sc[s] = true
		}
	}
	var ign []string
	for _, p := range ignorePaths {
		if strings.TrimSpace(p) != "" {
			ign = append(ign, canon(expandUser(p)))
		}
	}
	var out []Hit
	for _, h := range hits {
		if !sc[h.Tier] {
			continue
		}
		if access != "" && access != "any" && h.Access != access {
			continue
		}
		skip := false
		for _, r := range ign {
			if under(h.Path, r) || under(canon(h.Path), r) {
				skip = true
				break
			}
		}
		if !skip {
			out = append(out, h)
		}
	}
	return out
}

// Describe renders up to limit hits.
func Describe(hits []Hit, limit int) string {
	var shown []string
	for i, h := range hits {
		if i >= limit {
			shown = append(shown, fmt.Sprintf("…(+%d)", len(hits)-limit))
			break
		}
		shown = append(shown, h.Display())
	}
	return strings.Join(shown, ", ")
}
