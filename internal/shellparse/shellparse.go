// Package shellparse splits shell command text into sub-commands while
// respecting quotes and heredocs, strips wrapper prefixes (sudo/env/xargs…),
// and recurses into `bash -c '…'` / `osascript … do shell script "…"`.
//
// Ported from cc-monitor (cc_monitor/policy.py, MIT License); see NOTICE.
package shellparse

import (
	"regexp"
	"strings"
)

var (
	wrapperRE = regexp.MustCompile(`^(?:` +
		`sudo(?:\s+(?:-[ugCDhprtUT]\s+\S+|--\S+|-[A-Za-z]+))*` +
		`|doas(?:\s+-u\s+\S+)?` +
		`|env(?:\s+(?:-\S+|\w+=\S*))*` +
		`|xargs(?:\s+(?:-[InLPdsE]\s*\S+|-\S+))*` +
		`|nice(?:\s+-n\s*\S+)?` +
		`|command|exec|time|nohup|builtin|caffeinate` +
		`)\s+`)
	envAssignRE = regexp.MustCompile(`^(?:[A-Za-z_]\w*=(?:'[^']*'|"[^"]*"|\S*)\s+)+`)
	// Accepts -c as well as combined flags such as -lc / -ec (Codex uses `bash -lc`).
	shellCRE     = regexp.MustCompile(`(?is)^(?:sh|bash|zsh|dash|ksh|fish)\s+(?:-\S+\s+)*?-[a-zA-Z]*c\s+(?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)")`)
	osascriptRE  = regexp.MustCompile(`(?is)do shell script\s+"((?:[^"\\]|\\.)*)"`)
	pathPrefixRE = regexp.MustCompile(`^(\S*/)(\S+)`)
	unescapeRE   = regexp.MustCompile(`\\(.)`)
	heredocHead  = regexp.MustCompile(`^<<-?\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)(['"]?)`)
)

// matchHeredoc returns (fullMatchLen, delimiter) for a heredoc opener at s, or (0,"").
func matchHeredoc(s string) (int, string) {
	// Python used a backreference: an opening quote must be closed by the same quote.
	m := heredocHead.FindStringSubmatchIndex(s)
	if m == nil {
		return 0, ""
	}
	open, delim, closeQ := s[m[2]:m[3]], s[m[4]:m[5]], s[m[6]:m[7]]
	if open == "" {
		return m[5], delim
	}
	if closeQ != open {
		return 0, ""
	}
	return m[7], delim
}

// SplitSegments splits on top-level ; & | and newlines. Separators inside
// single/double quotes or heredoc bodies don't count.
func SplitSegments(cmd string) []string {
	cmd = strings.ReplaceAll(cmd, "\\\n", " ")
	var segments []string
	var cur strings.Builder
	n := len(cmd)
	var quote byte
	heredocEnd := ""
	inHeredoc := false
	i := 0
	for i < n {
		if inHeredoc {
			lineEnd := strings.IndexByte(cmd[i:], '\n')
			var line string
			if lineEnd == -1 {
				line = cmd[i:]
			} else {
				line = cmd[i : i+lineEnd]
			}
			cur.WriteString(line)
			if strings.TrimSpace(line) == heredocEnd {
				inHeredoc = false
			}
			if lineEnd == -1 {
				i = n
			} else {
				cur.WriteByte('\n')
				i += lineEnd + 1
			}
			continue
		}
		ch := cmd[i]
		if quote != 0 {
			cur.WriteByte(ch)
			if ch == '\\' && quote == '"' && i+1 < n {
				cur.WriteByte(cmd[i+1])
				i += 2
				continue
			}
			if ch == quote {
				quote = 0
			}
			i++
			continue
		}
		if ch == '\'' || ch == '"' {
			quote = ch
			cur.WriteByte(ch)
			i++
			continue
		}
		if ch == '\\' && i+1 < n {
			cur.WriteString(cmd[i : i+2])
			i += 2
			continue
		}
		if ch == '<' && i+1 < n && cmd[i+1] == '<' {
			if l, delim := matchHeredoc(cmd[i:]); l > 0 {
				cur.WriteString(cmd[i : i+l])
				i += l
				nl := strings.IndexByte(cmd[i:], '\n')
				if nl == -1 {
					cur.WriteString(cmd[i:])
					i = n
				} else {
					cur.WriteString(cmd[i : i+nl+1])
					i += nl + 1
					heredocEnd = delim
					inHeredoc = true
				}
				continue
			}
		}
		if ch == ';' || ch == '&' || ch == '|' || ch == '\n' {
			segments = append(segments, cur.String())
			cur.Reset()
			i++
			continue
		}
		cur.WriteByte(ch)
		i++
	}
	if cur.Len() > 0 {
		segments = append(segments, cur.String())
	}
	return segments
}

func stripLead(seg string) string {
	return strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(seg), "({"))
}

// NormalizeHead strips leading parens, env assignments and wrapper commands,
// then the executable's directory prefix (/opt/local/bin/port -> port).
func NormalizeHead(seg string) string {
	seg = stripLead(seg)
	for {
		before := seg
		seg = envAssignRE.ReplaceAllString(seg, "")
		seg = wrapperRE.ReplaceAllString(seg, "")
		if seg == before {
			break
		}
	}
	if m := pathPrefixRE.FindStringSubmatchIndex(seg); m != nil {
		seg = seg[m[3]:]
	}
	return seg
}

// Unescape removes backslash escapes.
func Unescape(s string) string { return unescapeRE.ReplaceAllString(s, "$1") }

// ShellCInner returns the script of a `sh -c '…'` head, if it is one.
func ShellCInner(head string) (string, bool) {
	m := shellCRE.FindStringSubmatchIndex(head)
	if m == nil {
		return "", false
	}
	if m[2] >= 0 {
		return head[m[2]:m[3]], true
	}
	return Unescape(head[m[4]:m[5]]), true
}

// SegmentHeads expands a command into sub-commands for match="segment" rules.
// Each segment yields its "plain" form (only parens/env stripped — rules like
// sudo_usage need to see sudo) and its normalized head.
func SegmentHeads(cmd string) []string { return segmentHeads(cmd, 0) }

func segmentHeads(cmd string, depth int) []string {
	var heads []string
	for _, raw := range SplitSegments(cmd) {
		plain := envAssignRE.ReplaceAllString(stripLead(raw), "")
		head := NormalizeHead(raw)
		if head == "" {
			continue
		}
		if plain != "" && plain != head {
			heads = append(heads, plain)
		}
		heads = append(heads, head)
		if depth >= 3 {
			continue
		}
		if inner, ok := ShellCInner(head); ok {
			heads = append(heads, segmentHeads(inner, depth+1)...)
			continue
		}
		for _, om := range osascriptRE.FindAllStringSubmatch(head, -1) {
			heads = append(heads, segmentHeads(Unescape(om[1]), depth+1)...)
		}
	}
	return heads
}

// IterSegments yields normalized heads, recursing into sh -c (used by workdir).
func IterSegments(cmd string) []string { return iterSegments(cmd, 0) }

func iterSegments(cmd string, depth int) []string {
	var out []string
	for _, raw := range SplitSegments(cmd) {
		head := NormalizeHead(raw)
		if strings.TrimSpace(head) == "" {
			continue
		}
		if depth < 3 {
			if inner, ok := ShellCInner(head); ok {
				out = append(out, iterSegments(inner, depth+1)...)
				continue
			}
		}
		out = append(out, head)
	}
	return out
}

// Split tokenizes like Python shlex.split(posix=True). ok=false on unbalanced quotes.
func Split(s string) (tokens []string, ok bool) {
	var cur strings.Builder
	inTok := false
	i := 0
	n := len(s)
	for i < n {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			if inTok {
				tokens = append(tokens, cur.String())
				cur.Reset()
				inTok = false
			}
			i++
		case c == '\'':
			inTok = true
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return nil, false
			}
			cur.WriteString(s[i+1 : i+1+j])
			i += j + 2
		case c == '"':
			inTok = true
			i++
			closed := false
			for i < n {
				d := s[i]
				if d == '\\' && i+1 < n && strings.IndexByte("\\\"$`\n", s[i+1]) >= 0 {
					cur.WriteByte(s[i+1])
					i += 2
					continue
				}
				if d == '"' {
					closed = true
					i++
					break
				}
				cur.WriteByte(d)
				i++
			}
			if !closed {
				return nil, false
			}
		case c == '\\':
			inTok = true
			if i+1 < n {
				cur.WriteByte(s[i+1])
				i += 2
			} else {
				return nil, false
			}
		default:
			inTok = true
			cur.WriteByte(c)
			i++
		}
	}
	if inTok {
		tokens = append(tokens, cur.String())
	}
	return tokens, true
}
