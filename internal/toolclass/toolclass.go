// Package toolclass maps each agent's raw tool names and argument shapes onto
// a small set of canonical classes, so rules are written once for every agent
// (DESIGN.md §6.2).
package toolclass

import (
	"encoding/json"
	"strings"
)

// Canonical classes.
const (
	ExecShell  = "exec.shell"
	FSRead     = "fs.read"
	FSSearch   = "fs.search"
	FSWrite    = "fs.write"
	FSEdit     = "fs.edit"
	FSDelete   = "fs.delete"
	NetFetch   = "net.fetch"
	NetSearch  = "net.search"
	MCPCall    = "mcp.call"
	AgentSpawn = "agent.spawn"
	AgentAsk   = "agent.ask"
	Other      = "other"
)

// Call is one normalized tool invocation.
type Call struct {
	ID           string         // tool_call_id / tool_use_id
	Raw          string         // raw tool name as the agent sent it
	Class        string         // canonical class
	Args         map[string]any // raw args plus canonical aliases
	Agent        string
	Session      string
	AgentSession string
	CWD          string
	Model        string // the LLM the agent asked, when the proxy saw the request
}

// exact maps raw tool names (lower-cased) to classes. Covers Claude Code,
// Codex, Cursor, Gemini CLI, and common OpenAI-style function names.
var exact = map[string]string{
	// Claude Code
	"bash": ExecShell, "bashoutput": Other, "killshell": Other,
	"read": FSRead, "grep": FSSearch, "glob": FSSearch, "ls": FSSearch,
	"write": FSWrite, "edit": FSEdit, "multiedit": FSEdit, "notebookedit": FSEdit,
	"webfetch": NetFetch, "websearch": NetSearch,
	"task": AgentSpawn, "agent": AgentSpawn, "askuserquestion": AgentAsk,
	// Codex
	"shell": ExecShell, "exec_command": ExecShell, "local_shell": ExecShell, "container.exec": ExecShell,
	"web_search": NetSearch,
	// Cursor
	"run_terminal_cmd": ExecShell, "read_file": FSRead, "edit_file": FSEdit, "search_replace": FSEdit,
	"delete_file": FSDelete, "list_dir": FSSearch, "grep_search": FSSearch, "file_search": FSSearch,
	"codebase_search": FSSearch,
	// Gemini CLI
	"run_shell_command": ExecShell, "write_file": FSWrite, "replace": FSEdit, "web_fetch": NetFetch,
	"google_web_search": NetSearch, "read_many_files": FSRead, "list_directory": FSSearch,
	"search_file_content": FSSearch,
	// OpenCode (lower-case names; CC-Monitor's opencode definition)
	"list": FSSearch, "patch": FSEdit, "question": AgentAsk,
	// Bookkeeping tools that only touch the agent's own todo list. The name
	// heuristics below would call them file reads/writes.
	"todowrite": Other, "todoread": Other,
	// generic
	"execute_command": ExecShell, "terminal": ExecShell, "run_command": ExecShell,
	"create_file": FSWrite, "str_replace_editor": FSEdit, "str_replace_based_edit_tool": FSEdit,
}

// LegacyToolClasses maps cc-monitor rule "tools" entries (Claude Code names) to classes.
func LegacyToolClasses(tools []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, t := range tools {
		c := ""
		if t == "*" {
			c = "*"
		} else if v, ok := exact[strings.ToLower(t)]; ok {
			c = v
		}
		if c != "" && !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

// Classify returns the canonical class for a raw tool name.
func Classify(raw string) string {
	l := strings.ToLower(raw)
	if strings.HasPrefix(l, "mcp__") || strings.HasPrefix(l, "mcp_") {
		return MCPCall
	}
	if c, ok := exact[l]; ok {
		return c
	}
	if strings.Contains(l, "todo") {
		return Other // todo-list bookkeeping is never a file or shell operation
	}
	switch {
	case containsAny(l, "shell", "exec", "terminal", "command", "bash"):
		return ExecShell
	case containsAny(l, "delete", "remove", "unlink"):
		return FSDelete
	case containsAny(l, "write", "create_file", "save_file"):
		return FSWrite
	case containsAny(l, "edit", "patch", "replace"):
		return FSEdit
	case containsAny(l, "fetch", "http", "browse", "url"):
		return NetFetch
	case containsAny(l, "search"):
		return NetSearch
	case containsAny(l, "read", "open_file", "view"):
		return FSRead
	}
	return Other
}

func containsAny(s string, subs ...string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

// aliases: canonical key -> raw keys seen across agents, in priority order.
var aliases = map[string][]string{
	"command":   {"command", "cmd", "commandLine", "script"},
	"file_path": {"file_path", "path", "notebook_path", "target_file", "absolute_path", "filePath", "filename"},
	"content":   {"content", "new_string", "new_source", "code_edit", "file_text", "text", "contents", "newString", "patchText"},
	"url":       {"url", "uri"},
	"cwd":       {"workdir", "cwd", "working_directory", "directory"},
}

// Normalize builds a Call from a raw name and its JSON-decoded arguments.
// It never drops the raw keys; it only adds canonical aliases that are missing.
// apply_patch-style composite calls are expanded into one Call per file.
func Normalize(id, raw string, args map[string]any) []Call {
	if args == nil {
		args = map[string]any{}
	}
	norm := make(map[string]any, len(args)+4)
	for k, v := range args {
		norm[k] = v
	}
	for canon, keys := range aliases {
		if _, ok := norm[canon]; ok && canon != "command" {
			continue
		}
		for _, k := range keys {
			if v, ok := args[k]; ok && v != nil {
				norm[canon] = v
				break
			}
		}
	}
	// Codex style: command is an argv array, often ["bash","-lc","<script>"].
	if arr, ok := norm["command"].([]any); ok {
		norm["command"] = argvToCommand(arr)
	}
	class := Classify(raw)
	if strings.EqualFold(raw, "apply_patch") || (class == FSEdit && isPatch(norm)) {
		if calls := expandPatch(id, raw, norm); len(calls) > 0 {
			return calls
		}
	}
	return []Call{{ID: id, Raw: raw, Class: class, Args: norm}}
}

func argvToCommand(arr []any) string {
	parts := make([]string, 0, len(arr))
	for _, a := range arr {
		s, _ := a.(string)
		parts = append(parts, s)
	}
	if len(parts) >= 3 {
		base := parts[0]
		if i := strings.LastIndexByte(base, '/'); i >= 0 {
			base = base[i+1:]
		}
		switch base {
		case "bash", "sh", "zsh", "dash":
			if strings.HasPrefix(parts[1], "-") && strings.Contains(parts[1], "c") {
				return strings.Join(parts[2:], " ")
			}
		}
	}
	return strings.Join(parts, " ")
}

func isPatch(args map[string]any) bool {
	s, _ := args["input"].(string)
	if s == "" {
		s, _ = args["patch"].(string)
	}
	return strings.Contains(s, "*** Begin Patch")
}

// expandPatch splits a Codex apply_patch body into per-file write/edit/delete calls.
func expandPatch(id, raw string, args map[string]any) []Call {
	body, _ := args["input"].(string)
	if body == "" {
		body, _ = args["patch"].(string)
	}
	if body == "" {
		if cmd, ok := args["command"].(string); ok {
			body = cmd
		}
	}
	var calls []Call
	var cur *Call
	var buf strings.Builder
	flush := func() {
		if cur != nil {
			cur.Args["content"] = buf.String()
			calls = append(calls, *cur)
		}
		cur = nil
		buf.Reset()
	}
	for _, line := range strings.Split(body, "\n") {
		var class, path string
		switch {
		case strings.HasPrefix(line, "*** Add File: "):
			class, path = FSWrite, strings.TrimPrefix(line, "*** Add File: ")
		case strings.HasPrefix(line, "*** Update File: "):
			class, path = FSEdit, strings.TrimPrefix(line, "*** Update File: ")
		case strings.HasPrefix(line, "*** Delete File: "):
			class, path = FSDelete, strings.TrimPrefix(line, "*** Delete File: ")
		case strings.HasPrefix(line, "*** End Patch"):
			flush()
			continue
		}
		if class != "" {
			flush()
			a := map[string]any{"file_path": strings.TrimSpace(path)}
			for k, v := range args {
				if _, ok := a[k]; !ok && k != "content" {
					a[k] = v
				}
			}
			cur = &Call{ID: id, Raw: raw, Class: class, Args: a}
			continue
		}
		if cur != nil && (strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++")) {
			buf.WriteString(line[1:])
			buf.WriteByte('\n')
		}
	}
	flush()
	return calls
}

// ParseArgs decodes a JSON argument string (OpenAI function.arguments).
func ParseArgs(s string) map[string]any {
	m := map[string]any{}
	if strings.TrimSpace(s) == "" {
		return m
	}
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return map[string]any{"_raw": s}
	}
	return m
}

// Summary renders the most representative argument for display.
func (c Call) Summary() string {
	for _, k := range []string{"command", "file_path", "url", "query"} {
		if s, ok := c.Args[k].(string); ok && s != "" {
			return s
		}
	}
	b, _ := json.Marshal(c.Args)
	s := string(b)
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}
