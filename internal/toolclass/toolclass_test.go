package toolclass

import "testing"

func TestOpenCodeToolNames(t *testing.T) {
	want := map[string]string{
		"bash": ExecShell, "read": FSRead, "write": FSWrite, "edit": FSEdit, "patch": FSEdit, "multiedit": FSEdit,
		"glob": FSSearch, "grep": FSSearch, "list": FSSearch, "webfetch": NetFetch, "websearch": NetSearch,
		"task": AgentSpawn, "question": AgentAsk, "todowrite": Other, "todoread": Other,
	}
	for name, class := range want {
		if got := Classify(name); got != class {
			t.Errorf("Classify(%q)=%s want %s", name, got, class)
		}
	}
}

// Claude Code's TodoWrite is not a file write; counting it as one inflated the
// "file writes" statistic and fed path rules a call that has no path.
func TestTodoToolsAreNotFileOperations(t *testing.T) {
	for _, n := range []string{"TodoWrite", "TodoRead", "todowrite", "todo_write", "UpdateTodoList"} {
		if got := Classify(n); got != Other {
			t.Errorf("Classify(%q)=%s, want other", n, got)
		}
	}
	// ...without breaking the genuine ones
	if Classify("write_file") != FSWrite || Classify("Write") != FSWrite || Classify("read_file") != FSRead {
		t.Error("real file tools must keep their class")
	}
}

func TestOpenCodeFieldAliases(t *testing.T) {
	c := Normalize("c", "edit", map[string]any{"filePath": "/etc/hosts", "oldString": "a", "newString": "-----BEGIN PRIVATE KEY-----"})[0]
	if c.Class != FSEdit || c.Args["file_path"] != "/etc/hosts" {
		t.Errorf("edit: %+v", c)
	}
	if c.Args["content"] != "-----BEGIN PRIVATE KEY-----" {
		t.Errorf("newString must reach `content` so secret-in-write rules can see it: %v", c.Args["content"])
	}
	p := Normalize("c", "patch", map[string]any{"filePath": "/x", "patchText": "diff body"})[0]
	if p.Args["content"] != "diff body" {
		t.Errorf("patchText must reach `content`: %v", p.Args["content"])
	}
	// the original keys are preserved
	if c.Args["filePath"] != "/etc/hosts" {
		t.Error("raw keys must not be dropped")
	}
}
