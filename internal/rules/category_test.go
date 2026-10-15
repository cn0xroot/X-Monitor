package rules

import (
	"sort"
	"testing"
)

// Rules that are informational (a search, a question to the user, an outbound
// request) and deliberately do not belong to a threat category. A new rule that
// lands here by accident should be categorized or added to this list on purpose.
var uncategorizedOK = map[string]bool{
	"web_search": true, "user_clarifying_question": true, "outbound_request": true,
	"mcp_suspicious_tool_name_other": true,
}

func TestEveryDefaultRuleIsCategorized(t *testing.T) {
	e, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	valid := map[string]bool{CatOther: true}
	for _, c := range Categories {
		valid[c] = true
	}
	var others []string
	counts := map[string]int{}
	for _, r := range e.Rules() {
		c := Category(r.ID)
		if !valid[c] {
			t.Errorf("%s: invalid category %q", r.ID, c)
		}
		counts[c]++
		if c == CatOther && !uncategorizedOK[r.ID] {
			others = append(others, r.ID)
		}
	}
	sort.Strings(others)
	if len(others) > 0 {
		t.Errorf("rules without a threat category (categorize them in category.go): %v", others)
	}
	for _, c := range Categories {
		if c == CatInjection || c == CatExfil {
			continue // driven by alerts / the session-sequence rule, not by static rules
		}
		if counts[c] == 0 {
			t.Errorf("category %q has no rules; the overview card would always be empty", c)
		}
	}
	t.Logf("rules per category: %v", counts)
}

func TestCategoryHelpers(t *testing.T) {
	if Category("xmon_self_read") != CatEvasion || Category("workdir_escape_read_other") != CatWorkspace {
		t.Error("prefix fallbacks broken")
	}
	if Category("no_such_rule") != CatOther {
		t.Error("unknown rules must be 'other'")
	}
	if AlertCategory("secret_egress") != CatExfil || AlertCategory("prompt_injection") != CatInjection || AlertCategory("agent_seen") != "" {
		t.Error("alert categories wrong")
	}
	e, _ := New("")
	if got := e.RulesIn(CatExfil); len(got) == 0 || got[len(got)-1] != "read_then_egress" {
		t.Errorf("exfil must include the synthesized sequence rule: %v", got)
	}
}
