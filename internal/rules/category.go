package rules

import "strings"

// Threat categories shown on the dashboard overview ("Security" cards).
const (
	CatDestruction = "destruction" // deleting / overwriting / force-rewriting
	CatCredentials = "credentials" // reading or writing secrets and sensitive files
	CatExfil       = "exfiltration"
	CatSupplyChain = "supply_chain" // installing or executing untrusted code
	CatPersistence = "persistence"
	CatPrivilege   = "privilege"
	CatC2          = "c2"        // reverse shells, tunnels, miners, offensive tooling, sandbox escapes
	CatWorkspace   = "workspace" // touching paths outside the project
	CatEvasion     = "evasion"   // tampering with or bypassing the monitor / agent config
	CatInjection   = "injection" // prompt injection in tool results
	CatOther       = "other"
)

// Categories lists every category in display order.
var Categories = []string{
	CatDestruction, CatCredentials, CatExfil, CatSupplyChain, CatPersistence,
	CatPrivilege, CatC2, CatWorkspace, CatEvasion, CatInjection,
}

var categoryOf = map[string]string{
	// destruction
	"dangerous_delete": CatDestruction, "disk_overwrite": CatDestruction, "fork_bomb": CatDestruction,
	"chmod_world_writable_recursive": CatDestruction, "chown_root_recursive": CatDestruction,
	"chgrp_root_recursive": CatDestruction, "git_force_push": CatDestruction,
	"git_hard_reset_clean": CatDestruction, "db_destructive_command": CatDestruction,
	"history_tampering": CatDestruction, "process_kill": CatDestruction,
	// supply chain (explicit; the package-manager family is matched by substring below)
	"curl_pipe_shell": CatSupplyChain, "curl_download_then_exec": CatSupplyChain,
	"encoded_payload_exec": CatSupplyChain, "npx_pipx_ephemeral_run": CatSupplyChain,
	// persistence
	"crontab_persistence": CatPersistence, "systemd_persistence": CatPersistence,
	"git_hooks_persistence": CatPersistence, "git_hooks_file_write": CatPersistence,
	"shell_rc_write": CatPersistence, "ssh_authorized_keys_bash_write": CatPersistence,
	"user_account_management": CatPersistence,
	// privilege
	"sudo_usage": CatPrivilege, "su_pkexec_privilege_escalation": CatPrivilege,
	"setuid_setgid_bit": CatPrivilege, "chmod_777_single_file": CatPrivilege,
	"chmod_recursive_generic": CatPrivilege,
	// command & control / offensive tooling
	"reverse_shell_pattern": CatC2, "shell_escape_via_utility": CatC2, "ssh_tunnel_reverse_proxy": CatC2,
	"covert_tunnel_tool_execution": CatC2, "c2_framework_execution": CatC2,
	"post_exploitation_tool_execution": CatC2, "pentest_recon_tool_execution": CatC2,
	"mcp_suspicious_tool_name": CatC2, "crypto_miner_pool_domain_command": CatC2,
	"crypto_miner_pool_domain_write": CatC2, "webshell_pattern_in_write": CatC2,
	"dynamic_exec_in_write": CatC2, "docker_privileged_or_host_mount": CatC2,
	"db_arbitrary_file_write": CatC2, "db_arbitrary_file_write_content": CatC2,
	// credentials
	"sensitive_file_read": CatCredentials, "sensitive_file_read_bash": CatCredentials,
	"sensitive_file_write": CatCredentials, "browser_credential_read": CatCredentials,
	"browser_credential_read_bash": CatCredentials, "cloud_vpn_config_read": CatCredentials,
	"cloud_vpn_config_write": CatCredentials, "env_dump": CatCredentials, "proc_env_read": CatCredentials,
	"credential_grep_scan": CatCredentials, "history_read": CatCredentials,
	"history_file_read": CatCredentials, "secret_pattern_in_write": CatCredentials,
	"pii_pattern_in_write": CatCredentials,
	// exfiltration (sequence rule synthesized by the decision engine)
	"read_then_egress": CatExfil,
	// evasion
	"claude_config_tamper": CatEvasion, "disable_security_controls": CatEvasion,
	// workspace
	"system_config_write": CatWorkspace,
}

// Category returns the dashboard category of a rule id. Rules not listed
// explicitly fall back to naming conventions; anything unknown is "other".
func Category(id string) string {
	if c, ok := categoryOf[id]; ok {
		return c
	}
	switch {
	case strings.HasPrefix(id, "xmon_"):
		return CatEvasion
	case strings.HasPrefix(id, "workdir_escape"):
		return CatWorkspace
	case strings.Contains(id, "install"), strings.HasPrefix(id, "pip_"), strings.HasPrefix(id, "uv_"),
		strings.HasPrefix(id, "npm_"), strings.HasPrefix(id, "js_package"), strings.Contains(id, "package"),
		strings.HasPrefix(id, "toolchain"), strings.HasPrefix(id, "container_image"),
		strings.HasPrefix(id, "editor_plugin"), strings.HasPrefix(id, "source_build"):
		return CatSupplyChain
	}
	return CatOther
}

// AlertCategory maps non-rule alert event types to a category ("" = none).
func AlertCategory(typ string) string {
	switch typ {
	case "secret_egress":
		return CatExfil
	case "prompt_injection":
		return CatInjection
	case "hook_bypass", "blocked_but_executed", "silent_sensitive_write", "exec_denied":
		return CatEvasion
	}
	return ""
}

// AlertTypes returns the alert event types that belong to a category.
func AlertTypes(cat string) []string {
	var out []string
	for _, t := range []string{"secret_egress", "prompt_injection", "hook_bypass", "blocked_but_executed", "silent_sensitive_write", "exec_denied"} {
		if AlertCategory(t) == cat {
			out = append(out, t)
		}
	}
	return out
}

// RulesIn returns the ids of the loaded rules that belong to a category.
func (e *Engine) RulesIn(cat string) []string {
	var out []string
	for _, r := range e.Rules() {
		if Category(r.ID) == cat {
			out = append(out, r.ID)
		}
	}
	if cat == CatExfil {
		out = append(out, "read_then_egress") // synthesized, not in the rule file
	}
	return out
}
