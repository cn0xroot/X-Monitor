// X-Monitor plugin for OpenCode: forwards every tool call to xmon-hook, which
// applies the rules, asks for approval when needed, and records the call.
// Installed by `xmon install --agent opencode` into ~/.config/opencode/plugins/.
// The hook path is written at install time; XMON_HOOK overrides it.
//
// Design adapted from CC-Monitor's OpenCode plugin (MIT License, see NOTICE).
// tool.execute.before runs the hook synchronously; exit code 2 means "blocked",
// and throwing makes OpenCode report the tool call as failed to the model.
// Any other non-zero exit (a bug in the monitor) fails open.
import { spawnSync } from "node:child_process";

const HOOK_BIN = process.env.XMON_HOOK || "__XMON_HOOK_BIN__";
const TIMEOUT_MS = 100 * 1000; // approvals wait for a human

function runHook(mode, payload) {
  const r = spawnSync(HOOK_BIN, [mode, "--agent", "opencode"], {
    input: JSON.stringify(payload),
    encoding: "utf8",
    timeout: TIMEOUT_MS,
    stdio: ["pipe", "pipe", "pipe"],
  });
  return { code: r.status, stderr: r.stderr || "" };
}

export const XmonPlugin = async ({ directory, worktree }) => {
  const cwd = worktree || directory || process.cwd();
  return {
    "tool.execute.before": async (input, output) => {
      const r = runHook("pre", {
        hook_event_name: "tool.execute.before",
        session_id: input.sessionID,
        call_id: input.callID,
        tool_name: input.tool,
        tool_input: output.args || {},
        cwd,
      });
      if (r.code === 2) {
        throw new Error(r.stderr.trim() || "[X-Monitor] operation blocked");
      }
    },
    "tool.execute.after": async (input, output) => {
      runHook("post", {
        hook_event_name: "tool.execute.after",
        session_id: input.sessionID,
        call_id: input.callID,
        tool_name: input.tool,
        tool_input: input.args || {},
        tool_response: {
          title: output.title,
          output: typeof output.output === "string" ? output.output.slice(0, 4000) : output.output,
        },
        cwd,
      });
    },
  };
};

export default XmonPlugin;
