package proxy

import "regexp"

// injectionRE is a cheap first-pass heuristic for prompt injection in
// untrusted tool results (DESIGN.md §7.6). GLM does the semantic check; this
// just flags the obvious patterns so the session gets tainted immediately.
var injectionRE = regexp.MustCompile(`(?i)(ignore (all |your )?(previous|prior|above) (instructions|prompts)` +
	`|disregard (the |all )?(above|previous|prior|earlier)` +
	`|you are now (a|an|in)` +
	`|new (system )?(instructions|prompt)s?:` +
	`|<\s*(system|important)\s*>` +
	`|do not (tell|inform|mention to) the user` +
	`|(reveal|print|output|exfiltrate).{0,30}(system prompt|api[_ ]?key|secret|credential|\.env)` +
	`|run the following command)`)
