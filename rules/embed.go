// Package rules embeds the built-in rule set.
//
// default_rules.json = X-Monitor self-protection rules followed by the
// cc-monitor rule set (MIT License, see NOTICE). Order matters: first match wins.
package rules

import _ "embed"

//go:embed default_rules.json
var JSON []byte
