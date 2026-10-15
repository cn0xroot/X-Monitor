//go:build !darwin && !linux

package enforce

import "errors"

// Tier names the enforcement mechanism available on this platform.
const Tier = "none"

// Available reports whether kernel-enforced sandboxing is usable here.
func Available() (bool, string) {
	return false, "no managed-mode sandbox on this platform yet (Windows: use the firewall and kill tiers)"
}

// Wrap is unsupported on this platform.
func Wrap(p *Policy, projectRoot string, argv []string) ([]string, error) {
	return nil, errors.New("sandbox not supported on this platform")
}
