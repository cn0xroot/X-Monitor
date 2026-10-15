//go:build darwin

package enforce

import (
	"fmt"
	"os/exec"
)

// Tier names the enforcement mechanism available on this platform.
const Tier = "sandbox-exec"

// Available reports whether kernel-enforced sandboxing is usable here.
func Available() (bool, string) {
	if _, err := exec.LookPath("sandbox-exec"); err != nil {
		return false, "sandbox-exec not found"
	}
	return true, ""
}

// Wrap returns argv that runs argv under a sandbox-exec profile built from p.
// sandbox-exec is deprecated by Apple but ships on every macOS and needs no
// entitlement, which makes it the practical managed-mode sandbox.
func Wrap(p *Policy, projectRoot string, argv []string) ([]string, error) {
	if ok, why := Available(); !ok {
		return nil, fmt.Errorf("sandbox unavailable: %s", why)
	}
	prof := SandboxProfile(p, projectRoot)
	return append([]string{"sandbox-exec", "-p", prof}, argv...), nil
}
