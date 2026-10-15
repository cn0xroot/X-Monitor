//go:build !linux && !darwin && !windows

package probe

import "context"

// New returns a no-op backend on platforms without an L1 collector yet
// (Windows ETW is tracked in DESIGN.md §11.3).
func New() Backend { return noneBackend{} }

type noneBackend struct{}

func (noneBackend) Name() string { return "none" }
func (noneBackend) Available() (bool, string) {
	return false, "no L1 backend on this platform yet"
}
func (noneBackend) Start(ctx context.Context, _ chan<- Exec, _ chan<- Connect) error {
	<-ctx.Done()
	return nil
}
