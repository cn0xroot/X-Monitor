//go:build linux

package enforce

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"unsafe"
)

// Landlock syscall numbers are identical on every architecture.
const (
	sysLandlockCreateRuleset = 444
	sysLandlockAddRule       = 445
	sysLandlockRestrictSelf  = 446

	llCreateRulesetVersion = 1 << 0
	llRulePathBeneath      = 1

	prSetNoNewPrivs = 38
)

// Filesystem access rights (include/uapi/linux/landlock.h).
const (
	accExecute    = 1 << 0
	accWriteFile  = 1 << 1
	accReadFile   = 1 << 2
	accReadDir    = 1 << 3
	accRemoveDir  = 1 << 4
	accRemoveFile = 1 << 5
	accMakeChar   = 1 << 6
	accMakeDir    = 1 << 7
	accMakeReg    = 1 << 8
	accMakeSock   = 1 << 9
	accMakeFifo   = 1 << 10
	accMakeBlock  = 1 << 11
	accMakeSym    = 1 << 12
	accRefer      = 1 << 13 // ABI >= 2
	accTruncate   = 1 << 14 // ABI >= 3
)

// Tier names the enforcement mechanism available on this platform.
const Tier = "landlock"

// ABI returns the kernel's Landlock ABI version, or an error if Landlock is
// unsupported or disabled (kernel < 5.13, or not in the active LSM list).
func ABI() (int, error) {
	v, _, errno := syscall.Syscall(sysLandlockCreateRuleset, 0, 0, llCreateRulesetVersion)
	if errno != 0 {
		return 0, errno
	}
	return int(v), nil
}

// Available reports whether Landlock can be used here.
func Available() (bool, string) {
	if _, err := ABI(); err != nil {
		return false, "landlock unavailable: " + err.Error() + " (needs Linux >= 5.13 with landlock in the LSM list)"
	}
	return true, ""
}

// writeRights is the set of rights the ruleset *handles* (denies unless a rule
// grants it). Reading is intentionally left unrestricted: the goal is "the
// agent can't modify things outside its workspace", not a full jail.
func writeRights(abi int) uint64 {
	r := uint64(accWriteFile | accRemoveDir | accRemoveFile | accMakeChar | accMakeDir |
		accMakeReg | accMakeSock | accMakeFifo | accMakeBlock | accMakeSym)
	if abi >= 2 {
		r |= accRefer // without this, cross-directory rename/link is always denied
	}
	if abi >= 3 {
		r |= accTruncate
	}
	return r
}

// Apply restricts the calling thread (and everything it later spawns) so that
// filesystem writes are only possible beneath the rw roots. Non-existent roots
// are skipped. The caller must have locked its OS thread; Landlock domains are
// per-thread, and are inherited across fork and exec.
func Apply(rw []string) error {
	abi, err := ABI()
	if err != nil {
		return fmt.Errorf("landlock: %w", err)
	}
	handled := writeRights(abi)
	attr := handled // struct landlock_ruleset_attr { __u64 handled_access_fs; }
	fd, _, errno := syscall.Syscall(sysLandlockCreateRuleset, uintptr(unsafe.Pointer(&attr)), 8, 0)
	if errno != 0 {
		return fmt.Errorf("landlock_create_ruleset: %w", errno)
	}
	rulesetFd := int(fd)
	defer syscall.Close(rulesetFd)

	for _, root := range rw {
		if err := addPathRule(rulesetFd, root, handled); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("landlock rule %s: %w", root, err)
		}
	}
	if _, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0, 0, 0, 0); errno != 0 {
		return fmt.Errorf("prctl(NO_NEW_PRIVS): %w", errno)
	}
	if _, _, errno := syscall.Syscall(sysLandlockRestrictSelf, uintptr(rulesetFd), 0, 0); errno != 0 {
		return fmt.Errorf("landlock_restrict_self: %w", errno)
	}
	return nil
}

func addPathRule(rulesetFd int, path string, handled uint64) error {
	pfd, err := syscall.Open(path, 0x200000|syscall.O_CLOEXEC, 0) // O_PATH
	if err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return os.ErrNotExist
		}
		return err
	}
	defer syscall.Close(pfd)
	var st syscall.Stat_t
	if err := syscall.Fstat(pfd, &st); err != nil {
		return err
	}
	allowed := handled
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		// A rule on a regular file may only carry file-applicable rights.
		allowed &= accWriteFile | accTruncate
	}
	// struct landlock_path_beneath_attr is packed: u64 allowed_access; s32 parent_fd.
	buf := make([]byte, 12)
	binary.NativeEndian.PutUint64(buf[0:8], allowed)
	binary.NativeEndian.PutUint32(buf[8:12], uint32(pfd))
	if _, _, errno := syscall.Syscall6(sysLandlockAddRule, uintptr(rulesetFd), llRulePathBeneath,
		uintptr(unsafe.Pointer(&buf[0])), 0, 0, 0); errno != 0 {
		return errno
	}
	return nil
}

// RunSandboxed applies Landlock to this process and execs argv. It returns
// only on error. It pins the OS thread so the restriction survives the exec.
func RunSandboxed(rw []string, argv []string) error {
	if len(argv) == 0 {
		return errors.New("no command")
	}
	runtime.LockOSThread()
	if err := Apply(rw); err != nil {
		return err
	}
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return err
	}
	return syscall.Exec(path, argv, os.Environ())
}

// Wrap returns argv that re-executes xmon in its hidden sandbox mode, which
// applies Landlock and then execs the real command (seccomp/Landlock can only
// be installed by the process itself, so a launcher helper is required).
func Wrap(p *Policy, projectRoot string, argv []string) ([]string, error) {
	if ok, why := Available(); !ok {
		return nil, errors.New(why)
	}
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	out := []string{self, "__sandbox"}
	roots := append([]string{}, p.WritableRoots...)
	if projectRoot != "" {
		roots = append(roots, projectRoot)
	}
	for _, r := range uniqSorted(roots) {
		out = append(out, "--rw", r)
	}
	out = append(out, "--")
	return append(out, argv...), nil
}
