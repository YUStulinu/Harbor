package container

import (
	"fmt"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

// capNumbers maps capability names (as in config.json) to their numbers (linux/capability.h).
var capNumbers = map[string]uint{
	"CAP_CHOWN": 0, "CAP_DAC_OVERRIDE": 1, "CAP_DAC_READ_SEARCH": 2, "CAP_FOWNER": 3, "CAP_FSETID": 4,
	"CAP_KILL": 5, "CAP_SETGID": 6, "CAP_SETUID": 7, "CAP_SETPCAP": 8, "CAP_LINUX_IMMUTABLE": 9,
	"CAP_NET_BIND_SERVICE": 10, "CAP_NET_BROADCAST": 11, "CAP_NET_ADMIN": 12, "CAP_NET_RAW": 13,
	"CAP_IPC_LOCK": 14, "CAP_IPC_OWNER": 15, "CAP_SYS_MODULE": 16, "CAP_SYS_RAWIO": 17, "CAP_SYS_CHROOT": 18,
	"CAP_SYS_PTRACE": 19, "CAP_SYS_PACCT": 20, "CAP_SYS_ADMIN": 21, "CAP_SYS_BOOT": 22, "CAP_SYS_NICE": 23,
	"CAP_SYS_RESOURCE": 24, "CAP_SYS_TIME": 25, "CAP_SYS_TTY_CONFIG": 26, "CAP_MKNOD": 27, "CAP_LEASE": 28,
	"CAP_AUDIT_WRITE": 29, "CAP_AUDIT_CONTROL": 30, "CAP_SETFCAP": 31, "CAP_MAC_OVERRIDE": 32,
	"CAP_MAC_ADMIN": 33, "CAP_SYSLOG": 34, "CAP_WAKE_ALARM": 35, "CAP_BLOCK_SUSPEND": 36,
	"CAP_AUDIT_READ": 37, "CAP_PERFMON": 38, "CAP_BPF": 39, "CAP_CHECKPOINT_RESTORE": 40,
}

// lastCap is the highest capability the running kernel knows.
func lastCap() uint {
	b, err := readFileString("/proc/sys/kernel/cap_last_cap")
	if err != nil {
		return 40
	}
	var n uint
	fmt.Sscanf(strings.TrimSpace(b), "%d", &n)
	return n
}

// capMask turns a list of names into a 64-bit set. Names the kernel does not know are ignored
// (the spec says a runtime SHOULD NOT fail on those), unknown names are errors.
func capMask(names []string, last uint) (uint64, error) {
	var m uint64
	for _, n := range names {
		c, ok := capNumbers[strings.ToUpper(n)]
		if !ok {
			return 0, fmt.Errorf("unknown capability %q", n)
		}
		if c > last {
			continue
		}
		m |= 1 << c
	}
	return m, nil
}

type capSets struct {
	bounding, effective, permitted, inheritable, ambient uint64
}

func parseCaps(c *specs.LinuxCapabilities) (capSets, error) {
	var s capSets
	if c == nil {
		return s, nil
	}
	last := lastCap()
	var err error
	for _, x := range []struct {
		dst   *uint64
		names []string
	}{{&s.bounding, c.Bounding}, {&s.effective, c.Effective}, {&s.permitted, c.Permitted}, {&s.inheritable, c.Inheritable}, {&s.ambient, c.Ambient}} {
		if *x.dst, err = capMask(x.names, last); err != nil {
			return s, err
		}
	}
	return s, nil
}

// dropBounding removes every capability not in the bounding set (needs CAP_SETPCAP).
func dropBounding(keep uint64) error {
	last := lastCap()
	for c := uint(0); c <= last; c++ {
		if keep&(1<<c) != 0 {
			continue
		}
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0); err != nil && err != unix.EINVAL {
			return fmt.Errorf("dropping capability %d from the bounding set: %w", c, err)
		}
	}
	return nil
}

// setCaps sets the effective/permitted/inheritable sets of the calling thread, then raises the
// ambient ones.
func setCaps(s capSets) error {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{
		{Effective: uint32(s.effective), Permitted: uint32(s.permitted), Inheritable: uint32(s.inheritable)},
		{Effective: uint32(s.effective >> 32), Permitted: uint32(s.permitted >> 32), Inheritable: uint32(s.inheritable >> 32)},
	}
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capset: %w", err)
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil && err != unix.EINVAL {
		return fmt.Errorf("clearing ambient capabilities: %w", err)
	}
	for c := uint(0); c < 64; c++ {
		if s.ambient&(1<<c) == 0 {
			continue
		}
		if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_RAISE, uintptr(c), 0, 0); err != nil {
			return fmt.Errorf("raising ambient capability %d: %w", c, err)
		}
	}
	return nil
}
