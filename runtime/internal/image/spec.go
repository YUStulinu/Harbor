// Package image runs containers from images: overlayfs root filesystems over the layers that
// harbor-registry unpacked, generated OCI configs, a bridge network, a shim that keeps logs
// and exit codes, and the HTTP API behind the web UI.
package image

import (
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// DefaultCaps is the capability set containers get (the same list Docker uses).
var DefaultCaps = []string{
	"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FSETID", "CAP_FOWNER", "CAP_MKNOD", "CAP_NET_RAW",
	"CAP_SETGID", "CAP_SETUID", "CAP_SETFCAP", "CAP_SETPCAP", "CAP_NET_BIND_SERVICE",
	"CAP_SYS_CHROOT", "CAP_KILL", "CAP_AUDIT_WRITE",
}

// DeniedSyscalls are refused with EPERM by the default seccomp profile: kernel modules,
// rebooting, swap, clocks, keyrings, BPF, perf, namespaces and mounts, accounting, and other
// calls a container has no business making. Most also need capabilities containers lack; the
// filter is a second wall.
var DeniedSyscalls = []string{
	"acct", "add_key", "bpf", "clock_adjtime", "clock_settime", "create_module", "delete_module",
	"finit_module", "fsconfig", "fsmount", "fsopen", "fspick", "get_kernel_syms", "init_module",
	"kexec_file_load", "kexec_load", "keyctl", "lookup_dcookie", "mount", "mount_setattr", "move_mount",
	"nfsservctl", "open_by_handle_at", "open_tree", "perf_event_open", "pivot_root", "query_module",
	"quotactl", "reboot", "request_key", "setns", "settimeofday", "swapoff", "swapon", "syslog",
	"umount2", "unshare", "uselib", "userfaultfd", "ustat", "vm86", "vm86old", "_sysctl",
}

// DefaultSeccomp allows everything except DeniedSyscalls.
func DefaultSeccomp() *specs.LinuxSeccomp {
	eperm := uint(1)
	return &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Architectures: []specs.Arch{specs.ArchX86_64, specs.ArchX86, specs.ArchX32},
		Syscalls:      []specs.LinuxSyscall{{Names: DeniedSyscalls, Action: specs.ActErrno, ErrnoRet: &eperm}},
	}
}

// DefaultSpec is a config.json for a container running args (like `runc spec`, with the
// network namespace, Docker's capabilities and the default seccomp profile).
func DefaultSpec(args, env []string, cwd string, _ bool) *specs.Spec {
	if cwd == "" {
		cwd = "/"
	}
	hasPath := false
	for _, e := range env {
		if len(e) > 5 && e[:5] == "PATH=" {
			hasPath = true
		}
	}
	if !hasPath {
		env = append([]string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}, env...)
	}
	caps := append([]string{}, DefaultCaps...)
	return &specs.Spec{
		Version: specs.Version,
		Root:    &specs.Root{Path: "rootfs"},
		Process: &specs.Process{
			Args: args,
			Env:  env,
			Cwd:  cwd,
			User: specs.User{UID: 0, GID: 0},
			Capabilities: &specs.LinuxCapabilities{
				Bounding: caps, Effective: caps, Permitted: caps,
			},
			Rlimits:         []specs.POSIXRlimit{{Type: "RLIMIT_NOFILE", Hard: 1048576, Soft: 1048576}},
			NoNewPrivileges: true,
		},
		Hostname: "harbor",
		Mounts: []specs.Mount{
			{Destination: "/proc", Type: "proc", Source: "proc"},
			{Destination: "/dev", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "strictatime", "mode=755", "size=65536k"}},
			{Destination: "/dev/pts", Type: "devpts", Source: "devpts", Options: []string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5"}},
			{Destination: "/dev/shm", Type: "tmpfs", Source: "shm", Options: []string{"nosuid", "noexec", "nodev", "mode=1777", "size=65536k"}},
			{Destination: "/dev/mqueue", Type: "mqueue", Source: "mqueue", Options: []string{"nosuid", "noexec", "nodev"}},
			{Destination: "/sys", Type: "sysfs", Source: "sysfs", Options: []string{"nosuid", "noexec", "nodev", "ro"}},
			{Destination: "/sys/fs/cgroup", Type: "cgroup", Source: "cgroup", Options: []string{"nosuid", "noexec", "nodev", "relatime", "ro"}},
		},
		Linux: &specs.Linux{
			Namespaces: []specs.LinuxNamespace{
				{Type: specs.PIDNamespace}, {Type: specs.NetworkNamespace}, {Type: specs.IPCNamespace},
				{Type: specs.UTSNamespace}, {Type: specs.MountNamespace}, {Type: specs.CgroupNamespace},
			},
			MaskedPaths: []string{
				"/proc/acpi", "/proc/asound", "/proc/kcore", "/proc/keys", "/proc/latency_stats", "/proc/timer_list",
				"/proc/timer_stats", "/proc/sched_debug", "/sys/firmware", "/proc/scsi", "/sys/devices/virtual/powercap",
			},
			ReadonlyPaths: []string{"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"},
			Seccomp:       DefaultSeccomp(),
		},
	}
}
