package container

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"

	"github.com/YUStulinu/Harbor/runtime/internal/seccomp"
)

// Init is the container's init process (`harbor init`, started by Create). The caller must
// have locked the main goroutine to the main OS thread: credentials, capabilities and the
// seccomp filter are per thread, and the thread that sets them must be the one that execs.
func Init() {
	toParent := os.NewFile(4, "to-parent")
	fromParent := bufio.NewReader(os.NewFile(3, "from-parent"))
	fail := func(err error) {
		send(toParent, message{Type: "error", Error: err.Error()})
		os.Exit(1)
	}
	m, err := recv(fromParent)
	if err != nil || m.Type != "config" || m.Config == nil {
		fail(fmt.Errorf("init: no config from the runtime (%v)", err))
	}
	cfg := m.Config
	// The fifo lives in the runtime's state directory, which pivot_root or chroot hides: keep
	// a handle on the directory and open the fifo relative to it later (openat works through
	// both, and needs no /proc in the container).
	stateFD, err := unix.Open(filepath.Dir(cfg.Fifo), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		fail(fmt.Errorf("init: state directory: %w", err))
	}
	if err := send(toParent, message{Type: "ns-ready"}); err != nil {
		os.Exit(1)
	}
	if m, err := recv(fromParent); err != nil || m.Type != "continue" {
		os.Exit(1) // the runtime gave up (a hook failed); it reports the error
	}
	path, err := setup(cfg)
	if err != nil {
		fail(err)
	}
	if err := send(toParent, message{Type: "ready"}); err != nil {
		os.Exit(1)
	}
	os.NewFile(3, "").Close()
	toParent.Close()

	// Wait for start: opening the fifo for writing blocks until start opens it for reading.
	fd, err := unix.Openat(stateFD, filepath.Base(cfg.Fifo), unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "harbor init: exec fifo:", err)
		os.Exit(1)
	}
	unix.Write(fd, []byte{0})
	unix.Close(fd)
	unix.Close(stateFD)
	if err := finish(cfg, path); err != nil {
		fmt.Fprintln(os.Stderr, "harbor init:", err)
		os.Exit(127)
	}
}

// setup does everything that can fail before the container is "created": the root
// filesystem, devices, hostname, sysctls, limits, and finding the program to run.
func setup(cfg *initConfig) (string, error) {
	s := cfg.Spec
	newMountNS, _ := hasNS(s, specs.MountNamespace)
	if newMountNS {
		if err := prepareRootfs(cfg); err != nil {
			return "", err
		}
		if s.Hooks != nil && len(s.Hooks.CreateContainer) > 0 {
			st := specs.State{Version: specs.Version, ID: cfg.ID, Status: specs.StateCreating, Pid: os.Getpid(), Bundle: cfg.Bundle, Annotations: s.Annotations}
			if err := runHooks("createContainer", s.Hooks.CreateContainer, st); err != nil {
				return "", err
			}
		}
		if err := pivotRoot(cfg.Rootfs); err != nil {
			return "", err
		}
		if err := finishRootfs(s); err != nil {
			return "", err
		}
	} else {
		// Without a mount namespace, mounts would change the host: only chroot.
		if err := unix.Chroot(cfg.Rootfs); err != nil {
			return "", fmt.Errorf("chroot: %w", err)
		}
	}
	if uts, _ := hasNS(s, specs.UTSNamespace); s.Hostname != "" {
		if !uts {
			return "", errors.New("hostname is set but there is no UTS namespace")
		}
		if err := unix.Sethostname([]byte(s.Hostname)); err != nil {
			return "", fmt.Errorf("sethostname: %w", err)
		}
	}
	if s.Domainname != "" {
		if err := unix.Setdomainname([]byte(s.Domainname)); err != nil {
			return "", fmt.Errorf("setdomainname: %w", err)
		}
	}
	for k, v := range s.Linux.Sysctl {
		p := filepath.Join("/proc/sys", strings.ReplaceAll(k, ".", "/"))
		if err := os.WriteFile(p, []byte(v), 0o644); err != nil {
			return "", fmt.Errorf("sysctl %s=%s: %w", k, v, err)
		}
	}
	p := s.Process
	for _, r := range p.Rlimits {
		res, ok := rlimits[r.Type]
		if !ok {
			return "", fmt.Errorf("unknown rlimit %s", r.Type)
		}
		// syscall.Setrlimit, not unix: Go raises RLIMIT_NOFILE at start-up and restores the
		// original value at exec unless the program set it through package syscall.
		if err := syscall.Setrlimit(res, &syscall.Rlimit{Cur: r.Soft, Max: r.Hard}); err != nil {
			return "", fmt.Errorf("setrlimit %s: %w", r.Type, err)
		}
	}
	if p.OOMScoreAdj != nil {
		if err := os.WriteFile("/proc/self/oom_score_adj", []byte(fmt.Sprint(*p.OOMScoreAdj)), 0o644); err != nil {
			return "", fmt.Errorf("oom_score_adj: %w", err)
		}
	}
	if err := unix.Chdir(p.Cwd); err != nil {
		return "", fmt.Errorf("process.cwd %s: %w", p.Cwd, err)
	}
	return lookPath(p.Args[0], p.Env)
}

var rlimits = map[string]int{
	"RLIMIT_AS": unix.RLIMIT_AS, "RLIMIT_CORE": unix.RLIMIT_CORE, "RLIMIT_CPU": unix.RLIMIT_CPU,
	"RLIMIT_DATA": unix.RLIMIT_DATA, "RLIMIT_FSIZE": unix.RLIMIT_FSIZE, "RLIMIT_LOCKS": unix.RLIMIT_LOCKS,
	"RLIMIT_MEMLOCK": unix.RLIMIT_MEMLOCK, "RLIMIT_MSGQUEUE": unix.RLIMIT_MSGQUEUE, "RLIMIT_NICE": unix.RLIMIT_NICE,
	"RLIMIT_NOFILE": unix.RLIMIT_NOFILE, "RLIMIT_NPROC": unix.RLIMIT_NPROC, "RLIMIT_RSS": unix.RLIMIT_RSS,
	"RLIMIT_RTPRIO": unix.RLIMIT_RTPRIO, "RLIMIT_RTTIME": unix.RLIMIT_RTTIME, "RLIMIT_SIGPENDING": unix.RLIMIT_SIGPENDING,
	"RLIMIT_STACK": unix.RLIMIT_STACK,
}

// lookPath resolves the program the way execvp would, with the container's PATH.
func lookPath(name string, env []string) (string, error) {
	if strings.Contains(name, "/") {
		if err := executable(name); err != nil {
			return "", fmt.Errorf("process.args[0] %s: %w", name, err)
		}
		return name, nil
	}
	path := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	for _, e := range env {
		if strings.HasPrefix(e, "PATH=") {
			path = e[5:]
		}
	}
	for _, dir := range filepath.SplitList(path) {
		if dir == "" {
			dir = "."
		}
		p := filepath.Join(dir, name)
		if executable(p) == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("process.args[0] %s: not found in $PATH", name)
}

func executable(p string) error {
	fi, err := os.Stat(p)
	if err != nil {
		return err
	}
	if fi.IsDir() || fi.Mode()&0o111 == 0 {
		return errors.New("not an executable file")
	}
	return nil
}

// finish runs after start: startContainer hooks, then privileges are dropped in the order
// that keeps each step possible, and the process is executed.
func finish(cfg *initConfig, path string) error {
	s := cfg.Spec
	p := s.Process
	if s.Hooks != nil && len(s.Hooks.StartContainer) > 0 {
		st := specs.State{Version: specs.Version, ID: cfg.ID, Status: specs.StateRunning, Pid: os.Getpid(), Bundle: cfg.Bundle, Annotations: s.Annotations}
		if err := runHooks("startContainer", s.Hooks.StartContainer, st); err != nil {
			return err
		}
	}
	caps, err := parseCaps(p.Capabilities)
	if err != nil {
		return err
	}
	if p.Capabilities != nil {
		if err := dropBounding(caps.bounding); err != nil {
			return err
		}
	}
	var prog []seccomp.Instruction
	if s.Linux.Seccomp != nil {
		if prog, err = seccomp.Compile(s.Linux.Seccomp); err != nil {
			return err
		}
	}
	// Without no_new_privs, loading a filter needs CAP_SYS_ADMIN: do it while we have it.
	if prog != nil && !p.NoNewPrivileges {
		if err := seccomp.Load(prog, s.Linux.Seccomp.Flags); err != nil {
			return err
		}
	}
	if p.User.Umask != nil {
		unix.Umask(int(*p.User.Umask))
	}
	if err := unix.Prctl(unix.PR_SET_KEEPCAPS, 1, 0, 0, 0); err != nil {
		return err
	}
	if err := setUser(p.User); err != nil {
		return err
	}
	if err := unix.Prctl(unix.PR_SET_KEEPCAPS, 0, 0, 0, 0); err != nil {
		return err
	}
	if p.Capabilities != nil {
		if err := setCaps(caps); err != nil {
			return err
		}
	}
	if p.NoNewPrivileges {
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			return fmt.Errorf("no_new_privs: %w", err)
		}
		if prog != nil {
			if err := seccomp.Load(prog, s.Linux.Seccomp.Flags); err != nil {
				return err
			}
		}
	}
	return syscall.Exec(path, p.Args, p.Env)
}

func setUser(u specs.User) error {
	if u.Username != "" {
		return errors.New("process.user.username is not supported; give uid and gid")
	}
	groups := make([]int, 0, len(u.AdditionalGids))
	for _, g := range u.AdditionalGids {
		groups = append(groups, int(g))
	}
	// setgroups may be denied in a user namespace; then only an empty list is acceptable.
	if err := unix.Setgroups(groups); err != nil && len(groups) > 0 {
		return fmt.Errorf("setgroups: %w", err)
	}
	// RawSyscall: change only this thread (the one that will exec), as runc does.
	if _, _, e := unix.RawSyscall(unix.SYS_SETRESGID, uintptr(u.GID), uintptr(u.GID), uintptr(u.GID)); e != 0 {
		return fmt.Errorf("setresgid(%d): %w", u.GID, e)
	}
	if _, _, e := unix.RawSyscall(unix.SYS_SETRESUID, uintptr(u.UID), uintptr(u.UID), uintptr(u.UID)); e != 0 {
		return fmt.Errorf("setresuid(%d): %w", u.UID, e)
	}
	return nil
}
