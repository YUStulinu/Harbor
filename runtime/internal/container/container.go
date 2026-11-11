// Package container implements the OCI runtime operations (create, start, state, kill,
// delete) and the container's init process.
//
// create starts `/proc/self/exe init` in new namespaces (clone3 places it directly in the
// container's cgroup) and talks to it over two pipes:
//
//	parent -> init: the config;                  init -> parent: "ns-ready"
//	parent: runs the createRuntime/prestart hooks
//	parent -> init: "continue";                  init: mounts, pivot_root, limits ...
//	                                             init -> parent: "ready" (or an error)
//
// The init then blocks opening exec.fifo for writing. start opens it for reading; the init
// writes a byte, runs the startContainer hooks, drops privileges, loads seccomp and execs the
// container process. This is the same split as runc's create/start.
package container

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"

	"github.com/YUStulinu/Harbor/runtime/internal/cgroups"
)

// message is one line on the parent/init pipes.
type message struct {
	Type   string      `json:"type"`
	Error  string      `json:"error,omitempty"`
	Config *initConfig `json:"config,omitempty"`
	Pid    int         `json:"pid,omitempty"`
}

// initConfig is what the init process needs.
type initConfig struct {
	Spec   *specs.Spec `json:"spec"`
	Rootfs string      `json:"rootfs"`
	Fifo   string      `json:"fifo"`
	ID     string      `json:"id"`
	Bundle string      `json:"bundle"`
}

// CreateOptions are the flags of `create`.
type CreateOptions struct {
	PidFile string
	// Stdio for the container process; nil means the runtime's own (OCI pass-through).
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	// Keep the init as our child (for `run`, which waits for it).
	KeepChild bool
}

var nsFlags = map[specs.LinuxNamespaceType]uintptr{
	specs.PIDNamespace: unix.CLONE_NEWPID, specs.NetworkNamespace: unix.CLONE_NEWNET,
	specs.MountNamespace: unix.CLONE_NEWNS, specs.IPCNamespace: unix.CLONE_NEWIPC,
	specs.UTSNamespace: unix.CLONE_NEWUTS, specs.UserNamespace: unix.CLONE_NEWUSER,
	specs.CgroupNamespace: unix.CLONE_NEWCGROUP, specs.TimeNamespace: unix.CLONE_NEWTIME,
}

// LoadSpec reads and checks a bundle's config.json.
func LoadSpec(bundle string) (*specs.Spec, error) {
	b, err := os.ReadFile(filepath.Join(bundle, "config.json"))
	if err != nil {
		return nil, err
	}
	var s specs.Spec
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("config.json: %w", err)
	}
	if s.Root == nil || s.Root.Path == "" {
		return nil, errors.New("config.json: root.path is required")
	}
	if s.Process == nil {
		return nil, errors.New("config.json: process is required by create")
	}
	if len(s.Process.Args) == 0 {
		return nil, errors.New("config.json: process.args must not be empty")
	}
	if !strings.HasPrefix(s.Version, "1.") {
		return nil, fmt.Errorf("config.json: unsupported ociVersion %q", s.Version)
	}
	if s.Process.Terminal {
		return nil, errors.New("process.terminal is not supported (no console socket support)")
	}
	if s.Process.Cwd == "" || !filepath.IsAbs(s.Process.Cwd) {
		return nil, fmt.Errorf("process.cwd must be an absolute path, got %q", s.Process.Cwd)
	}
	if s.Linux == nil {
		s.Linux = &specs.Linux{}
	}
	// Values that map to nothing in the kernel are errors at create time (config-linux.md).
	if _, err := parseCaps(s.Process.Capabilities); err != nil {
		return nil, err
	}
	for _, r := range s.Process.Rlimits {
		if _, ok := rlimits[r.Type]; !ok {
			return nil, fmt.Errorf("unknown rlimit %s", r.Type)
		}
	}
	seen := map[specs.LinuxNamespaceType]bool{}
	for _, ns := range s.Linux.Namespaces {
		if _, ok := nsFlags[ns.Type]; !ok {
			return nil, fmt.Errorf("unknown namespace type %q", ns.Type)
		}
		if seen[ns.Type] {
			return nil, fmt.Errorf("namespace %q listed twice", ns.Type)
		}
		seen[ns.Type] = true
	}
	return &s, nil
}

func hasNS(s *specs.Spec, t specs.LinuxNamespaceType) (bool, string) {
	for _, ns := range s.Linux.Namespaces {
		if ns.Type == t {
			return true, ns.Path
		}
	}
	return false, ""
}

func send(w io.Writer, m message) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

func recv(r *bufio.Reader) (message, error) {
	line, err := r.ReadBytes('\n')
	if err != nil {
		return message{}, err
	}
	var m message
	err = json.Unmarshal(line, &m)
	return m, err
}

// Create sets the container up and leaves its init waiting for start. It returns the init
// process (only meaningful with KeepChild).
func Create(root, id, bundle string, o CreateOptions) (proc *os.Process, err error) {
	if err := ValidID(id); err != nil {
		return nil, err
	}
	bundle, err = filepath.Abs(bundle)
	if err != nil {
		return nil, err
	}
	spec, err := LoadSpec(bundle)
	if err != nil {
		return nil, err
	}
	rootfs := spec.Root.Path
	if !filepath.IsAbs(rootfs) {
		rootfs = filepath.Join(bundle, rootfs)
	}
	if fi, err := os.Stat(rootfs); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("root.path %s is not a directory", rootfs)
	}
	if err := os.MkdirAll(root, 0o711); err != nil {
		return nil, err
	}
	dir := stateDir(root, id)
	if err := os.Mkdir(dir, 0o711); err != nil {
		if os.IsExist(err) {
			return nil, fmt.Errorf("container %s already exists", id)
		}
		return nil, err
	}
	var cgDir string
	var child *exec.Cmd
	defer func() {
		if err == nil {
			return
		}
		if child != nil && child.Process != nil {
			child.Process.Kill()
			child.Wait()
		}
		if cgDir != "" {
			cgroups.Destroy(cgDir)
		}
		os.RemoveAll(dir)
	}()

	fifo := filepath.Join(dir, "exec.fifo")
	if err := unix.Mkfifo(fifo, 0o622); err != nil {
		return nil, fmt.Errorf("exec fifo: %w", err)
	}
	// mkfifo applies the umask; the init may run as a uid that is not ours (user namespace).
	if err := unix.Chmod(fifo, 0o622); err != nil {
		return nil, err
	}
	cgDir, err = cgroups.Path(spec.Linux.CgroupsPath, id)
	if err != nil {
		return nil, err
	}
	if err := cgroups.Create(cgDir, spec.Linux.Resources); err != nil {
		return nil, err
	}
	cgFD, err := unix.Open(cgDir, unix.O_DIRECTORY|unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(cgFD)

	// Pipes: parent -> init (config, continue) and init -> parent (status).
	toInitR, toInitW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	fromInitR, fromInitW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer toInitW.Close()
	defer fromInitR.Close()

	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	child = exec.Command(self, "init")
	child.Env = []string{"_HARBOR_INIT=1"}
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	if o.Stdin != nil {
		child.Stdin = o.Stdin
	}
	if o.Stdout != nil {
		child.Stdout = o.Stdout
	}
	if o.Stderr != nil {
		child.Stderr = o.Stderr
	}
	child.ExtraFiles = []*os.File{toInitR, fromInitW}
	attr := &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: cgFD}
	var joins []string
	for _, ns := range spec.Linux.Namespaces {
		if ns.Path == "" {
			attr.Cloneflags |= nsFlags[ns.Type]
			continue
		}
		if ns.Type == specs.UserNamespace {
			return nil, errors.New("joining an existing user namespace is not supported")
		}
		joins = append(joins, string(ns.Type)+"="+ns.Path)
	}
	if len(joins) > 0 {
		// Done by the C constructor in internal/nsenter, before the Go runtime starts threads.
		child.Env = append(child.Env, "_HARBOR_SETNS="+strings.Join(joins, ","))
	}
	if attr.Cloneflags&unix.CLONE_NEWUSER != 0 {
		for _, m := range spec.Linux.UIDMappings {
			attr.UidMappings = append(attr.UidMappings, syscall.SysProcIDMap{ContainerID: int(m.ContainerID), HostID: int(m.HostID), Size: int(m.Size)})
		}
		for _, m := range spec.Linux.GIDMappings {
			attr.GidMappings = append(attr.GidMappings, syscall.SysProcIDMap{ContainerID: int(m.ContainerID), HostID: int(m.HostID), Size: int(m.Size)})
		}
		attr.GidMappingsEnableSetgroups = true
		// Become root of the new user namespace before exec: our host uid is usually not
		// mapped in it, and an unmapped uid execs without capabilities.
		attr.Credential = &syscall.Credential{Uid: 0, Gid: 0, NoSetGroups: true}
	}
	child.SysProcAttr = attr
	if err := child.Start(); err != nil {
		return nil, fmt.Errorf("starting init: %w", err)
	}
	toInitR.Close()
	fromInitW.Close()
	pid := child.Process.Pid
	in := bufio.NewReader(fromInitR)

	expect := func(want string) error {
		m, err := recv(in)
		if err == nil && m.Type == "pid" {
			// Joining a pid namespace: the real init is a child of the process we started.
			pid = m.Pid
			m, err = recv(in)
		}
		if err != nil {
			return fmt.Errorf("init exited during setup (%v)", err)
		}
		if m.Type == "error" {
			return errors.New(m.Error)
		}
		if m.Type != want {
			return fmt.Errorf("init: expected %s, got %s", want, m.Type)
		}
		return nil
	}
	cfg := &initConfig{Spec: spec, Rootfs: rootfs, Fifo: fifo, ID: id, Bundle: bundle}
	if err := send(toInitW, message{Type: "config", Config: cfg}); err != nil {
		return nil, err
	}
	if err := expect("ns-ready"); err != nil {
		return nil, err
	}
	_, startTime, err := procStat(pid)
	if err != nil {
		return nil, err
	}
	pidNS, _ := hasNS(spec, specs.PIDNamespace)
	saved := &Saved{ID: id, Bundle: bundle, Rootfs: rootfs, Pid: pid, PidStartTime: startTime, Created: time.Now().UTC(),
		CgroupPath: cgDir, Annotations: spec.Annotations, OwnPidNS: pidNS}
	if spec.Hooks != nil {
		st := saved.OCIState()
		st.Status = specs.StateCreating
		if err := runHooks("createRuntime", spec.Hooks.CreateRuntime, st); err != nil {
			return nil, err
		}
		// The validation suite expects prestart hooks to see "created" (as runc 1.0 did).
		pre := st
		pre.Status = specs.StateCreated
		if err := runHooks("prestart", spec.Hooks.Prestart, pre); err != nil { //nolint:staticcheck // deprecated but still in the spec
			return nil, err
		}
	}
	if err := send(toInitW, message{Type: "continue"}); err != nil {
		return nil, err
	}
	if err := expect("ready"); err != nil {
		return nil, err
	}
	if err := save(root, saved); err != nil {
		return nil, err
	}
	if o.PidFile != "" {
		tmp := o.PidFile + ".tmp"
		if err := os.WriteFile(tmp, []byte(strconv.Itoa(pid)), 0o644); err != nil {
			return nil, err
		}
		if err := os.Rename(tmp, o.PidFile); err != nil {
			return nil, err
		}
	}
	if o.KeepChild {
		return child.Process, nil
	}
	child.Process.Release()
	return nil, nil
}

// Start lets a created container run its process.
func Start(root, id string) error {
	s, err := load(root, id)
	if err != nil {
		return err
	}
	if st := s.Status(); st != specs.StateCreated {
		return fmt.Errorf("container %s is %s, not created", id, st)
	}
	fifo := filepath.Join(stateDir(root, id), "exec.fifo")
	// The init has the fifo open for writing (it blocks until we open it), so this does not
	// block for long; O_NONBLOCK guards against an init that died in between.
	fd, err := unix.Open(fifo, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("exec fifo: %w", err)
	}
	f := os.NewFile(uintptr(fd), fifo)
	buf := make([]byte, 1)
	n, err := f.Read(buf)
	f.Close()
	if n != 1 {
		return fmt.Errorf("container %s did not start (%v)", id, err)
	}
	os.Remove(fifo)
	s.Started = true
	if err := save(root, s); err != nil {
		return err
	}
	if spec, err := LoadSpec(s.Bundle); err == nil && spec.Hooks != nil {
		if err := runHooks("poststart", spec.Hooks.Poststart, s.OCIState()); err != nil {
			// The spec: a failing poststart hook is logged; the container keeps running.
			fmt.Fprintln(os.Stderr, "warning:", err)
		}
	}
	return nil
}

// State returns the OCI state of a container.
func State(root, id string) (specs.State, error) {
	s, err := load(root, id)
	if err != nil {
		return specs.State{}, err
	}
	return s.OCIState(), nil
}

// ParseSignal accepts "KILL", "SIGKILL" or "9".
func ParseSignal(s string) (unix.Signal, error) {
	if n, err := strconv.Atoi(s); err == nil {
		if n <= 0 || n > 64 {
			return 0, fmt.Errorf("invalid signal %s", s)
		}
		return unix.Signal(n), nil
	}
	name := strings.ToUpper(s)
	if !strings.HasPrefix(name, "SIG") {
		name = "SIG" + name
	}
	sig := unix.SignalNum(name)
	if sig == 0 {
		return 0, fmt.Errorf("unknown signal %s", s)
	}
	return sig, nil
}

// Kill sends a signal to the container's process.
func Kill(root, id string, sig unix.Signal) error {
	s, err := load(root, id)
	if err != nil {
		return err
	}
	if st := s.Status(); st == specs.StateStopped {
		return fmt.Errorf("container %s is not running", id)
	}
	return unix.Kill(s.Pid, sig)
}

// Delete removes a stopped container (or any container, with force).
func Delete(root, id string, force bool) error {
	s, err := load(root, id)
	if err != nil {
		return err
	}
	if st := s.Status(); st != specs.StateStopped {
		if !force {
			return fmt.Errorf("container %s is %s; stop it first or use --force", id, st)
		}
		unix.Kill(s.Pid, unix.SIGKILL)
		for i := 0; i < 500 && s.alive(); i++ {
			time.Sleep(10 * time.Millisecond)
		}
	}
	var errs []error
	if !s.OwnPidNS {
		// Without its own pid namespace, the container's other processes outlive the init.
		if procs, _ := cgroups.Procs(s.CgroupPath); len(procs) > 0 {
			for _, p := range procs {
				unix.Kill(p, unix.SIGKILL)
			}
		}
	}
	if err := cgroups.Destroy(s.CgroupPath); err != nil {
		errs = append(errs, err)
	}
	if spec, err := LoadSpec(s.Bundle); err == nil && spec.Hooks != nil {
		st := s.OCIState()
		st.Status = specs.StateStopped
		if err := runHooks("poststop", spec.Hooks.Poststop, st); err != nil {
			fmt.Fprintln(os.Stderr, "warning:", err)
		}
	}
	if err := os.RemoveAll(stateDir(root, id)); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
