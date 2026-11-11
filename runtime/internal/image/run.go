package image

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
	"sync"
	"syscall"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"

	"github.com/YUStulinu/Harbor/runtime/internal/cgroups"
	"github.com/YUStulinu/Harbor/runtime/internal/container"
)

// ErrUsage means the command line was wrong.
var ErrUsage = errors.New("usage")

// RunOptions are the flags of run-image.
type RunOptions struct {
	Image    string
	Args     []string
	Name     string
	Env      []string
	Limits   Limits
	Net      string // bridge, none, host
	Hostname string
	ReadOnly bool
	Detach   bool
	Remove   bool
}

// ParseSize accepts 64m, 1g, 512k, 1048576.
func ParseSize(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if strings.HasSuffix(s, "b") && len(s) > 1 && (s[len(s)-2] < '0' || s[len(s)-2] > '9') {
		s = s[:len(s)-1] // "64mb" -> "64m"
	}
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "k"):
		mult, s = 1<<10, s[:len(s)-1]
	case strings.HasSuffix(s, "m"):
		mult, s = 1<<20, s[:len(s)-1]
	case strings.HasSuffix(s, "g"):
		mult, s = 1<<30, s[:len(s)-1]
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("bad size %q", s)
	}
	return n * mult, nil
}

// prepare creates the container directory, the overlay root filesystem and config.json.
func prepare(ociRoot string, o RunOptions) (*Meta, error) {
	info, err := Inspect(o.Image, true)
	if err != nil {
		return nil, err
	}
	args := o.Args
	if len(args) == 0 {
		args = append(append([]string{}, info.Config.Entrypoint...), info.Config.Cmd...)
	} else if len(info.Config.Entrypoint) > 0 {
		args = append(append([]string{}, info.Config.Entrypoint...), args...)
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("image %s has no command; give one", o.Image)
	}
	if o.Net == "" {
		o.Net = "bridge"
	}
	if o.Net != "bridge" && o.Net != "none" && o.Net != "host" {
		return nil, fmt.Errorf("--net must be bridge, none or host")
	}
	id := newID()
	name := o.Name
	if name == "" {
		name = id[:12]
	}
	if other, err := Find(name); err == nil && other.Name == name {
		return nil, fmt.Errorf("a container named %s exists (%s)", name, other.ID[:12])
	}
	m := &Meta{ID: id, Name: name, Image: info.Name, Digest: info.Digest, Args: args, Created: time.Now().UTC(),
		Net: o.Net, Limits: o.Limits, Detached: o.Detach, AutoRemove: o.Remove, OCIRoot: ociRoot}
	ok := false
	defer func() {
		if !ok {
			cleanup(m)
		}
	}()
	for _, d := range []string{m.rootfs(), filepath.Join(m.dir(), "upper"), filepath.Join(m.dir(), "work")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	// overlayfs lists lower layers top first.
	lower := make([]string, len(info.Layers))
	for i, l := range info.Layers {
		lower[len(info.Layers)-1-i] = l
	}
	opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", strings.Join(lower, ":"), filepath.Join(m.dir(), "upper"), filepath.Join(m.dir(), "work"))
	if err := unix.Mount("overlay", m.rootfs(), "overlay", 0, opts); err != nil {
		return nil, fmt.Errorf("overlay mount: %w", err)
	}
	if o.Net == "bridge" {
		if m.IP, err = allocateIP(id); err != nil {
			return nil, err
		}
	}
	hostname := o.Hostname
	if hostname == "" {
		hostname = name
	}
	if err := writeNetFiles(m, hostname); err != nil {
		return nil, err
	}
	env := append(append([]string{}, info.Config.Env...), o.Env...)
	spec := DefaultSpec(args, env, info.Config.WorkingDir, false)
	spec.Hostname = hostname
	spec.Root.Readonly = o.ReadOnly
	if info.Config.User != "" {
		uid, gid, err := resolveUser(m.rootfs(), info.Config.User)
		if err != nil {
			return nil, err
		}
		spec.Process.User = specs.User{UID: uid, GID: gid}
	}
	if o.Net == "host" {
		var ns []specs.LinuxNamespace
		for _, n := range spec.Linux.Namespaces {
			if n.Type != specs.NetworkNamespace {
				ns = append(ns, n)
			}
		}
		spec.Linux.Namespaces = ns
	}
	for _, f := range []string{"resolv.conf", "hostname", "hosts"} {
		spec.Mounts = append(spec.Mounts, specs.Mount{Destination: "/etc/" + f, Type: "bind", Source: filepath.Join(m.dir(), f), Options: []string{"rbind", "rprivate"}})
	}
	res := &specs.LinuxResources{}
	if o.Limits.MemoryBytes > 0 {
		lim := o.Limits.MemoryBytes
		res.Memory = &specs.LinuxMemory{Limit: &lim, Swap: &lim} // no swap on top
	}
	if o.Limits.CPUs > 0 {
		period := uint64(100000)
		quota := int64(o.Limits.CPUs * float64(period))
		res.CPU = &specs.LinuxCPU{Quota: &quota, Period: &period}
	}
	if o.Limits.Pids > 0 {
		res.Pids = &specs.LinuxPids{Limit: o.Limits.Pids}
	}
	spec.Linux.Resources = res
	spec.Linux.CgroupsPath = "/harbor/" + id
	spec.Annotations = map[string]string{"org.opencontainers.image.ref.name": info.Name, "harbor.name": name}
	b, _ := json.MarshalIndent(spec, "", "  ")
	if err := os.WriteFile(filepath.Join(m.bundle(), "config.json"), b, 0o644); err != nil {
		return nil, err
	}
	m.CgroupPath, _ = cgroups.Path(spec.Linux.CgroupsPath, id)
	if err := m.save(); err != nil {
		return nil, err
	}
	ok = true
	return m, nil
}

// resolveUser turns "uid", "uid:gid", "name" or "name:group" into numbers with the image's
// /etc/passwd and /etc/group.
func resolveUser(rootfs, user string) (uint32, uint32, error) {
	u, g, hasGroup := strings.Cut(user, ":")
	lookup := func(file, name string) (uint32, uint32, bool) {
		f, err := os.Open(filepath.Join(rootfs, "etc", file))
		if err != nil {
			return 0, 0, false
		}
		defer f.Close()
		s := bufio.NewScanner(f)
		for s.Scan() {
			p := strings.Split(s.Text(), ":")
			if len(p) >= 4 && p[0] == name {
				a, _ := strconv.Atoi(p[2])
				b, _ := strconv.Atoi(p[3])
				return uint32(a), uint32(b), true
			}
		}
		return 0, 0, false
	}
	var uid, gid uint32
	if n, err := strconv.Atoi(u); err == nil {
		uid, gid = uint32(n), uint32(n)
	} else if a, b, ok := lookup("passwd", u); ok {
		uid, gid = a, b
	} else {
		return 0, 0, fmt.Errorf("user %s not found in the image", u)
	}
	if hasGroup {
		if n, err := strconv.Atoi(g); err == nil {
			gid = uint32(n)
		} else if a, _, ok := lookup("group", g); ok {
			gid = a
		} else {
			return 0, 0, fmt.Errorf("group %s not found in the image", g)
		}
	}
	return uid, gid, nil
}

// logLine is one line of log.jsonl.
type logLine struct {
	T      time.Time `json:"t"`
	Stream string    `json:"s"`
	Line   string    `json:"l"`
}

// pump copies a stream to the log, a line at a time.
func pump(r io.Reader, stream string, mu *sync.Mutex, w io.Writer, wg *sync.WaitGroup) {
	defer wg.Done()
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, err := br.ReadString('\n')
		if line != "" {
			b, _ := json.Marshal(logLine{time.Now().UTC(), stream, strings.TrimSuffix(line, "\n")})
			mu.Lock()
			w.Write(append(b, '\n'))
			mu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

// execute creates, connects and starts the container, waits for it and records the result.
// With logs, its output goes to log.jsonl; otherwise to our own stdio. ready (if not nil) is
// called once the container runs, or with the error that stopped it.
func execute(m *Meta, logs bool, ready func(error)) int {
	notify := func(err error) {
		if ready != nil {
			ready(err)
			ready = nil
		}
	}
	opts := container.CreateOptions{KeepChild: true}
	var wg sync.WaitGroup
	var logFile *os.File
	if logs {
		var err error
		logFile, err = os.OpenFile(m.logPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			notify(err)
			return 125
		}
		defer logFile.Close()
		var mu sync.Mutex
		outR, outW, _ := os.Pipe()
		errR, errW, _ := os.Pipe()
		devnull, _ := os.Open(os.DevNull)
		opts.Stdin, opts.Stdout, opts.Stderr = devnull, outW, errW
		wg.Add(2)
		go pump(outR, "stdout", &mu, logFile, &wg)
		go pump(errR, "stderr", &mu, logFile, &wg)
		defer func() {
			outW.Close()
			errW.Close()
			wg.Wait()
			devnull.Close()
		}()
	}
	fail := func(err error) int {
		m.Error = err.Error()
		now := time.Now().UTC()
		m.Finished = &now
		code := 125
		m.ExitCode = &code
		m.save()
		notify(err)
		return code
	}
	proc, err := container.Create(m.OCIRoot, m.ID, m.bundle(), opts)
	if err != nil {
		return fail(err)
	}
	if logs {
		// Our copies of the write ends: the container holds its own.
		opts.Stdout.(*os.File).Close()
		opts.Stderr.(*os.File).Close()
	}
	m.Pid = proc.Pid
	if err := attach(m, proc.Pid); err != nil {
		container.Delete(m.OCIRoot, m.ID, true)
		return fail(err)
	}
	if err := container.Start(m.OCIRoot, m.ID); err != nil {
		container.Delete(m.OCIRoot, m.ID, true)
		return fail(err)
	}
	now := time.Now().UTC()
	m.Started = &now
	m.save()
	notify(nil)

	st, werr := proc.Wait()
	code := 0
	if werr != nil {
		code = 125
	} else if ws, ok := st.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		code = 128 + int(ws.Signal())
	} else {
		code = st.ExitCode()
	}
	if s, err := cgroups.Read(m.CgroupPath); err == nil {
		m.Final = s
	}
	fin := time.Now().UTC()
	m.Finished, m.ExitCode = &fin, &code
	m.save()
	container.Delete(m.OCIRoot, m.ID, true)
	detach(m)
	return code
}

// cleanup removes everything a container left: OCI state, network, overlay, directory.
func cleanup(m *Meta) {
	if m.OCIRoot != "" {
		container.Delete(m.OCIRoot, m.ID, true)
	}
	detach(m)
	releaseIP(m.IP)
	unix.Unmount(m.rootfs(), unix.MNT_DETACH)
	os.RemoveAll(m.dir())
}

// Run runs a container from an image. In the foreground it returns the exit code; detached,
// it returns once the container is running (a shim process stays behind to wait for it).
func Run(ociRoot string, o RunOptions) (*Meta, int, error) {
	m, err := prepare(ociRoot, o)
	if err != nil {
		return nil, 125, err
	}
	if !o.Detach {
		code := execute(m, false, nil)
		if o.Remove {
			cleanup(m)
		}
		if m.Error != "" {
			return m, code, errors.New(m.Error)
		}
		return m, code, nil
	}
	// Detached: a shim in its own session owns the container's init.
	r, w, err := os.Pipe()
	if err != nil {
		return nil, 125, err
	}
	self, _ := os.Executable()
	shim := exec.Command(self, "_shim", m.ID)
	shim.ExtraFiles = []*os.File{w}
	shim.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := shim.Start(); err != nil {
		cleanup(m)
		return nil, 125, err
	}
	w.Close()
	msg, _ := io.ReadAll(r)
	shim.Process.Release()
	if s := strings.TrimSpace(string(msg)); s != "ok" {
		if s == "" {
			s = "the shim exited"
		}
		return m, 125, errors.New(s)
	}
	m, _ = loadMeta(m.ID)
	return m, 0, nil
}

// Shim is `harbor _shim ID`: runs a prepared container with logs and waits for it.
func Shim(args []string) {
	if len(args) != 1 {
		os.Exit(2)
	}
	// The status pipe must not leak into the container (its holder would keep the caller
	// waiting until the container exits).
	unix.CloseOnExec(3)
	status := os.NewFile(3, "status")
	m, err := loadMeta(args[0])
	if err != nil {
		status.WriteString(err.Error())
		os.Exit(1)
	}
	// Our stdio is the caller's; switch to /dev/null so the caller is not held.
	if devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0); err == nil {
		unix.Dup2(int(devnull.Fd()), 0)
		unix.Dup2(int(devnull.Fd()), 1)
		unix.Dup2(int(devnull.Fd()), 2)
	}
	execute(m, true, func(err error) {
		if err != nil {
			status.WriteString(err.Error())
		} else {
			status.WriteString("ok")
		}
		status.Close()
	})
	if m.AutoRemove {
		cleanup(m)
	}
}

// Status of an image-based container: created/running from the runtime, else exited.
func Status(m *Meta) string {
	if m.Finished != nil {
		return "exited"
	}
	st, err := container.State(m.OCIRoot, m.ID)
	if err != nil {
		if m.Started == nil {
			return "creating"
		}
		return "exited"
	}
	return string(st.Status)
}

// Stop sends SIGTERM, then SIGKILL after the timeout.
func Stop(m *Meta, timeout time.Duration) error {
	if Status(m) != "running" && Status(m) != "created" {
		return nil
	}
	if err := container.Kill(m.OCIRoot, m.ID, unix.SIGTERM); err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if st, err := container.State(m.OCIRoot, m.ID); err != nil || st.Status == specs.StateStopped {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return container.Kill(m.OCIRoot, m.ID, unix.SIGKILL)
}

// Remove deletes a container (running ones only with force).
func Remove(m *Meta, force bool) error {
	if s := Status(m); s == "running" || s == "created" {
		if !force {
			return fmt.Errorf("container %s is %s; stop it or use -f", m.Name, s)
		}
		container.Kill(m.OCIRoot, m.ID, unix.SIGKILL)
		for i := 0; i < 200 && Status(m) == "running"; i++ {
			time.Sleep(25 * time.Millisecond)
			m, _ = loadMeta(m.ID)
		}
	}
	cleanup(m)
	return nil
}

// ReadLogs returns the log lines after the first `skip`.
func ReadLogs(m *Meta, skip int) ([]logLine, error) {
	f, err := os.Open(m.logPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []logLine
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 1<<20), 1<<20)
	for i := 0; s.Scan(); i++ {
		if i < skip {
			continue
		}
		var l logLine
		if json.Unmarshal(s.Bytes(), &l) == nil {
			out = append(out, l)
		}
	}
	return out, nil
}
