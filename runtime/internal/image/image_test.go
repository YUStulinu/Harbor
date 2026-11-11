package image

import (
	"os"
	"path/filepath"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/YUStulinu/Harbor/runtime/internal/seccomp"
)

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{"64m": 64 << 20, "1g": 1 << 30, "512k": 512 << 10, "1048576": 1 << 20, "2MB": 2 << 20} {
		if got, err := ParseSize(in); err != nil || got != want {
			t.Errorf("ParseSize(%q) = %d, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "-1m", "abc", "0"} {
		if _, err := ParseSize(bad); err == nil {
			t.Errorf("ParseSize(%q) accepted", bad)
		}
	}
}

func TestParseRun(t *testing.T) {
	o, err := parseRun([]string{"-d", "--name", "web", "--memory=64m", "--cpus", "0.5", "--pids", "20", "-e", "A=1", "--net", "none", "alpine", "sh", "-c", "echo --memory"})
	if err != nil {
		t.Fatal(err)
	}
	if !o.Detach || o.Name != "web" || o.Limits.MemoryBytes != 64<<20 || o.Limits.CPUs != 0.5 || o.Limits.Pids != 20 || o.Net != "none" || o.Image != "alpine" {
		t.Errorf("%+v", o)
	}
	if len(o.Args) != 3 || o.Args[2] != "echo --memory" || len(o.Env) != 1 {
		t.Errorf("args %v env %v", o.Args, o.Env)
	}
	for _, bad := range [][]string{{}, {"--cpus", "0", "alpine"}, {"--bogus", "alpine"}, {"--memory"}} {
		if _, err := parseRun(bad); err == nil {
			t.Errorf("parseRun(%v) accepted", bad)
		}
	}
}

func TestResolveUser(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "etc"), 0o755)
	os.WriteFile(filepath.Join(root, "etc", "passwd"), []byte("root:x:0:0::/root:/bin/sh\napp:x:1000:1001::/home/app:/bin/sh\n"), 0o644)
	os.WriteFile(filepath.Join(root, "etc", "group"), []byte("root:x:0:\nstaff:x:50:\n"), 0o644)
	for in, want := range map[string][2]uint32{"app": {1000, 1001}, "app:staff": {1000, 50}, "42": {42, 42}, "42:7": {42, 7}, "root": {0, 0}} {
		u, g, err := resolveUser(root, in)
		if err != nil || u != want[0] || g != want[1] {
			t.Errorf("resolveUser(%q) = %d:%d, %v", in, u, g, err)
		}
	}
	for _, bad := range []string{"nobody", "app:nogroup"} {
		if _, _, err := resolveUser(root, bad); err == nil {
			t.Errorf("resolveUser(%q) accepted", bad)
		}
	}
}

func TestDefaultSpec(t *testing.T) {
	s := DefaultSpec([]string{"python3"}, []string{"LANG=C"}, "", false)
	if s.Process.Cwd != "/" || s.Process.Env[0][:5] != "PATH=" || !s.Process.NoNewPrivileges {
		t.Errorf("process %+v", s.Process)
	}
	ns := map[specs.LinuxNamespaceType]bool{}
	for _, n := range s.Linux.Namespaces {
		ns[n.Type] = true
	}
	for _, want := range []specs.LinuxNamespaceType{specs.PIDNamespace, specs.MountNamespace, specs.NetworkNamespace, specs.UTSNamespace, specs.IPCNamespace} {
		if !ns[want] {
			t.Errorf("missing %s namespace", want)
		}
	}
	// The default profile compiles and refuses what it lists.
	prog, err := seccomp.Compile(s.Linux.Seccomp)
	if err != nil {
		t.Fatal(err)
	}
	nr, _ := seccomp.SyscallNumber("mount")
	if got := seccomp.Run(prog, nr, [6]uint64{}); got != 0x00050001 {
		t.Errorf("mount -> %#x, want ERRNO(EPERM)", got)
	}
	nr, _ = seccomp.SyscallNumber("openat")
	if got := seccomp.Run(prog, nr, [6]uint64{}); got != 0x7fff0000 {
		t.Errorf("openat -> %#x, want ALLOW", got)
	}
	for _, c := range s.Process.Capabilities.Bounding {
		if c == "CAP_SYS_ADMIN" || c == "CAP_NET_ADMIN" {
			t.Errorf("default capabilities include %s", c)
		}
	}
}

func TestIPAllocation(t *testing.T) {
	NetDir = t.TempDir()
	a, err := allocateIP("c1")
	if err != nil || a != "10.88.0.2" {
		t.Fatalf("first %s %v", a, err)
	}
	b, _ := allocateIP("c2")
	if b != "10.88.0.3" {
		t.Errorf("second %s", b)
	}
	releaseIP(a)
	if c, _ := allocateIP("c3"); c != "10.88.0.2" {
		t.Errorf("released address not reused: %s", c)
	}
	releaseIP("../../etc/passwd") // not an address: ignored
}
