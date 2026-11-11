package cgroups

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func i64(v int64) *int64   { return &v }
func u64(v uint64) *uint64 { return &v }
func u16(v uint16) *uint16 { return &v }

func TestPath(t *testing.T) {
	Root = "/sys/fs/cgroup"
	for in, want := range map[string]string{
		"":             "/sys/fs/cgroup/harbor/c1",
		"/a/b":         "/sys/fs/cgroup/a/b",
		"mine/x":       "/sys/fs/cgroup/harbor/mine/x",
		"/a/../b":      "/sys/fs/cgroup/b",
		"harbor/other": "/sys/fs/cgroup/harbor/other",
	} {
		got, err := Path(in, "c1")
		if err != nil || got != want {
			t.Errorf("Path(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"/", "/..", "system.slice:harbor:c1"} {
		if _, err := Path(bad, "c1"); err == nil {
			t.Errorf("Path(%q) accepted", bad)
		}
	}
}

func TestConversions(t *testing.T) {
	if CPUWeight(2) != 1 || CPUWeight(262144) != 10000 || CPUWeight(1024) != 39 {
		t.Errorf("cpu weights %d %d %d", CPUWeight(2), CPUWeight(262144), CPUWeight(1024))
	}
	if IOWeight(10) != 1 || IOWeight(1000) != 10000 || IOWeight(500) != 4950 {
		t.Errorf("io weights %d %d %d", IOWeight(10), IOWeight(1000), IOWeight(500))
	}
}

func TestFiles(t *testing.T) {
	r := &specs.LinuxResources{
		Memory:  &specs.LinuxMemory{Limit: i64(64 << 20), Swap: i64(96 << 20), Reservation: i64(-1)},
		CPU:     &specs.LinuxCPU{Shares: u64(512), Quota: i64(50000), Period: u64(100000), Cpus: "0-1"},
		Pids:    &specs.LinuxPids{Limit: 32},
		BlockIO: &specs.LinuxBlockIO{Weight: u16(100)},
	}
	got, err := Files(r)
	if err != nil {
		t.Fatal(err)
	}
	want := [][2]string{
		{"memory.max", "67108864"}, {"memory.low", "max"}, {"memory.swap.max", "33554432"},
		{"cpu.weight", "20"}, {"cpu.max", "50000 100000"}, {"cpuset.cpus", "0-1"},
		{"pids.max", "32"}, {"io.weight", "default 910"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v\nwant %v", got, want)
	}
	// Quota without period, unlimited values.
	got, _ = Files(&specs.LinuxResources{CPU: &specs.LinuxCPU{Quota: i64(-1)}, Pids: &specs.LinuxPids{Limit: -1}, Memory: &specs.LinuxMemory{Limit: i64(-1)}})
	want = [][2]string{{"memory.max", "max"}, {"cpu.max", "max 100000"}, {"pids.max", "max"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
	if _, err := Files(&specs.LinuxResources{Memory: &specs.LinuxMemory{Limit: i64(100), Swap: i64(50)}}); err == nil {
		t.Error("swap below limit accepted")
	}
	if _, err := Files(&specs.LinuxResources{Unified: map[string]string{"../x": "1"}}); err == nil {
		t.Error("unified path escape accepted")
	}
}

// Against a fake hierarchy (a plain directory), so it runs without root.
func TestCreateApplyRead(t *testing.T) {
	Root = t.TempDir()
	defer func() { Root = "/sys/fs/cgroup" }()
	os.WriteFile(filepath.Join(Root, "cgroup.controllers"), []byte("cpu memory pids\n"), 0o644)
	dir, _ := Path("", "c2")
	os.MkdirAll(dir, 0o755) // a real cgroupfs creates the files; here, pre-create the dir
	for _, f := range []string{"memory.max", "pids.max", "cpu.stat", "memory.current", "memory.events"} {
		os.WriteFile(filepath.Join(dir, f), nil, 0o644)
	}
	if err := Create(dir, &specs.LinuxResources{Memory: &specs.LinuxMemory{Limit: i64(1 << 20)}, Pids: &specs.LinuxPids{Limit: 5}}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "memory.max")); string(b) != "1048576" {
		t.Errorf("memory.max = %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(Root, "harbor", "cgroup.subtree_control")); len(b) == 0 {
		t.Error("controllers not enabled in the parent")
	}
	os.WriteFile(filepath.Join(dir, "cpu.stat"), []byte("usage_usec 1234\nthrottled_usec 5\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "memory.current"), []byte("4096\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "memory.events"), []byte("low 0\noom_kill 2\n"), 0o644)
	s, err := Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.CPUUsageUsec != 1234 || s.MemoryCurrent != 4096 || s.MemoryMax != 1<<20 || s.OOMKills != 2 || s.PidsMax != 5 {
		t.Errorf("stats %+v", s)
	}
}
