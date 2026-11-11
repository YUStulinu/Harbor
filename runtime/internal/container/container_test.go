package container

import (
	"os"
	"path/filepath"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

func TestSecureJoinStaysInsideRoot(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "etc"), 0o755)
	os.MkdirAll(filepath.Join(root, "usr", "lib"), 0o755)
	os.Symlink("/etc", filepath.Join(root, "abs"))                  // absolute: restarts at root
	os.Symlink("../../..", filepath.Join(root, "usr", "lib", "up")) // climbs past root
	os.Symlink("lib", filepath.Join(root, "usr", "rel"))
	os.Symlink("loop2", filepath.Join(root, "loop1"))
	os.Symlink("loop1", filepath.Join(root, "loop2"))
	for in, want := range map[string]string{
		"/etc/passwd":          "etc/passwd",
		"/abs/passwd":          "etc/passwd",
		"/usr/lib/up/etc":      "etc",
		"/usr/rel/x":           "usr/lib/x",
		"/../../../etc/shadow": "etc/shadow",
		"/a/./b/../c":          "a/c",
		"/":                    "",
	} {
		got, err := secureJoin(root, in)
		if err != nil || got != filepath.Join(root, want) {
			t.Errorf("secureJoin(%q) = %q, %v; want %q", in, got, err, filepath.Join(root, want))
		}
	}
	if _, err := secureJoin(root, "/loop1/x"); err == nil {
		t.Error("symlink loop not detected")
	}
}

func TestMountOptions(t *testing.T) {
	o := parseMountOptions([]string{"nosuid", "noexec", "ro", "rw", "mode=755", "size=65536k", "rbind", "rslave", "defaults"})
	if o.flags != unix.MS_NOSUID|unix.MS_NOEXEC {
		t.Errorf("flags %#x", o.flags)
	}
	if o.clear&unix.MS_RDONLY == 0 || !o.bind || !o.recursive {
		t.Errorf("parsed %+v", o)
	}
	if len(o.data) != 2 || o.data[0] != "mode=755" || o.data[1] != "size=65536k" {
		t.Errorf("data %v", o.data)
	}
	if len(o.propagation) != 1 || o.propagation[0] != unix.MS_SLAVE|unix.MS_REC {
		t.Errorf("propagation %v", o.propagation)
	}
}

func TestSignals(t *testing.T) {
	for in, want := range map[string]unix.Signal{"KILL": unix.SIGKILL, "SIGTERM": unix.SIGTERM, "9": unix.SIGKILL, "usr1": unix.SIGUSR1} {
		if got, err := ParseSignal(in); err != nil || got != want {
			t.Errorf("ParseSignal(%q) = %v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"NOPE", "0", "65", "-1"} {
		if _, err := ParseSignal(bad); err == nil {
			t.Errorf("ParseSignal(%q) accepted", bad)
		}
	}
}

func TestIDs(t *testing.T) {
	for _, ok := range []string{"a", "web-1", "c.2_x", "0f3c2a"} {
		if ValidID(ok) != nil {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"", "../x", "a/b", ".hidden", "-x", string(make([]byte, 200))} {
		if ValidID(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCapabilities(t *testing.T) {
	s, err := parseCaps(&specs.LinuxCapabilities{Bounding: []string{"CAP_KILL", "cap_chown"}, Effective: []string{"CAP_NET_RAW"}})
	if err != nil {
		t.Fatal(err)
	}
	if s.bounding != 1<<5|1<<0 || s.effective != 1<<13 || s.permitted != 0 {
		t.Errorf("sets %+v", s)
	}
	if _, err := parseCaps(&specs.LinuxCapabilities{Bounding: []string{"CAP_TEST"}}); err == nil {
		t.Error("unknown capability accepted")
	}
}

func TestProcStatAndStatus(t *testing.T) {
	st, start, err := procStat(os.Getpid())
	if err != nil || start == 0 || (st != 'R' && st != 'S') {
		t.Fatalf("procStat(self) = %c %d %v", st, start, err)
	}
	s := &Saved{Pid: os.Getpid(), PidStartTime: start}
	if s.Status() != specs.StateCreated {
		t.Errorf("not started: %s", s.Status())
	}
	s.Started = true
	if s.Status() != specs.StateRunning {
		t.Errorf("started: %s", s.Status())
	}
	s.PidStartTime++ // the pid now belongs to another process
	if s.Status() != specs.StateStopped || s.OCIState().Pid != 0 {
		t.Errorf("reused pid: %s", s.Status())
	}
}

func TestLoadSpecValidation(t *testing.T) {
	dir := t.TempDir()
	write := func(js string) error {
		os.WriteFile(filepath.Join(dir, "config.json"), []byte(js), 0o644)
		_, err := LoadSpec(dir)
		return err
	}
	good := `{"ociVersion":"1.2.0","root":{"path":"rootfs"},"process":{"args":["sh"],"cwd":"/"},"linux":{"namespaces":[{"type":"pid"}]}}`
	if err := write(good); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		`{"ociVersion":"0.9","root":{"path":"r"},"process":{"args":["sh"],"cwd":"/"}}`,
		`{"ociVersion":"1.2.0","process":{"args":["sh"],"cwd":"/"}}`,
		`{"ociVersion":"1.2.0","root":{"path":"r"},"process":{"args":[],"cwd":"/"}}`,
		`{"ociVersion":"1.2.0","root":{"path":"r"},"process":{"args":["sh"],"cwd":"rel"}}`,
		`{"ociVersion":"1.2.0","root":{"path":"r"},"process":{"args":["sh"],"cwd":"/"},"linux":{"namespaces":[{"type":"pid"},{"type":"pid"}]}}`,
		`{"ociVersion":"1.2.0","root":{"path":"r"},"process":{"args":["sh"],"cwd":"/","rlimits":[{"type":"RLIMIT_TEST","hard":1,"soft":1}]}}`,
		`not json`,
	} {
		if err := write(bad); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestLookPath(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "tool"), []byte("#!/bin/sh\n"), 0o755)
	os.WriteFile(filepath.Join(dir, "data"), nil, 0o644)
	if p, err := lookPath("tool", []string{"PATH=/nonexistent:" + dir}); err != nil || p != filepath.Join(dir, "tool") {
		t.Errorf("lookPath = %q, %v", p, err)
	}
	if _, err := lookPath("data", []string{"PATH=" + dir}); err == nil {
		t.Error("non-executable found")
	}
	if _, err := lookPath(filepath.Join(dir, "missing"), nil); err == nil {
		t.Error("missing absolute path accepted")
	}
}
