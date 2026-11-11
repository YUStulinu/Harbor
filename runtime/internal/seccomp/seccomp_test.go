package seccomp

import (
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

func nr(t *testing.T, name string) uint32 {
	n, ok := SyscallNumber(name)
	if !ok {
		t.Fatalf("no syscall %s", name)
	}
	return n
}

func errno(e uint) *uint { return &e }

func TestTableHasCommonCalls(t *testing.T) {
	for name, want := range map[string]uint32{"read": 0, "write": 1, "openat": 257, "mkdirat": 258, "clone3": 435, "personality": 135} {
		if got := nr(t, name); got != want {
			t.Errorf("%s = %d, want %d", name, got, want)
		}
	}
}

func TestDenyListAndAllowList(t *testing.T) {
	deny := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{"mkdir", "mkdirat", "no_such_call"}, Action: specs.ActErrno, ErrnoRet: errno(uint(unix.EACCES))},
			{Names: []string{"reboot"}, Action: specs.ActKillProcess},
		},
	}
	p, err := Compile(deny)
	if err != nil {
		t.Fatal(err)
	}
	var none [6]uint64
	if got := Run(p, nr(t, "mkdirat"), none); got != unix.SECCOMP_RET_ERRNO|uint32(unix.EACCES) {
		t.Errorf("mkdirat -> %#x", got)
	}
	if got := Run(p, nr(t, "reboot"), none); got != unix.SECCOMP_RET_KILL_PROCESS {
		t.Errorf("reboot -> %#x", got)
	}
	if got := Run(p, nr(t, "read"), none); got != unix.SECCOMP_RET_ALLOW {
		t.Errorf("read -> %#x", got)
	}
	allow := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno, Syscalls: []specs.LinuxSyscall{{Names: []string{"read", "exit"}, Action: specs.ActAllow}}}
	p, _ = Compile(allow)
	if Run(p, nr(t, "read"), none) != unix.SECCOMP_RET_ALLOW || Run(p, nr(t, "write"), none) != unix.SECCOMP_RET_ERRNO|uint32(unix.EPERM) {
		t.Error("allow list")
	}
	// x32 system calls get the default action.
	if Run(p, nr(t, "read")|x32Bit, none) != unix.SECCOMP_RET_ERRNO|uint32(unix.EPERM) {
		t.Error("x32 call allowed")
	}
}

// Every operator against a reference implementation, on values that straddle the 32-bit halves.
func TestArgumentConditions(t *testing.T) {
	values := []uint64{0, 1, 5, 0xffffffff, 0x100000000, 0x100000005, 0x2_0000_0000, 1 << 63, ^uint64(0)}
	ops := map[specs.LinuxSeccompOperator]func(a, v, v2 uint64) bool{
		specs.OpEqualTo:      func(a, v, _ uint64) bool { return a == v },
		specs.OpNotEqual:     func(a, v, _ uint64) bool { return a != v },
		specs.OpGreaterThan:  func(a, v, _ uint64) bool { return a > v },
		specs.OpGreaterEqual: func(a, v, _ uint64) bool { return a >= v },
		specs.OpLessThan:     func(a, v, _ uint64) bool { return a < v },
		specs.OpLessEqual:    func(a, v, _ uint64) bool { return a <= v },
		specs.OpMaskedEqual:  func(a, m, d uint64) bool { return a&m == d },
	}
	call := nr(t, "personality")
	for op, ref := range ops {
		for _, v := range values {
			v2 := v & 0xf0000000f
			prof := &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
				Syscalls:      []specs.LinuxSyscall{{Names: []string{"personality"}, Action: specs.ActAllow, Args: []specs.LinuxSeccompArg{{Index: 2, Value: v, ValueTwo: v2, Op: op}}}},
			}
			p, err := Compile(prof)
			if err != nil {
				t.Fatal(err)
			}
			for _, a := range values {
				var args [6]uint64
				args[2] = a
				got := Run(p, call, args) == unix.SECCOMP_RET_ALLOW
				if want := ref(a, v, v2); got != want {
					t.Errorf("%s: arg %#x vs %#x: got %v, want %v", op, a, v, got, want)
				}
			}
		}
	}
}

func TestSeveralConditionsAndRules(t *testing.T) {
	// Docker-style: personality allowed for three specific values, via three rules.
	prof := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno}
	for _, v := range []uint64{0, 8, 0xffffffff} {
		prof.Syscalls = append(prof.Syscalls, specs.LinuxSyscall{Names: []string{"personality"}, Action: specs.ActAllow, Args: []specs.LinuxSeccompArg{{Index: 0, Value: v, Op: specs.OpEqualTo}}})
	}
	// clone allowed only without CLONE_NEWUSER (masked) and with arg1 == 0 (two conditions).
	prof.Syscalls = append(prof.Syscalls, specs.LinuxSyscall{Names: []string{"clone"}, Action: specs.ActAllow, Args: []specs.LinuxSeccompArg{
		{Index: 0, Value: unix.CLONE_NEWUSER, ValueTwo: 0, Op: specs.OpMaskedEqual},
		{Index: 1, Value: 0, Op: specs.OpEqualTo},
	}})
	p, err := Compile(prof)
	if err != nil {
		t.Fatal(err)
	}
	pers, clone := nr(t, "personality"), nr(t, "clone")
	for _, c := range []struct {
		nr   uint32
		args [6]uint64
		ok   bool
	}{
		{pers, [6]uint64{0}, true}, {pers, [6]uint64{8}, true}, {pers, [6]uint64{0xffffffff}, true}, {pers, [6]uint64{9}, false},
		{clone, [6]uint64{uint64(unix.SIGCHLD), 0}, true}, {clone, [6]uint64{unix.CLONE_NEWUSER | uint64(unix.SIGCHLD), 0}, false}, {clone, [6]uint64{uint64(unix.SIGCHLD), 1}, false},
	} {
		if got := Run(p, c.nr, c.args) == unix.SECCOMP_RET_ALLOW; got != c.ok {
			t.Errorf("nr %d args %v: allowed=%v, want %v", c.nr, c.args[:2], got, c.ok)
		}
	}
}

func TestRejectsUnsupported(t *testing.T) {
	if _, err := Compile(&specs.LinuxSeccomp{DefaultAction: specs.ActNotify}); err == nil {
		t.Error("notify accepted")
	}
	if _, err := Compile(&specs.LinuxSeccomp{DefaultAction: specs.ActAllow, Syscalls: []specs.LinuxSyscall{{Names: []string{"read"}, Action: specs.ActErrno, Args: []specs.LinuxSeccompArg{{Index: 6, Op: specs.OpEqualTo}}}}}); err == nil {
		t.Error("argument index 6 accepted")
	}
}
