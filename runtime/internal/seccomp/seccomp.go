// Package seccomp compiles an OCI seccomp profile (linux.seccomp in config.json) into a
// classic BPF program and loads it with seccomp(2). No libseccomp: the program is assembled
// here.
//
// The program, for x86-64:
//
//	load arch; if arch != AUDIT_ARCH_X86_64: return default action
//	load nr;   if nr has the x32 bit set:     return default action
//	for each rule, for each of its syscalls:
//	    if nr == N and every argument condition holds: return the rule's action
//	return default action
//
// Arguments are 64-bit but BPF compares 32-bit words, so each condition loads the high and
// the low half of the argument separately.
package seccomp

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

// Classic BPF opcodes used here.
const (
	ldW   = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
	jeqK  = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
	jgtK  = unix.BPF_JMP | unix.BPF_JGT | unix.BPF_K
	jgeK  = unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K
	jsetK = unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K
	ja    = unix.BPF_JMP | unix.BPF_JA
	andK  = unix.BPF_ALU | unix.BPF_AND | unix.BPF_K
	retK  = unix.BPF_RET | unix.BPF_K

	offNr   = 0
	offArch = 4
	offArgs = 16

	auditArchX86_64 = 0xc000003e
	x32Bit          = 0x40000000
)

// Instruction is one classic BPF instruction (struct sock_filter).
type Instruction struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}

// Action translates an OCI action (and errno) into a SECCOMP_RET_* value.
func Action(a specs.LinuxSeccompAction, errno *uint) (uint32, error) {
	e := uint32(unix.EPERM)
	if errno != nil {
		e = uint32(*errno)
	}
	switch a {
	case specs.ActKill, specs.ActKillThread:
		return unix.SECCOMP_RET_KILL_THREAD, nil
	case specs.ActKillProcess:
		return unix.SECCOMP_RET_KILL_PROCESS, nil
	case specs.ActTrap:
		return unix.SECCOMP_RET_TRAP, nil
	case specs.ActErrno:
		return unix.SECCOMP_RET_ERRNO | (e & unix.SECCOMP_RET_DATA), nil
	case specs.ActTrace:
		return unix.SECCOMP_RET_TRACE | (e & unix.SECCOMP_RET_DATA), nil
	case specs.ActAllow:
		return unix.SECCOMP_RET_ALLOW, nil
	case specs.ActLog:
		return unix.SECCOMP_RET_LOG, nil
	}
	return 0, fmt.Errorf("seccomp action %q is not supported", a)
}

// SyscallNumber returns the x86-64 number of a system call name.
func SyscallNumber(name string) (uint32, bool) {
	n, ok := syscallsAMD64[name]
	return n, ok
}

type asm struct {
	prog []Instruction
}

func (a *asm) emit(code uint16, jt, jf uint8, k uint32) int {
	a.prog = append(a.prog, Instruction{code, jt, jf, k})
	return len(a.prog) - 1
}

// Jumps to a label not yet placed are patched once the label is known. Conditional jump
// offsets are 8 bits, so a rule block (which is small) is the only thing they skip.
type fixup struct {
	at       int
	falseArm bool // patch Jf (else Jt)
}

func (a *asm) patch(fs []fixup, target int) error {
	for _, f := range fs {
		off := target - f.at - 1
		if off < 0 || off > 255 {
			return fmt.Errorf("seccomp: jump of %d instructions is out of range", off)
		}
		if f.falseArm {
			a.prog[f.at].Jf = uint8(off)
		} else {
			a.prog[f.at].Jt = uint8(off)
		}
	}
	return nil
}

// condition emits the checks for one argument condition; every failing path is recorded in
// fail (to be pointed at the end of the rule).
func (a *asm) condition(c specs.LinuxSeccompArg, fail *[]fixup) error {
	if c.Index > 5 {
		return fmt.Errorf("seccomp: argument index %d out of range", c.Index)
	}
	lo := uint32(offArgs + 8*c.Index) // little-endian: low word first
	hi := lo + 4
	v := c.Value
	vhi, vlo := uint32(v>>32), uint32(v)
	switch c.Op {
	case specs.OpEqualTo:
		a.emit(ldW, 0, 0, hi)
		*fail = append(*fail, fixup{a.emit(jeqK, 0, 0, vhi), true})
		a.emit(ldW, 0, 0, lo)
		*fail = append(*fail, fixup{a.emit(jeqK, 0, 0, vlo), true})
	case specs.OpNotEqual:
		// Passes if either half differs.
		a.emit(ldW, 0, 0, hi)
		a.emit(jeqK, 0, 2, vhi) // high differs -> skip to the end of this check (pass)
		a.emit(ldW, 0, 0, lo)
		*fail = append(*fail, fixup{a.emit(jeqK, 0, 0, vlo), false})
	case specs.OpMaskedEqual:
		// (arg & Value) == ValueTwo
		m := c.Value
		d := c.ValueTwo
		a.emit(ldW, 0, 0, hi)
		a.emit(andK, 0, 0, uint32(m>>32))
		*fail = append(*fail, fixup{a.emit(jeqK, 0, 0, uint32(d>>32)), true})
		a.emit(ldW, 0, 0, lo)
		a.emit(andK, 0, 0, uint32(m))
		*fail = append(*fail, fixup{a.emit(jeqK, 0, 0, uint32(d)), true})
	case specs.OpGreaterThan, specs.OpGreaterEqual, specs.OpLessThan, specs.OpLessEqual:
		// Unsigned 64-bit comparison: decide on the high word unless it is equal.
		// a > v  : hi > vhi, or hi == vhi and lo >  vlo
		// a >= v : hi > vhi, or hi == vhi and lo >= vlo
		// a < v  is not (a >= v);  a <= v  is not (a > v)
		strict := c.Op == specs.OpGreaterThan || c.Op == specs.OpLessEqual
		greater := c.Op == specs.OpGreaterThan || c.Op == specs.OpGreaterEqual
		loOp := uint16(jgeK)
		if strict {
			loOp = jgtK
		}
		a.emit(ldW, 0, 0, hi)
		if greater {
			a.emit(jgtK, 3, 0, vhi) // hi > vhi: pass (skip the rest of this check)
			*fail = append(*fail, fixup{a.emit(jeqK, 0, 0, vhi), true})
			a.emit(ldW, 0, 0, lo)
			*fail = append(*fail, fixup{a.emit(loOp, 0, 0, vlo), true})
		} else {
			// pass unless (hi > vhi) or (hi == vhi and lo cmp vlo)
			*fail = append(*fail, fixup{a.emit(jgtK, 0, 0, vhi), false})
			a.emit(jeqK, 0, 2, vhi) // hi < vhi: pass
			a.emit(ldW, 0, 0, lo)
			*fail = append(*fail, fixup{a.emit(loOp, 0, 0, vlo), false})
		}
	default:
		return fmt.Errorf("seccomp: operator %q is not supported", c.Op)
	}
	return nil
}

// Compile builds the BPF program for a profile. Unknown system call names are skipped (a
// profile written for other kernels may name calls this one does not have).
func Compile(s *specs.LinuxSeccomp) ([]Instruction, error) {
	def, err := Action(s.DefaultAction, s.DefaultErrnoRet)
	if err != nil {
		return nil, err
	}
	for _, ar := range s.Architectures {
		switch ar {
		case specs.ArchX86_64, specs.ArchX86, specs.ArchX32:
		default:
			// Other architectures cannot occur on this machine.
		}
	}
	a := &asm{}
	a.emit(ldW, 0, 0, offArch)
	a.emit(jeqK, 1, 0, auditArchX86_64)
	a.emit(retK, 0, 0, def)
	a.emit(ldW, 0, 0, offNr)
	a.emit(jsetK, 0, 1, x32Bit)
	a.emit(retK, 0, 0, def)
	for _, rule := range s.Syscalls {
		act, err := Action(rule.Action, rule.ErrnoRet)
		if err != nil {
			return nil, err
		}
		if act == def && len(rule.Args) == 0 {
			continue // the same as not listing it
		}
		for _, name := range rule.Names {
			nr, ok := SyscallNumber(name)
			if !ok {
				continue
			}
			if len(rule.Args) == 0 {
				a.emit(jeqK, 0, 1, nr)
				a.emit(retK, 0, 0, act)
				continue
			}
			// if nr != N skip the block; the block ends by reloading nr for the next rule.
			skip := a.emit(jeqK, 0, 0, nr)
			var fail []fixup
			for _, c := range rule.Args {
				if err := a.condition(c, &fail); err != nil {
					return nil, err
				}
			}
			a.emit(retK, 0, 0, act)
			end := a.emit(ldW, 0, 0, offNr) // conditions failed: back to comparing numbers
			if err := a.patch(fail, end); err != nil {
				return nil, err
			}
			if end-skip-1 > 255 {
				return nil, fmt.Errorf("seccomp: rule for %s is too long", name)
			}
			a.prog[skip].Jf = uint8(end - skip)
		}
	}
	a.emit(retK, 0, 0, def)
	if len(a.prog) > 4096 {
		return nil, fmt.Errorf("seccomp: program of %d instructions exceeds the kernel limit", len(a.prog))
	}
	return a.prog, nil
}

// Run interprets a program on a syscall the way the kernel would (for tests).
func Run(prog []Instruction, nr uint32, args [6]uint64) uint32 {
	var data [64]byte
	binary.LittleEndian.PutUint32(data[offNr:], nr)
	binary.LittleEndian.PutUint32(data[offArch:], auditArchX86_64)
	for i, v := range args {
		binary.LittleEndian.PutUint64(data[offArgs+8*i:], v)
	}
	var acc uint32
	for pc := 0; pc < len(prog); pc++ {
		in := prog[pc]
		switch in.Code {
		case ldW:
			acc = binary.LittleEndian.Uint32(data[in.K:])
		case andK:
			acc &= in.K
		case retK:
			return in.K
		case ja:
			pc += int(in.K)
		case jeqK, jgtK, jgeK, jsetK:
			var ok bool
			switch in.Code {
			case jeqK:
				ok = acc == in.K
			case jgtK:
				ok = acc > in.K
			case jgeK:
				ok = acc >= in.K
			case jsetK:
				ok = acc&in.K != 0
			}
			if ok {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		default:
			panic(fmt.Sprintf("unknown opcode %#x", in.Code))
		}
	}
	return unix.SECCOMP_RET_KILL_PROCESS
}

// Load installs the program for the calling thread (and what it executes next). The caller
// must have set no_new_privs or hold CAP_SYS_ADMIN.
func Load(prog []Instruction, flags []specs.LinuxSeccompFlag) error {
	var f uintptr
	for _, fl := range flags {
		switch fl {
		case specs.LinuxSeccompFlagLog:
			f |= unix.SECCOMP_FILTER_FLAG_LOG
		case specs.LinuxSeccompFlagSpecAllow:
			f |= unix.SECCOMP_FILTER_FLAG_SPEC_ALLOW
		case specs.LinuxSeccompFlagWaitKillableRecv:
			// Only meaningful with user notification, which is not supported.
		}
	}
	filter := make([]unix.SockFilter, len(prog))
	for i, in := range prog {
		filter[i] = unix.SockFilter{Code: in.Code, Jt: in.Jt, Jf: in.Jf, K: in.K}
	}
	fp := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	_, _, e := unix.RawSyscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, f, uintptr(unsafe.Pointer(&fp)))
	if e != 0 {
		return fmt.Errorf("seccomp(SET_MODE_FILTER): %w", e)
	}
	return nil
}
