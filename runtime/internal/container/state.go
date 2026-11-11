package container

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// DefaultRoot holds one directory per container (state.json, exec.fifo).
const DefaultRoot = "/run/harbor"

// Saved is what the runtime remembers about a container between commands.
type Saved struct {
	ID           string            `json:"id"`
	Bundle       string            `json:"bundle"`
	Rootfs       string            `json:"rootfs"`
	Pid          int               `json:"pid"`
	PidStartTime uint64            `json:"pid_start_time"` // guards against pid reuse
	Created      time.Time         `json:"created"`
	Started      bool              `json:"started"`
	CgroupPath   string            `json:"cgroup_path"`
	Annotations  map[string]string `json:"annotations,omitempty"`
	OwnPidNS     bool              `json:"own_pid_ns"`
}

var idRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// ValidID checks a container id (it names a directory).
func ValidID(id string) error {
	if !idRe.MatchString(id) {
		return fmt.Errorf("invalid container id %q", id)
	}
	return nil
}

func stateDir(root, id string) string { return filepath.Join(root, id) }

func load(root, id string) (*Saved, error) {
	if err := ValidID(id); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(stateDir(root, id), "state.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("container %s does not exist", id)
		}
		return nil, err
	}
	var s Saved
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("container %s: corrupt state: %w", id, err)
	}
	return &s, nil
}

func save(root string, s *Saved) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	dir := stateDir(root, s.ID)
	tmp := filepath.Join(dir, "state.json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, "state.json"))
}

// procStat returns a process's state letter and start time (fields 3 and 22 of /proc/pid/stat).
func procStat(pid int) (byte, uint64, error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, 0, err
	}
	s := string(b)
	// The command name is in parentheses and may contain spaces: parse after the last ')'.
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0, 0, errors.New("bad /proc/pid/stat")
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 20 {
		return 0, 0, errors.New("bad /proc/pid/stat")
	}
	start, err := strconv.ParseUint(f[19], 10, 64)
	return f[0][0], start, err
}

// alive reports whether the container's init process is still the one we started.
func (s *Saved) alive() bool {
	if s.Pid <= 0 {
		return false
	}
	st, start, err := procStat(s.Pid)
	if err != nil || st == 'Z' || st == 'X' {
		return false
	}
	return start == s.PidStartTime
}

// Status is "created", "running" or "stopped".
func (s *Saved) Status() specs.ContainerState {
	switch {
	case !s.alive():
		return specs.StateStopped
	case !s.Started:
		return specs.StateCreated
	default:
		return specs.StateRunning
	}
}

// OCIState is the `state` command's output (runtime spec "state").
func (s *Saved) OCIState() specs.State {
	st := specs.State{Version: specs.Version, ID: s.ID, Status: s.Status(), Bundle: s.Bundle, Annotations: s.Annotations}
	if st.Status != specs.StateStopped {
		st.Pid = s.Pid
	}
	return st
}

// List returns every container under root.
func List(root string) ([]*Saved, error) {
	ents, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []*Saved
	for _, e := range ents {
		if s, err := load(root, e.Name()); err == nil {
			out = append(out, s)
		}
	}
	return out, nil
}

// Get loads one container.
func Get(root, id string) (*Saved, error) { return load(root, id) }
