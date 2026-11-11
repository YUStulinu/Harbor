// Package cgroups manages a container's cgroup on the unified (v2) hierarchy: creating it,
// translating the OCI resource limits (which were written with cgroup v1 in mind) into v2
// files, reading usage, and killing and removing it.
package cgroups

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// Root is where the unified hierarchy is mounted.
var Root = "/sys/fs/cgroup"

// Path returns the absolute cgroup directory for a container. An absolute cgroupsPath is
// relative to the hierarchy root; a relative one, and the default, go under "harbor".
func Path(cgroupsPath, id string) (string, error) {
	p := cgroupsPath
	if p == "" {
		p = "harbor/" + id
	}
	if strings.Contains(p, ":") {
		return "", fmt.Errorf("systemd-style cgroupsPath %q is not supported", p)
	}
	if !filepath.IsAbs(p) {
		p = "/harbor/" + strings.TrimPrefix(p, "harbor/")
	}
	clean := filepath.Clean(p)
	if clean == "/" {
		return "", errors.New("cgroupsPath must not be the root cgroup")
	}
	return filepath.Join(Root, clean), nil
}

func write(dir, file, value string) error {
	if err := os.WriteFile(filepath.Join(dir, file), []byte(value), 0o644); err != nil {
		return fmt.Errorf("cgroup %s = %q: %w", file, value, err)
	}
	return nil
}

// enableControllers turns on, in every ancestor of dir, the controllers its children need.
func enableControllers(dir string) error {
	rel, err := filepath.Rel(Root, dir)
	if err != nil {
		return err
	}
	avail, err := os.ReadFile(filepath.Join(Root, "cgroup.controllers"))
	if err != nil {
		return err
	}
	cur := Root
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		for _, c := range strings.Fields(string(avail)) {
			// One at a time: a controller that cannot be enabled (e.g. cpuset with
			// processes in the cgroup) must not stop the others.
			_ = write(cur, "cgroup.subtree_control", "+"+c)
		}
		cur = filepath.Join(cur, part)
		if err := os.Mkdir(cur, 0o755); err != nil && !os.IsExist(err) {
			return err
		}
	}
	return nil
}

// Create makes the cgroup (and its parents) and applies the limits.
func Create(dir string, r *specs.LinuxResources) error {
	if err := enableControllers(dir); err != nil {
		return fmt.Errorf("creating cgroup %s: %w", dir, err)
	}
	return Apply(dir, r)
}

// CPUWeight converts cgroup v1 cpu.shares (2..262144) to v2 cpu.weight (1..10000), as the
// kernel documentation and runc do.
func CPUWeight(shares uint64) uint64 {
	if shares == 0 {
		return 0
	}
	if shares < 2 {
		shares = 2
	}
	if shares > 262144 {
		shares = 262144
	}
	return 1 + ((shares-2)*9999)/262142
}

// IOWeight converts a v1 blkio weight (10..1000) to v2 io.weight (1..10000).
func IOWeight(w uint16) uint64 {
	if w == 0 {
		return 0
	}
	return 1 + (uint64(w)-10)*9999/990
}

func limit(v int64) string {
	if v < 0 {
		return "max"
	}
	return strconv.FormatInt(v, 10)
}

// Files returns the v2 files and values for a set of OCI resources (in the order to write).
func Files(r *specs.LinuxResources) ([][2]string, error) {
	var out [][2]string
	if r == nil {
		return out, nil
	}
	if m := r.Memory; m != nil {
		if m.Limit != nil {
			out = append(out, [2]string{"memory.max", limit(*m.Limit)})
		}
		if m.Reservation != nil {
			out = append(out, [2]string{"memory.low", limit(*m.Reservation)})
		}
		if m.Swap != nil {
			// v1 "memsw" is memory + swap; v2 limits swap alone.
			swap := *m.Swap
			switch {
			case swap < 0:
				out = append(out, [2]string{"memory.swap.max", "max"})
			case m.Limit != nil && *m.Limit >= 0:
				if swap < *m.Limit {
					return nil, fmt.Errorf("memory.swap (%d) is lower than memory.limit (%d)", swap, *m.Limit)
				}
				out = append(out, [2]string{"memory.swap.max", strconv.FormatInt(swap-*m.Limit, 10)})
			}
		}
	}
	if c := r.CPU; c != nil {
		if c.Shares != nil && *c.Shares > 0 {
			out = append(out, [2]string{"cpu.weight", strconv.FormatUint(CPUWeight(*c.Shares), 10)})
		}
		if c.Quota != nil || c.Period != nil {
			period := uint64(100000)
			if c.Period != nil && *c.Period > 0 {
				period = *c.Period
			}
			quota := "max"
			if c.Quota != nil && *c.Quota > 0 {
				quota = strconv.FormatInt(*c.Quota, 10)
			}
			out = append(out, [2]string{"cpu.max", quota + " " + strconv.FormatUint(period, 10)})
		}
		if c.Cpus != "" {
			out = append(out, [2]string{"cpuset.cpus", c.Cpus})
		}
		if c.Mems != "" {
			out = append(out, [2]string{"cpuset.mems", c.Mems})
		}
	}
	if p := r.Pids; p != nil {
		out = append(out, [2]string{"pids.max", limit(p.Limit)})
	}
	if b := r.BlockIO; b != nil && b.Weight != nil && *b.Weight > 0 {
		out = append(out, [2]string{"io.weight", "default " + strconv.FormatUint(IOWeight(*b.Weight), 10)})
	}
	for k, v := range r.Unified {
		if strings.Contains(k, "/") || strings.HasPrefix(k, "cgroup.") {
			return nil, fmt.Errorf("unified key %q is not allowed", k)
		}
		out = append(out, [2]string{k, v})
	}
	return out, nil
}

// Apply writes the limits to an existing cgroup.
func Apply(dir string, r *specs.LinuxResources) error {
	files, err := Files(r)
	if err != nil {
		return err
	}
	for _, f := range files {
		if err := write(dir, f[0], f[1]); err != nil {
			// swap accounting may be off; a swap limit we cannot set is not fatal
			if f[0] == "memory.swap.max" && errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		}
	}
	return nil
}

// Join moves a process into the cgroup.
func Join(dir string, pid int) error {
	return write(dir, "cgroup.procs", strconv.Itoa(pid))
}

// Procs lists the processes in the cgroup.
func Procs(dir string) ([]int, error) {
	b, err := os.ReadFile(filepath.Join(dir, "cgroup.procs"))
	if err != nil {
		return nil, err
	}
	var out []int
	for _, f := range strings.Fields(string(b)) {
		if n, err := strconv.Atoi(f); err == nil {
			out = append(out, n)
		}
	}
	return out, nil
}

// Destroy kills everything in the cgroup and removes it.
func Destroy(dir string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil
	}
	_ = write(dir, "cgroup.kill", "1")
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := os.Remove(dir)
		if err == nil || os.IsNotExist(err) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("removing cgroup %s: %w", dir, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Stats is a snapshot of a cgroup's usage.
type Stats struct {
	MemoryCurrent uint64 `json:"memory_current"`
	MemoryMax     int64  `json:"memory_max"` // -1 = no limit
	MemoryPeak    uint64 `json:"memory_peak"`
	OOMKills      uint64 `json:"oom_kills"`
	CPUUsageUsec  uint64 `json:"cpu_usage_usec"`
	CPUThrottled  uint64 `json:"cpu_throttled_usec"`
	CPUMax        string `json:"cpu_max"`
	PidsCurrent   uint64 `json:"pids_current"`
	PidsMax       int64  `json:"pids_max"`
}

func readUint(dir, file string) uint64 {
	b, _ := os.ReadFile(filepath.Join(dir, file))
	n, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return n
}

func readLimit(dir, file string) int64 {
	b, _ := os.ReadFile(filepath.Join(dir, file))
	s := strings.TrimSpace(string(b))
	if s == "max" || s == "" {
		return -1
	}
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}

func readKeyed(dir, file string) map[string]uint64 {
	out := map[string]uint64{}
	f, err := os.Open(filepath.Join(dir, file))
	if err != nil {
		return out
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		parts := strings.Fields(s.Text())
		if len(parts) == 2 {
			n, _ := strconv.ParseUint(parts[1], 10, 64)
			out[parts[0]] = n
		}
	}
	return out
}

// Read returns the current usage.
func Read(dir string) (Stats, error) {
	if _, err := os.Stat(dir); err != nil {
		return Stats{}, err
	}
	cpu := readKeyed(dir, "cpu.stat")
	b, _ := os.ReadFile(filepath.Join(dir, "cpu.max"))
	return Stats{
		MemoryCurrent: readUint(dir, "memory.current"),
		MemoryMax:     readLimit(dir, "memory.max"),
		MemoryPeak:    readUint(dir, "memory.peak"),
		OOMKills:      readKeyed(dir, "memory.events")["oom_kill"],
		CPUUsageUsec:  cpu["usage_usec"],
		CPUThrottled:  cpu["throttled_usec"],
		CPUMax:        strings.TrimSpace(string(b)),
		PidsCurrent:   readUint(dir, "pids.current"),
		PidsMax:       readLimit(dir, "pids.max"),
	}, nil
}
