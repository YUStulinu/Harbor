package image

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Dir holds one directory per image-based container.
var Dir = "/var/lib/harbor/containers"

// Registry is the harbor-registry binary (looked up in PATH unless set).
var Registry = "harbor-registry"

// ImageInfo is `harbor-registry inspect` output.
type ImageInfo struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
	Config struct {
		Env        []string `json:"Env"`
		Entrypoint []string `json:"Entrypoint"`
		Cmd        []string `json:"Cmd"`
		WorkingDir string   `json:"WorkingDir"`
		User       string   `json:"User"`
	} `json:"config"`
	Layers []string `json:"layers"`
	Size   int64    `json:"size"`
}

// Inspect asks harbor-registry about an image (pulling it if it is not stored yet).
func Inspect(name string, pull bool) (*ImageInfo, error) {
	out, err := exec.Command(Registry, "inspect", name).Output()
	if err != nil && pull {
		p := exec.Command(Registry, "pull", name)
		p.Stdout, p.Stderr = os.Stderr, os.Stderr
		if perr := p.Run(); perr != nil {
			return nil, fmt.Errorf("pulling %s: %w", name, perr)
		}
		out, err = exec.Command(Registry, "inspect", name).Output()
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, fmt.Errorf("%s inspect %s: %s", Registry, name, strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, err
	}
	var info ImageInfo
	if err := json.Unmarshal(out, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// Limits are the resource flags of run-image.
type Limits struct {
	MemoryBytes int64   `json:"memory_bytes,omitempty"`
	CPUs        float64 `json:"cpus,omitempty"`
	Pids        int64   `json:"pids,omitempty"`
}

// Meta is what we keep about an image-based container (meta.json in its directory).
type Meta struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Image      string     `json:"image"`
	Digest     string     `json:"digest"`
	Args       []string   `json:"args"`
	Created    time.Time  `json:"created"`
	Started    *time.Time `json:"started,omitempty"`
	Finished   *time.Time `json:"finished,omitempty"`
	ExitCode   *int       `json:"exit_code,omitempty"`
	Error      string     `json:"error,omitempty"`
	Pid        int        `json:"pid,omitempty"`
	Net        string     `json:"net"`
	IP         string     `json:"ip,omitempty"`
	Limits     Limits     `json:"limits"`
	Detached   bool       `json:"detached"`
	AutoRemove bool       `json:"auto_remove"`
	OCIRoot    string     `json:"oci_root"`
	CgroupPath string     `json:"cgroup_path,omitempty"`
	Final      any        `json:"final_stats,omitempty"` // cgroup usage when the process ended
}

func (m *Meta) dir() string      { return filepath.Join(Dir, m.ID) }
func (m *Meta) bundle() string   { return filepath.Join(m.dir(), "bundle") }
func (m *Meta) rootfs() string   { return filepath.Join(m.bundle(), "rootfs") }
func (m *Meta) logPath() string  { return filepath.Join(m.dir(), "log.jsonl") }
func (m *Meta) metaPath() string { return filepath.Join(m.dir(), "meta.json") }

func (m *Meta) save() error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.metaPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.metaPath())
}

func loadMeta(id string) (*Meta, error) {
	b, err := os.ReadFile(filepath.Join(Dir, id, "meta.json"))
	if err != nil {
		return nil, err
	}
	var m Meta
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// Find resolves a container by id, id prefix or name.
func Find(ref string) (*Meta, error) {
	all, err := All()
	if err != nil {
		return nil, err
	}
	var hits []*Meta
	for _, m := range all {
		if m.ID == ref || m.Name == ref {
			return m, nil
		}
		if len(ref) >= 3 && strings.HasPrefix(m.ID, ref) {
			hits = append(hits, m)
		}
	}
	switch len(hits) {
	case 0:
		return nil, fmt.Errorf("no container %s", ref)
	case 1:
		return hits[0], nil
	}
	return nil, fmt.Errorf("%s matches %d containers", ref, len(hits))
}

// All lists the image-based containers, newest first.
func All() ([]*Meta, error) {
	ents, err := os.ReadDir(Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []*Meta
	for _, e := range ents {
		if m, err := loadMeta(e.Name()); err == nil {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out, nil
}

func newID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
