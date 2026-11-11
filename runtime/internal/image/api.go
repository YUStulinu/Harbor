package image

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/YUStulinu/Harbor/runtime/internal/cgroups"
)

// Sample is one point of a container's resource history.
type Sample struct {
	T          time.Time `json:"t"`
	CPUPercent float64   `json:"cpu_percent"` // of one core
	Memory     uint64    `json:"memory"`
	Pids       uint64    `json:"pids"`
}

// sampler keeps the last few minutes of usage for every running container.
type sampler struct {
	mu      sync.Mutex
	history map[string][]Sample
	last    map[string]cgroups.Stats
	lastT   map[string]time.Time
}

const historyLen = 150 // 5 minutes at one sample every 2 s

func (s *sampler) tick() {
	all, _ := All()
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range all {
		if Status(m) != "running" {
			continue
		}
		st, err := cgroups.Read(m.CgroupPath)
		if err != nil {
			continue
		}
		var cpu float64
		if prev, ok := s.last[m.ID]; ok && st.CPUUsageUsec >= prev.CPUUsageUsec {
			dt := now.Sub(s.lastT[m.ID]).Seconds()
			if dt > 0 {
				cpu = float64(st.CPUUsageUsec-prev.CPUUsageUsec) / 1e6 / dt * 100
			}
		}
		s.last[m.ID], s.lastT[m.ID] = st, now
		h := append(s.history[m.ID], Sample{T: now, CPUPercent: cpu, Memory: st.MemoryCurrent, Pids: st.PidsCurrent})
		if len(h) > historyLen {
			h = h[len(h)-historyLen:]
		}
		s.history[m.ID] = h
	}
}

func (s *sampler) get(id string) []Sample {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Sample(nil), s.history[id]...)
}

// ContainerView is a container as the API returns it.
type ContainerView struct {
	*Meta
	Status  string         `json:"status"`
	Stats   *cgroups.Stats `json:"stats,omitempty"`
	History []Sample       `json:"history,omitempty"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

// Serve runs the HTTP API and the web UI.
func Serve(ociRoot, addr, web string) error {
	s := &sampler{history: map[string][]Sample{}, last: map[string]cgroups.Stats{}, lastT: map[string]time.Time{}}
	go func() {
		for {
			s.tick()
			time.Sleep(2 * time.Second)
		}
	}()
	view := func(m *Meta, history bool) ContainerView {
		v := ContainerView{Meta: m, Status: Status(m)}
		if v.Status == "running" || v.Status == "created" {
			if st, err := cgroups.Read(m.CgroupPath); err == nil {
				v.Stats = &st
			}
		}
		if history {
			v.History = s.get(m.ID)
		}
		return v
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/host", func(w http.ResponseWriter, r *http.Request) {
		var u unix.Utsname
		unix.Uname(&u)
		var si unix.Sysinfo_t
		unix.Sysinfo(&si)
		writeJSON(w, 200, map[string]any{
			"kernel": unix.ByteSliceToString(u.Release[:]), "hostname": unix.ByteSliceToString(u.Nodename[:]),
			"cpus": runtime.NumCPU(), "memory": uint64(si.Totalram) * uint64(si.Unit), "bridge": Bridge, "subnet": Subnet,
		})
	})
	mux.HandleFunc("/api/images", func(w http.ResponseWriter, r *http.Request) {
		out, err := exec.Command(Registry, "images").Output()
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		var list []map[string]string
		for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			f := strings.Split(l, "\t")
			if len(f) == 3 {
				list = append(list, map[string]string{"name": f[0], "digest": f[1], "size": f[2]})
			}
		}
		writeJSON(w, 200, list)
	})
	mux.HandleFunc("/api/containers", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			all, err := All()
			if err != nil {
				writeErr(w, 500, err)
				return
			}
			out := []ContainerView{}
			for _, m := range all {
				out = append(out, view(m, false))
			}
			writeJSON(w, 200, out)
		case http.MethodPost:
			// JSON with a custom header: a page on another origin cannot send this without a
			// CORS preflight, which this server never approves.
			if r.Header.Get("X-Harbor") != "1" || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
				writeErr(w, 403, errors.New("use the API with Content-Type: application/json and X-Harbor: 1"))
				return
			}
			var req struct {
				Image  string   `json:"image"`
				Args   []string `json:"args"`
				Name   string   `json:"name"`
				Memory string   `json:"memory"`
				CPUs   float64  `json:"cpus"`
				Pids   int64    `json:"pids"`
				Net    string   `json:"net"`
				Env    []string `json:"env"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil || req.Image == "" {
				writeErr(w, 400, fmt.Errorf("bad request: need at least an image (%v)", err))
				return
			}
			o := RunOptions{Image: req.Image, Args: req.Args, Name: req.Name, Net: req.Net, Env: req.Env, Detach: true}
			o.Limits.CPUs, o.Limits.Pids = req.CPUs, req.Pids
			if req.Memory != "" {
				b, err := ParseSize(req.Memory)
				if err != nil {
					writeErr(w, 400, err)
					return
				}
				o.Limits.MemoryBytes = b
			}
			m, _, err := Run(ociRoot, o)
			if err != nil {
				writeErr(w, 400, err)
				return
			}
			writeJSON(w, 201, view(m, false))
		default:
			writeErr(w, 405, errors.New("GET or POST"))
		}
	})
	mux.HandleFunc("/api/containers/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/api/containers/")
		ref, action, _ := strings.Cut(rest, "/")
		m, err := Find(ref)
		if err != nil {
			writeErr(w, 404, err)
			return
		}
		mutating := r.Method != http.MethodGet
		if mutating && r.Header.Get("X-Harbor") != "1" {
			writeErr(w, 403, errors.New("missing X-Harbor: 1"))
			return
		}
		switch {
		case action == "" && r.Method == http.MethodGet:
			v := view(m, true)
			writeJSON(w, 200, v)
		case action == "" && r.Method == http.MethodDelete:
			if err := Remove(m, r.URL.Query().Get("force") == "1"); err != nil {
				writeErr(w, 409, err)
				return
			}
			writeJSON(w, 200, map[string]string{"removed": m.ID})
		case action == "stop" && r.Method == http.MethodPost:
			if err := Stop(m, 10*time.Second); err != nil {
				writeErr(w, 409, err)
				return
			}
			writeJSON(w, 200, map[string]string{"stopped": m.ID})
		case action == "logs" && r.Method == http.MethodGet:
			skip, _ := strconv.Atoi(r.URL.Query().Get("since"))
			lines, err := ReadLogs(m, skip)
			if err != nil {
				writeErr(w, 500, err)
				return
			}
			if lines == nil {
				lines = []logLine{}
			}
			writeJSON(w, 200, map[string]any{"next": skip + len(lines), "lines": lines})
		case action == "config" && r.Method == http.MethodGet:
			b, err := os.ReadFile(filepath.Join(m.bundle(), "config.json"))
			if err != nil {
				writeErr(w, 404, err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(b)
		default:
			writeErr(w, 404, errors.New("unknown endpoint"))
		}
	})
	files := http.FileServer(http.Dir(web))
	mux.Handle("/", files)
	fmt.Fprintf(os.Stderr, "harbor UI on http://%s/ (web files from %s)\n", addr, web)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	return srv.ListenAndServe()
}
