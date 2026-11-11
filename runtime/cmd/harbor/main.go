// harbor: an OCI container runtime, plus image-based containers with overlayfs, a bridge
// network, logs and a web UI.
//
// OCI runtime commands (the runc command line, as used by runtime-tools):
//
//	harbor [--root DIR] create [--bundle DIR] [--pid-file FILE] ID
//	harbor [--root DIR] start ID
//	harbor [--root DIR] state ID
//	harbor [--root DIR] kill ID [SIGNAL]
//	harbor [--root DIR] delete [--force] ID
//	harbor [--root DIR] run [--bundle DIR] [--pid-file FILE] ID     create + start + wait
//	harbor [--root DIR] list
//	harbor spec [--rootless]                                          write a default config.json
//
// Images and containers (see `harbor help`):
//
//	harbor pull IMAGE | images
//	harbor run-image [-d] [--name N] [--memory 64m] [--cpus 0.5] [--pids N] [--net bridge|none|host] [-e K=V] IMAGE [CMD...]
//	harbor ps | logs ID | stats ID | stop ID | rm [-f] ID
//	harbor serve [--addr 127.0.0.1:8800] [--web DIR]
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"text/tabwriter"

	"golang.org/x/sys/unix"

	"github.com/YUStulinu/Harbor/runtime/internal/container"
	"github.com/YUStulinu/Harbor/runtime/internal/image"
	_ "github.com/YUStulinu/Harbor/runtime/internal/nsenter"
)

func init() {
	// The container's init sets credentials and seccomp on its thread and then execs: it
	// must stay on the main thread from the start.
	if len(os.Args) > 1 && os.Args[1] == "init" {
		runtime.GOMAXPROCS(1)
		runtime.LockOSThread()
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: harbor [--root DIR] COMMAND
OCI runtime:  create [--bundle DIR] [--pid-file F] ID | start ID | state ID | kill ID [SIG]
              delete [--force] ID | run [--bundle DIR] ID | list | spec
Images:       pull IMAGE | images
Containers:   run-image [-d] [--rm] [--name N] [--memory SIZE] [--cpus N] [--pids N] [--net bridge|none|host]
                        [-e KEY=VAL] [--hostname H] [--read-only] IMAGE [CMD ARG...]
              ps | logs ID | stats ID | stop ID | rm [-f] ID
UI:           serve [--addr 127.0.0.1:8800] [--web DIR]
`)
	os.Exit(2)
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "harbor:", err)
	os.Exit(1)
}

// flagSet is a tiny parser for "--name value", "--name=value" and boolean flags.
type flagSet struct {
	vals  map[string]*string
	bools map[string]*bool
	multi map[string]*[]string
	args  []string
}

func newFlags() *flagSet {
	return &flagSet{vals: map[string]*string{}, bools: map[string]*bool{}, multi: map[string]*[]string{}}
}
func (f *flagSet) str(def string, names ...string) *string {
	v := def
	for _, n := range names {
		f.vals[n] = &v
	}
	return &v
}
func (f *flagSet) boolean(names ...string) *bool {
	var v bool
	for _, n := range names {
		f.bools[n] = &v
	}
	return &v
}
func (f *flagSet) list(names ...string) *[]string {
	var v []string
	for _, n := range names {
		f.multi[n] = &v
	}
	return &v
}

// parse stops at the first non-flag argument when stopAtArg is set (for container commands).
func (f *flagSet) parse(args []string, stopAtArg bool) error {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			f.args = append(f.args, args[i+1:]...)
			return nil
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			if stopAtArg {
				f.args = append(f.args, args[i:]...)
				return nil
			}
			f.args = append(f.args, a)
			continue
		}
		name, val, hasVal := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if b, ok := f.bools[name]; ok {
			*b = !hasVal || val == "true"
			continue
		}
		dst, ok := f.vals[name]
		m, isMulti := f.multi[name]
		if !ok && !isMulti {
			return fmt.Errorf("unknown flag %s", a)
		}
		if !hasVal {
			if i+1 >= len(args) {
				return fmt.Errorf("flag %s needs a value", a)
			}
			i++
			val = args[i]
		}
		if isMulti {
			*m = append(*m, val)
		} else {
			*dst = val
		}
	}
	return nil
}

func printJSON(v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "init" {
		container.Init()
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "_shim" {
		image.Shim(os.Args[2:])
		return
	}
	g := newFlags()
	root := g.str(container.DefaultRoot, "root")
	g.str("", "log", "log-format") // accepted for runc compatibility; errors go to stderr
	g.boolean("debug", "systemd-cgroup")
	if err := g.parse(os.Args[1:], true); err != nil {
		die(err)
	}
	if len(g.args) == 0 {
		usage()
	}
	cmd, rest := g.args[0], g.args[1:]
	f := newFlags()
	switch cmd {
	case "create", "run":
		bundle := f.str(".", "bundle", "b")
		pidFile := f.str("", "pid-file")
		console := f.str("", "console-socket")
		f.boolean("no-pivot", "no-new-keyring", "detach", "d")
		if err := f.parse(rest, false); err != nil {
			die(err)
		}
		if len(f.args) != 1 {
			usage()
		}
		if *console != "" {
			die(errors.New("--console-socket is not supported"))
		}
		id := f.args[0]
		if cmd == "create" {
			if _, err := container.Create(*root, id, *bundle, container.CreateOptions{PidFile: *pidFile}); err != nil {
				die(err)
			}
			return
		}
		p, err := container.Create(*root, id, *bundle, container.CreateOptions{PidFile: *pidFile, KeepChild: true})
		if err != nil {
			die(err)
		}
		if err := container.Start(*root, id); err != nil {
			die(err)
		}
		st, err := p.Wait()
		container.Delete(*root, id, true)
		if err != nil {
			die(err)
		}
		code := st.ExitCode()
		if ws, ok := st.Sys().(unix.WaitStatus); ok && ws.Signaled() {
			code = 128 + int(ws.Signal())
		}
		os.Exit(code)
	case "start", "state":
		if err := f.parse(rest, false); err != nil || len(f.args) != 1 {
			usage()
		}
		if cmd == "start" {
			if err := container.Start(*root, f.args[0]); err != nil {
				die(err)
			}
			return
		}
		st, err := container.State(*root, f.args[0])
		if err != nil {
			die(err)
		}
		printJSON(st)
	case "kill":
		all := f.boolean("all", "a")
		if err := f.parse(rest, false); err != nil || len(f.args) < 1 || len(f.args) > 2 {
			usage()
		}
		_ = all
		sig := "SIGTERM"
		if len(f.args) == 2 {
			sig = f.args[1]
		}
		s, err := container.ParseSignal(sig)
		if err != nil {
			die(err)
		}
		if err := container.Kill(*root, f.args[0], s); err != nil {
			die(err)
		}
	case "delete":
		force := f.boolean("force", "f")
		if err := f.parse(rest, false); err != nil || len(f.args) != 1 {
			usage()
		}
		if err := container.Delete(*root, f.args[0], *force); err != nil {
			die(err)
		}
	case "list":
		cs, err := container.List(*root)
		if err != nil {
			die(err)
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tPID\tSTATUS\tBUNDLE\tCREATED")
		for _, c := range cs {
			st := c.OCIState()
			fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\n", c.ID, st.Pid, st.Status, c.Bundle, c.Created.Format("2006-01-02T15:04:05Z"))
		}
		w.Flush()
	case "spec":
		rootless := f.boolean("rootless")
		if err := f.parse(rest, false); err != nil {
			usage()
		}
		if _, err := os.Stat("config.json"); err == nil {
			die(errors.New("config.json already exists"))
		}
		s := image.DefaultSpec([]string{"sh"}, nil, "/", *rootless)
		b, _ := json.MarshalIndent(s, "", "  ")
		if err := os.WriteFile("config.json", append(b, '\n'), 0o644); err != nil {
			die(err)
		}
	default:
		if err := image.Command(*root, cmd, rest); err != nil {
			if errors.Is(err, image.ErrUsage) {
				usage()
			}
			die(err)
		}
	}
}
