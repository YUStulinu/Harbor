package image

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/YUStulinu/Harbor/runtime/internal/cgroups"
)

// Command runs the image-level commands of the CLI.
func Command(ociRoot, cmd string, args []string) error {
	switch cmd {
	case "pull", "images":
		c := exec.Command(Registry, append([]string{cmd}, args...)...)
		c.Stdout, c.Stderr = os.Stdout, os.Stderr
		return c.Run()
	case "run-image":
		o, err := parseRun(args)
		if err != nil {
			return err
		}
		m, code, err := Run(ociRoot, o)
		if err != nil {
			return err
		}
		if o.Detach {
			fmt.Println(m.ID)
			return nil
		}
		os.Exit(code)
	case "ps":
		all, err := All()
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tNAME\tIMAGE\tSTATUS\tIP\tCOMMAND")
		for _, m := range all {
			st := Status(m)
			if st == "exited" && m.ExitCode != nil {
				st = fmt.Sprintf("exited (%d)", *m.ExitCode)
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", m.ID[:12], m.Name, m.Image, st, m.IP, strings.Join(m.Args, " "))
		}
		return w.Flush()
	case "logs", "stats", "stop", "rm", "inspect":
		force := false
		var ref string
		for _, a := range args {
			if a == "-f" || a == "--force" {
				force = true
			} else {
				ref = a
			}
		}
		if ref == "" {
			return ErrUsage
		}
		m, err := Find(ref)
		if err != nil {
			return err
		}
		switch cmd {
		case "logs":
			lines, err := ReadLogs(m, 0)
			if err != nil {
				return err
			}
			for _, l := range lines {
				out := os.Stdout
				if l.Stream == "stderr" {
					out = os.Stderr
				}
				fmt.Fprintln(out, l.Line)
			}
		case "stats":
			s, err := cgroups.Read(m.CgroupPath)
			if err != nil {
				return fmt.Errorf("container %s is not running", m.Name)
			}
			b, _ := json.MarshalIndent(s, "", "  ")
			fmt.Println(string(b))
		case "inspect":
			b, _ := json.MarshalIndent(m, "", "  ")
			fmt.Println(string(b))
		case "stop":
			return Stop(m, 10*time.Second)
		case "rm":
			return Remove(m, force)
		}
		return nil
	case "serve":
		addr, web := "127.0.0.1:8800", "web/dist"
		for i := 0; i+1 < len(args); i += 2 {
			switch args[i] {
			case "--addr":
				addr = args[i+1]
			case "--web":
				web = args[i+1]
			default:
				return ErrUsage
			}
		}
		return Serve(ociRoot, addr, web)
	}
	return ErrUsage
}

func parseRun(args []string) (RunOptions, error) {
	var o RunOptions
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			o.Image = a
			o.Args = args[i+1:]
			break
		}
		val := func() (string, error) {
			if k, v, ok := strings.Cut(a, "="); ok && strings.HasPrefix(k, "--") {
				return v, nil
			}
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s needs a value", a)
			}
			i++
			return args[i], nil
		}
		name, _, _ := strings.Cut(a, "=")
		var err error
		var v string
		switch name {
		case "-d", "--detach":
			o.Detach = true
		case "--rm":
			o.Remove = true
		case "--read-only":
			o.ReadOnly = true
		case "--name":
			o.Name, err = val()
		case "--hostname":
			o.Hostname, err = val()
		case "--net", "--network":
			o.Net, err = val()
		case "-e", "--env":
			if v, err = val(); err == nil {
				o.Env = append(o.Env, v)
			}
		case "-m", "--memory":
			if v, err = val(); err == nil {
				o.Limits.MemoryBytes, err = ParseSize(v)
			}
		case "--cpus":
			if v, err = val(); err == nil {
				o.Limits.CPUs, err = strconv.ParseFloat(v, 64)
				if err == nil && o.Limits.CPUs <= 0 {
					err = fmt.Errorf("--cpus must be positive")
				}
			}
		case "--pids":
			if v, err = val(); err == nil {
				o.Limits.Pids, err = strconv.ParseInt(v, 10, 64)
			}
		default:
			return o, fmt.Errorf("unknown flag %s", a)
		}
		if err != nil {
			return o, err
		}
	}
	if o.Image == "" {
		return o, ErrUsage
	}
	return o, nil
}
