package container

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// mountOpts is a parsed mount option list.
type mountOpts struct {
	flags       uintptr // flags for the mount itself
	clear       uintptr // flags explicitly turned off (rw, suid, dev, exec, ...)
	propagation []uintptr
	data        []string
	bind        bool
	recursive   bool
}

var optFlags = map[string]struct {
	clear bool
	flag  uintptr
}{
	"ro": {false, unix.MS_RDONLY}, "rw": {true, unix.MS_RDONLY},
	"nosuid": {false, unix.MS_NOSUID}, "suid": {true, unix.MS_NOSUID},
	"nodev": {false, unix.MS_NODEV}, "dev": {true, unix.MS_NODEV},
	"noexec": {false, unix.MS_NOEXEC}, "exec": {true, unix.MS_NOEXEC},
	"sync": {false, unix.MS_SYNCHRONOUS}, "async": {true, unix.MS_SYNCHRONOUS},
	"dirsync": {false, unix.MS_DIRSYNC}, "remount": {false, unix.MS_REMOUNT},
	"mand": {false, unix.MS_MANDLOCK}, "nomand": {true, unix.MS_MANDLOCK},
	"noatime": {false, unix.MS_NOATIME}, "atime": {true, unix.MS_NOATIME},
	"nodiratime": {false, unix.MS_NODIRATIME}, "diratime": {true, unix.MS_NODIRATIME},
	"relatime": {false, unix.MS_RELATIME}, "norelatime": {true, unix.MS_RELATIME},
	"strictatime": {false, unix.MS_STRICTATIME}, "nostrictatime": {true, unix.MS_STRICTATIME},
	"silent": {false, unix.MS_SILENT}, "loud": {true, unix.MS_SILENT},
}

var propFlags = map[string]uintptr{
	"private": unix.MS_PRIVATE, "rprivate": unix.MS_PRIVATE | unix.MS_REC,
	"shared": unix.MS_SHARED, "rshared": unix.MS_SHARED | unix.MS_REC,
	"slave": unix.MS_SLAVE, "rslave": unix.MS_SLAVE | unix.MS_REC,
	"unbindable": unix.MS_UNBINDABLE, "runbindable": unix.MS_UNBINDABLE | unix.MS_REC,
}

func parseMountOptions(opts []string) mountOpts {
	var m mountOpts
	for _, o := range opts {
		switch {
		case o == "bind":
			m.bind = true
		case o == "rbind":
			m.bind, m.recursive = true, true
		case propFlags[o] != 0:
			m.propagation = append(m.propagation, propFlags[o])
		default:
			if f, ok := optFlags[o]; ok {
				if f.clear {
					m.flags &^= f.flag
					m.clear |= f.flag
				} else {
					m.flags |= f.flag
				}
			} else if o != "" && o != "defaults" {
				m.data = append(m.data, o)
			}
		}
	}
	return m
}

// secureJoin resolves path inside root as if root were "/": symbolic links are followed but
// can never lead outside root (an absolute link target restarts at root, ".." stops at root).
// The result need not exist.
func secureJoin(root, path string) (string, error) {
	const maxLinks = 255
	links := 0
	var cur string // resolved, relative to root, always clean
	rest := path
	for rest != "" {
		var part string
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			part, rest = rest[:i], rest[i+1:]
		} else {
			part, rest = rest, ""
		}
		switch part {
		case "", ".":
			continue
		case "..":
			cur = filepath.Dir("/" + cur)[1:]
			continue
		}
		next := filepath.Join(cur, part)
		fi, err := os.Lstat(filepath.Join(root, next))
		if err != nil || fi.Mode()&os.ModeSymlink == 0 {
			cur = next
			continue
		}
		links++
		if links > maxLinks {
			return "", fmt.Errorf("too many symbolic links resolving %s", path)
		}
		target, err := os.Readlink(filepath.Join(root, next))
		if err != nil {
			return "", err
		}
		if filepath.IsAbs(target) {
			cur = ""
		}
		rest = target + "/" + rest
	}
	return filepath.Join(root, cur), nil
}

// ensureTarget creates the mount point: a directory, or an empty file when mounting a file.
func ensureTarget(dest string, file bool) error {
	if fi, err := os.Stat(dest); err == nil {
		if file && fi.IsDir() {
			return fmt.Errorf("cannot mount a file on directory %s", dest)
		}
		return nil
	}
	if !file {
		return os.MkdirAll(dest, 0o755)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	return f.Close()
}

func mountErr(op, src, dst, typ string, err error) error {
	return fmt.Errorf("%s %s on %s (type %s): %w", op, src, dst, typ, err)
}

// doMount performs one mount (from config.json) at dest, which is already inside the rootfs.
func doMount(src, dest, typ string, options []string) error {
	o := parseMountOptions(options)
	data := strings.Join(o.data, ",")
	if typ == "bind" {
		o.bind = true
	}
	if o.bind {
		fi, err := os.Stat(src)
		if err != nil {
			return mountErr("bind", src, dest, typ, err)
		}
		if err := ensureTarget(dest, !fi.IsDir()); err != nil {
			return err
		}
		flags := uintptr(unix.MS_BIND)
		if o.recursive {
			flags |= unix.MS_REC
		}
		if err := unix.Mount(src, dest, "", flags, ""); err != nil {
			return mountErr("bind", src, dest, typ, err)
		}
		// Bind mounts ignore other flags: apply them with a remount.
		if rem := o.flags &^ unix.MS_REMOUNT; rem != 0 {
			if err := unix.Mount("", dest, "", unix.MS_REMOUNT|unix.MS_BIND|rem, ""); err != nil {
				return mountErr("remount", src, dest, typ, err)
			}
		}
	} else {
		if err := ensureTarget(dest, false); err != nil {
			return err
		}
		if typ == "cgroup" {
			typ = "cgroup2" // the host has only the unified hierarchy
			data = ""
		}
		err := unix.Mount(src, dest, typ, o.flags, data)
		if err != nil && typ == "sysfs" && errors.Is(err, unix.EPERM) {
			// Without a network namespace of our own, sysfs cannot be mounted: bind the host's.
			err = unix.Mount("/sys", dest, "", unix.MS_BIND|unix.MS_REC, "")
			if err == nil && o.flags&unix.MS_RDONLY != 0 {
				err = unix.Mount("", dest, "", unix.MS_REMOUNT|unix.MS_BIND|unix.MS_RDONLY, "")
			}
		}
		if err != nil {
			return mountErr("mount", src, dest, typ, err)
		}
	}
	for _, p := range o.propagation {
		if err := unix.Mount("", dest, "", p, ""); err != nil {
			return mountErr("propagation", src, dest, typ, err)
		}
	}
	return nil
}

func readFileString(p string) (string, error) {
	b, err := os.ReadFile(p)
	return string(b), err
}
