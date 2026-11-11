package container

import (
	"fmt"
	"os"
	"path/filepath"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

// The devices every container gets (runtime spec, "Default Devices").
var defaultDevices = []specs.LinuxDevice{
	{Path: "/dev/null", Type: "c", Major: 1, Minor: 3},
	{Path: "/dev/zero", Type: "c", Major: 1, Minor: 5},
	{Path: "/dev/full", Type: "c", Major: 1, Minor: 7},
	{Path: "/dev/random", Type: "c", Major: 1, Minor: 8},
	{Path: "/dev/urandom", Type: "c", Major: 1, Minor: 9},
	{Path: "/dev/tty", Type: "c", Major: 5, Minor: 0},
}

var propagation = map[string]uintptr{
	"": unix.MS_SLAVE | unix.MS_REC, "slave": unix.MS_SLAVE, "rslave": unix.MS_SLAVE | unix.MS_REC,
	"private": unix.MS_PRIVATE, "rprivate": unix.MS_PRIVATE | unix.MS_REC,
	"shared": unix.MS_SHARED, "rshared": unix.MS_SHARED | unix.MS_REC,
	"unbindable": unix.MS_UNBINDABLE, "runbindable": unix.MS_UNBINDABLE | unix.MS_REC,
}

// prepareRootfs runs in the container's mount namespace, before pivot_root: it makes the
// rootfs a mount point, performs the configured mounts and creates the devices.
func prepareRootfs(cfg *initConfig) error {
	s := cfg.Spec
	if _, ok := propagation[s.Linux.RootfsPropagation]; !ok {
		return fmt.Errorf("unknown rootfsPropagation %q", s.Linux.RootfsPropagation)
	}
	// Nothing we mount may reach the host. The configured rootfsPropagation is applied to the
	// container's root after pivot_root (finishRootfs).
	if err := unix.Mount("", "/", "", unix.MS_SLAVE|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("root propagation: %w", err)
	}
	rootfs := cfg.Rootfs
	if err := unix.Mount(rootfs, rootfs, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("bind-mounting the rootfs: %w", err)
	}
	for _, m := range s.Mounts {
		if !filepath.IsAbs(m.Destination) {
			return fmt.Errorf("mount destination %q must be absolute", m.Destination)
		}
		dest, err := secureJoin(rootfs, m.Destination)
		if err != nil {
			return err
		}
		src := m.Source
		typ := m.Type
		if typ == "" && hasOption(m.Options, "bind", "rbind") {
			typ = "bind"
		}
		if typ == "bind" && !filepath.IsAbs(src) {
			src = filepath.Join(cfg.Bundle, src)
		}
		if err := doMount(src, dest, typ, m.Options); err != nil {
			return err
		}
	}
	if err := createDevices(rootfs, s.Linux.Devices); err != nil {
		return err
	}
	return nil
}

func hasOption(opts []string, names ...string) bool {
	for _, o := range opts {
		for _, n := range names {
			if o == n {
				return true
			}
		}
	}
	return false
}

func createDevices(rootfs string, devs []specs.LinuxDevice) error {
	dev := filepath.Join(rootfs, "dev")
	if err := os.MkdirAll(dev, 0o755); err != nil {
		return err
	}
	all := append([]specs.LinuxDevice{}, defaultDevices...)
	for _, d := range devs {
		// A configured device replaces a default one with the same path.
		replaced := false
		for i := range all {
			if all[i].Path == d.Path {
				all[i], replaced = d, true
			}
		}
		if !replaced {
			all = append(all, d)
		}
	}
	for _, d := range all {
		if err := createDevice(rootfs, d); err != nil {
			return err
		}
	}
	for link, target := range map[string]string{"/dev/fd": "/proc/self/fd", "/dev/stdin": "/proc/self/fd/0", "/dev/stdout": "/proc/self/fd/1", "/dev/stderr": "/proc/self/fd/2"} {
		p := filepath.Join(rootfs, link)
		if _, err := os.Lstat(p); os.IsNotExist(err) {
			if err := os.Symlink(target, p); err != nil {
				return err
			}
		}
	}
	// /dev/ptmx points into the container's own devpts, when there is one.
	if fi, err := os.Stat(filepath.Join(dev, "pts", "ptmx")); err == nil && !fi.IsDir() {
		p := filepath.Join(dev, "ptmx")
		os.Remove(p)
		if err := os.Symlink("pts/ptmx", p); err != nil {
			return err
		}
	}
	return nil
}

func createDevice(rootfs string, d specs.LinuxDevice) error {
	if !filepath.IsAbs(d.Path) {
		return fmt.Errorf("device path %q must be absolute", d.Path)
	}
	dest, err := secureJoin(rootfs, d.Path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	var mode uint32
	switch d.Type {
	case "c", "u":
		mode = unix.S_IFCHR
	case "b":
		mode = unix.S_IFBLK
	case "p":
		mode = unix.S_IFIFO
	default:
		return fmt.Errorf("device %s: unknown type %q", d.Path, d.Type)
	}
	perm := uint32(0o666)
	if d.FileMode != nil {
		perm = uint32(*d.FileMode) & 0o7777
	}
	os.Remove(dest)
	err = unix.Mknod(dest, mode|perm, int(unix.Mkdev(uint32(d.Major), uint32(d.Minor))))
	if err == unix.EPERM {
		// In a user namespace mknod is not allowed: bind the host's device instead.
		if err := ensureTarget(dest, true); err != nil {
			return err
		}
		if err := unix.Mount(d.Path, dest, "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("device %s: bind: %w", d.Path, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("device %s: mknod: %w", d.Path, err)
	}
	// mknod applies the umask: set the mode explicitly.
	if err := unix.Chmod(dest, perm); err != nil {
		return err
	}
	uid, gid := -1, -1
	if d.UID != nil {
		uid = int(*d.UID)
	}
	if d.GID != nil {
		gid = int(*d.GID)
	}
	if uid >= 0 || gid >= 0 {
		if err := unix.Chown(dest, uid, gid); err != nil {
			return fmt.Errorf("device %s: chown: %w", d.Path, err)
		}
	}
	return nil
}

// pivotRoot makes rootfs the root without a temporary directory: pivot_root(".", ".") stacks
// the old root under the new one, and the detach removes it (the trick runc uses).
func pivotRoot(rootfs string) error {
	oldroot, err := unix.Open("/", unix.O_DIRECTORY|unix.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer unix.Close(oldroot)
	newroot, err := unix.Open(rootfs, unix.O_DIRECTORY|unix.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer unix.Close(newroot)
	if err := unix.Fchdir(newroot); err != nil {
		return err
	}
	if err := unix.PivotRoot(".", "."); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}
	if err := unix.Fchdir(oldroot); err != nil {
		return err
	}
	// The old root must not propagate the unmount back to the host.
	if err := unix.Mount("", ".", "", unix.MS_SLAVE|unix.MS_REC, ""); err != nil {
		return err
	}
	if err := unix.Unmount(".", unix.MNT_DETACH); err != nil {
		return fmt.Errorf("detaching the old root: %w", err)
	}
	return unix.Chdir("/")
}

// remountReadonly makes an existing mount read-only, keeping the flags the kernel requires
// to be kept (nosuid, nodev, noexec, atime flags locked in a user namespace).
func remountReadonly(p string) error {
	var st unix.Statfs_t
	if err := unix.Statfs(p, &st); err != nil {
		return err
	}
	keep := uintptr(st.Flags) & (unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC | unix.MS_NOATIME | unix.MS_NODIRATIME | unix.MS_RELATIME)
	return unix.Mount("", p, "", unix.MS_REMOUNT|unix.MS_BIND|unix.MS_RDONLY|keep, "")
}

// finishRootfs runs after pivot_root: root propagation, masked and read-only paths, and a
// read-only root.
func finishRootfs(s *specs.Spec) error {
	if s.Linux.RootfsPropagation != "" {
		if err := unix.Mount("", "/", "", propagation[s.Linux.RootfsPropagation], ""); err != nil {
			return fmt.Errorf("rootfsPropagation %s: %w", s.Linux.RootfsPropagation, err)
		}
	}
	for _, p := range s.Linux.ReadonlyPaths {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if err := unix.Mount(p, p, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
			return fmt.Errorf("readonly path %s: %w", p, err)
		}
		if err := remountReadonly(p); err != nil {
			return fmt.Errorf("readonly path %s: %w", p, err)
		}
	}
	for _, p := range s.Linux.MaskedPaths {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		if fi.IsDir() {
			err = unix.Mount("tmpfs", p, "tmpfs", unix.MS_RDONLY, "")
		} else {
			err = unix.Mount("/dev/null", p, "", unix.MS_BIND, "")
		}
		if err != nil {
			return fmt.Errorf("masked path %s: %w", p, err)
		}
	}
	if s.Root.Readonly {
		if err := remountReadonly("/"); err != nil {
			return fmt.Errorf("read-only root: %w", err)
		}
	}
	return nil
}
