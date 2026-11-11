package image

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// The bridge network: every container with --net bridge gets a veth pair, one end in its
// network namespace as eth0 with an address in Subnet, the other end on the harbor0 bridge.
// Outgoing traffic is masqueraded behind the host's address.
const (
	Bridge  = "harbor0"
	Gateway = "10.88.0.1"
	Subnet  = "10.88.0.0/16"
)

// NetDir holds one file per allocated address.
var NetDir = "/var/lib/harbor/net"

func sh(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ensureBridge creates harbor0 and the NAT rule once.
func ensureBridge() error {
	if exec.Command("ip", "link", "show", Bridge).Run() != nil {
		if err := sh("ip", "link", "add", Bridge, "type", "bridge"); err != nil {
			return err
		}
		if err := sh("ip", "addr", "add", Gateway+"/16", "dev", Bridge); err != nil {
			return err
		}
	}
	if err := sh("ip", "link", "set", Bridge, "up"); err != nil {
		return err
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644); err != nil {
		return err
	}
	rules := [][]string{
		{"-t", "nat", "POSTROUTING", "-s", Subnet, "!", "-o", Bridge, "-j", "MASQUERADE"},
		{"-t", "filter", "FORWARD", "-i", Bridge, "-j", "ACCEPT"},
		{"-t", "filter", "FORWARD", "-o", Bridge, "-j", "ACCEPT"},
	}
	for _, r := range rules {
		check := append([]string{r[0], r[1], "-C"}, r[2:]...)
		if exec.Command("iptables", check...).Run() == nil {
			continue
		}
		add := append([]string{r[0], r[1], "-A"}, r[2:]...)
		if err := sh("iptables", add...); err != nil {
			return err
		}
	}
	return nil
}

// allocateIP takes the lowest free address of the subnet (a file per address, created with
// O_EXCL, so two containers never get the same one).
func allocateIP(id string) (string, error) {
	if err := os.MkdirAll(NetDir, 0o755); err != nil {
		return "", err
	}
	for i := 2; i < 65534; i++ {
		ip := fmt.Sprintf("10.88.%d.%d", i/256, i%256)
		if i%256 == 0 || i%256 == 255 {
			continue
		}
		f, err := os.OpenFile(filepath.Join(NetDir, ip), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			continue
		}
		f.WriteString(id)
		f.Close()
		return ip, nil
	}
	return "", fmt.Errorf("no free address in %s", Subnet)
}

func releaseIP(ip string) {
	if ip != "" && net.ParseIP(ip) != nil {
		os.Remove(filepath.Join(NetDir, ip))
	}
}

func vethNames(id string) (host, peer string) {
	return "hb" + id[:10], "hp" + id[:10]
}

// inNetns runs a command in the network namespace of pid.
func inNetns(pid int, args ...string) error {
	return sh("nsenter", append([]string{"--net=/proc/" + fmt.Sprint(pid) + "/ns/net", "--"}, args...)...)
}

// attach connects the container (whose init is pid) to the bridge.
func attach(m *Meta, pid int) error {
	if m.Net == "host" {
		return nil
	}
	if err := inNetns(pid, "ip", "link", "set", "lo", "up"); err != nil {
		return err
	}
	if m.Net == "none" {
		return nil
	}
	if err := ensureBridge(); err != nil {
		return err
	}
	host, peer := vethNames(m.ID)
	steps := [][]string{
		{"ip", "link", "add", host, "type", "veth", "peer", "name", peer},
		{"ip", "link", "set", peer, "netns", fmt.Sprint(pid)},
		{"ip", "link", "set", host, "master", Bridge},
		{"ip", "link", "set", host, "up"},
	}
	for _, s := range steps {
		if err := sh(s[0], s[1:]...); err != nil {
			return err
		}
	}
	inside := [][]string{
		{"ip", "link", "set", peer, "name", "eth0"},
		{"ip", "addr", "add", m.IP + "/16", "dev", "eth0"},
		{"ip", "link", "set", "eth0", "up"},
		{"ip", "route", "add", "default", "via", Gateway},
	}
	for _, s := range inside {
		if err := inNetns(pid, s...); err != nil {
			return err
		}
	}
	return nil
}

// detach removes the host end of the veth pair (the other end went with the namespace).
func detach(m *Meta) {
	if m.Net == "bridge" {
		host, _ := vethNames(m.ID)
		exec.Command("ip", "link", "del", host).Run()
	}
}

// writeNetFiles writes the hosts, hostname and resolv.conf that are bind-mounted into the
// container. Name servers on the host's loopback are not reachable from the container, so
// those are replaced by a public resolver.
func writeNetFiles(m *Meta, hostname string) error {
	var ns []string
	if b, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.Fields(l)
			if len(f) >= 2 && f[0] == "nameserver" && !strings.HasPrefix(f[1], "127.") && f[1] != "::1" {
				ns = append(ns, "nameserver "+f[1])
			}
		}
	}
	if len(ns) == 0 || m.Net == "bridge" && !reachableNS(ns) {
		ns = []string{"nameserver 1.1.1.1", "nameserver 8.8.8.8"}
	}
	files := map[string]string{
		"resolv.conf": strings.Join(ns, "\n") + "\n",
		"hostname":    hostname + "\n",
		"hosts":       fmt.Sprintf("127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost\n%s\t%s\n", firstNonEmpty(m.IP, "127.0.1.1"), hostname),
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(m.dir(), name), []byte(content), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// reachableNS: WSL's resolver address is on a link-local/virtual network that NAT from the
// bridge does not reach reliably; treat private addresses as unreachable.
func reachableNS(lines []string) bool {
	for _, l := range lines {
		ip := net.ParseIP(strings.Fields(l)[1])
		if ip != nil && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() {
			return true
		}
	}
	return false
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
