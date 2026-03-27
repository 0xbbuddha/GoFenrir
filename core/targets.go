package core

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// ParseTargets expands a target string into a list of hosts.
// Accepts: single IP/hostname, CIDR range (e.g. 192.168.1.0/24),
// @file reference, or a path to an existing file.
func ParseTargets(target string) ([]string, error) {
	if strings.HasPrefix(target, "@") {
		return readLines(target[1:])
	}
	if info, err := os.Stat(target); err == nil && !info.IsDir() {
		return readLines(target)
	}
	if strings.Contains(target, "/") {
		return expandCIDR(target)
	}
	return []string{target}, nil
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open file %q: %w", path, err)
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines, scanner.Err()
}

func expandCIDR(cidr string) ([]string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}

	var hosts []string
	for ip := cloneIP(ipnet.IP); ipnet.Contains(ip); incIP(ip) {
		hosts = append(hosts, ip.String())
	}
	// Remove network and broadcast addresses for subnets larger than /31
	if len(hosts) > 2 {
		hosts = hosts[1 : len(hosts)-1]
	}
	return hosts, nil
}

func cloneIP(ip net.IP) net.IP {
	clone := make(net.IP, len(ip))
	copy(clone, ip)
	return clone
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}
