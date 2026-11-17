package observe

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"aios/internal/model"
)

// NetworkInterface is one host interface view.
type NetworkInterface struct {
	Name          string        `json:"name"`
	Index         int           `json:"index"`
	MTU           int           `json:"mtu"`
	Flags         []string      `json:"flags"`
	OperState     string        `json:"oper_state"`
	MAC           string        `json:"mac"`
	Addresses     []string      `json:"addresses"`
	LinkSpeedMbps *int          `json:"link_speed_mbps"`
	Wireless      *WirelessInfo `json:"wireless"`
	DefaultRoute  bool          `json:"default_route"`
	Gateway       *string       `json:"gateway"`
}

// WirelessInfo is the link quality procfs reports for a wireless interface.
type WirelessInfo struct {
	Status    *string `json:"status"`
	Quality   *int    `json:"quality"`
	SignalDBM *int    `json:"signal_dbm"`
	NoiseDBM  *int    `json:"noise_dbm"`
}

// NetworkStatus is the read-only link and address snapshot.
type NetworkStatus struct {
	GeneratedAt model.Timestamp    `json:"generated_at"`
	Interfaces  []NetworkInterface `json:"interfaces"`
	Default     *string            `json:"default_interface"`
	Gateway     *string            `json:"default_gateway"`
	Notes       []string           `json:"notes"`
}

type defaultRoute struct {
	iface   string
	gateway string
	metric  int
}

// ReadNetworkStatus reads interfaces, addresses, sysfs link state, the IPv4
// default route, and optionally wireless signal quality. It never runs a
// command and never changes a link.
func ReadNetworkStatus(procRoot, sysRoot string, includeWireless, includeLinkSpeed bool) (NetworkStatus, error) {
	if sysRoot == "" {
		sysRoot = "/sys"
	}
	status := NetworkStatus{
		GeneratedAt: model.Timestamp{Time: time.Now().UTC().Truncate(time.Microsecond)},
		Interfaces:  []NetworkInterface{},
		Notes: []string{
			"Link speed is the negotiated interface rate, not a measured throughput.",
			"Switching connections requires an operator-approved network.prefer plan.",
		},
	}
	routes := procDefaultRoutes(procRoot)
	defaultIface, defaultGateway := "", ""
	if len(routes) > 0 {
		defaultIface = routes[0].iface
		defaultGateway = routes[0].gateway
		status.Default = &defaultIface
		status.Gateway = &defaultGateway
	}
	wireless := parseProcWireless(procRoot)
	interfaces, err := net.Interfaces()
	if err != nil {
		return status, err
	}
	sort.Slice(interfaces, func(i, j int) bool { return interfaces[i].Index < interfaces[j].Index })
	for _, iface := range interfaces {
		entry := NetworkInterface{
			Name: iface.Name, Index: iface.Index, MTU: iface.MTU,
			Flags: interfaceFlags(iface.Flags), MAC: iface.HardwareAddr.String(),
			Addresses: []string{},
		}
		for _, addr := range interfaceAddrs(iface) {
			entry.Addresses = append(entry.Addresses, addr)
		}
		entry.OperState = readTrimmed(filepath.Join(sysRoot, "class", "net", iface.Name, "operstate"))
		if entry.OperState == "" {
			entry.OperState = "unknown"
		}
		if includeLinkSpeed {
			if raw := readTrimmed(filepath.Join(sysRoot, "class", "net", iface.Name, "speed")); raw != "" {
				if value, err := strconv.Atoi(raw); err == nil && value > 0 {
					entry.LinkSpeedMbps = &value
				}
			}
		}
		if includeWireless {
			if info, ok := wireless[iface.Name]; ok {
				entry.Wireless = &info
			}
		}
		for _, route := range routes {
			if route.iface == iface.Name {
				entry.DefaultRoute = true
				gateway := route.gateway
				entry.Gateway = &gateway
				break
			}
		}
		status.Interfaces = append(status.Interfaces, entry)
	}
	return status, nil
}

func interfaceAddrs(iface net.Interface) []string {
	raw, err := iface.Addrs()
	if err != nil {
		return []string{}
	}
	out := make([]string, 0, len(raw))
	for _, addr := range raw {
		out = append(out, addr.String())
	}
	return out
}

func interfaceFlags(flags net.Flags) []string {
	out := []string{}
	for name, flag := range map[string]net.Flags{
		"up": net.FlagUp, "broadcast": net.FlagBroadcast, "loopback": net.FlagLoopback,
		"point_to_point": net.FlagPointToPoint, "multicast": net.FlagMulticast,
	} {
		if flags&flag != 0 {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func readTrimmed(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func procDefaultRoutes(procRoot string) []defaultRoute {
	data, err := os.ReadFile(filepath.Join(procRoot, "net", "route"))
	if err != nil {
		return nil
	}
	lines := strings.Split(string(data), "\n")
	routes := []defaultRoute{}
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		if fields[1] != "00000000" {
			continue
		}
		gateway := decodeIPv4Hex(fields[2])
		metric, _ := strconv.Atoi(fields[6])
		routes = append(routes, defaultRoute{iface: fields[0], gateway: gateway, metric: metric})
	}
	sort.SliceStable(routes, func(i, j int) bool { return routes[i].metric < routes[j].metric })
	return routes
}

func decodeIPv4Hex(value string) string {
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 4 {
		return ""
	}
	// /proc/net/route stores IPv4 in host byte order.
	return fmt.Sprintf("%d.%d.%d.%d", raw[3], raw[2], raw[1], raw[0])
}

func parseProcWireless(procRoot string) map[string]WirelessInfo {
	data, err := os.ReadFile(filepath.Join(procRoot, "net", "wireless"))
	if err != nil {
		return map[string]WirelessInfo{}
	}
	out := map[string]WirelessInfo{}
	for _, line := range strings.Split(string(data), "\n") {
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		name := strings.TrimSpace(line[:idx])
		fields := strings.Fields(strings.TrimSuffix(line[idx+1:], "."))
		if name == "" || len(fields) < 4 {
			continue
		}
		info := WirelessInfo{Status: strPtr(fields[0])}
		info.Quality = parseIntPtr(fields[1])
		info.SignalDBM = parseIntPtr(fields[2])
		info.NoiseDBM = parseIntPtr(fields[3])
		out[name] = info
	}
	return out
}

func strPtr(value string) *string { return &value }

func parseIntPtr(value string) *int {
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return nil
	}
	return &parsed
}
