package observe

import (
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// NetworkConnection is one socket table row, optionally attributed to PIDs.
type NetworkConnection struct {
	Family          string   `json:"family"`
	LocalAddress    string   `json:"local_address"`
	LocalPort       int      `json:"local_port"`
	RemoteAddress   *string  `json:"remote_address"`
	RemotePort      *int     `json:"remote_port"`
	State           *string  `json:"state"`
	Inode           *int64   `json:"inode"`
	UID             *int     `json:"uid"`
	PIDs            []int    `json:"pids"`
	ProcessNames    []string `json:"process_names"`
	TxQueue         *string  `json:"tx_queue"`
	RxQueue         *string  `json:"rx_queue"`
	RetransmitCount *string  `json:"retransmit_count"`
}

// NetworkSummary aggregates the connection table before truncation.
type NetworkSummary struct {
	Total        int            `json:"total"`
	ByState      map[string]int `json:"by_state"`
	ByTransport  map[string]int `json:"by_transport"`
	Attributed   int            `json:"attributed"`
	Unattributed int            `json:"unattributed"`
	Truncated    bool           `json:"truncated"`
}

// NetworkConnections is the network observer result.
type NetworkConnections struct {
	Connections  []NetworkConnection `json:"connections"`
	Summary      NetworkSummary      `json:"summary"`
	SkippedFiles []string            `json:"skipped_files"`
}

var netTCPStates = map[string]string{
	"01": "ESTABLISHED",
	"02": "SYN_SENT",
	"03": "SYN_RECV",
	"04": "FIN_WAIT1",
	"05": "FIN_WAIT2",
	"06": "TIME_WAIT",
	"07": "CLOSE",
	"08": "CLOSE_WAIT",
	"09": "LAST_ACK",
	"0A": "LISTEN",
	"0B": "CLOSING",
}

var netSocketFamilies = []string{"tcp", "tcp6", "udp", "udp6"}

// netParseAddr parses "0100007F:1F90" into ("127.0.0.1", 8080).
func netParseAddr(spec, family string) (string, int) {
	hexAddr, hexPort, _ := strings.Cut(spec, ":")
	port, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil {
		port = 0
	}
	if strings.HasSuffix(family, "6") {
		return netParseIPV6(hexAddr), int(port)
	}
	return netParseIPV4(hexAddr), int(port)
}

// netParseIPV4 decodes the little-endian per-word representation used by
// /proc/net/tcp.
func netParseIPV4(value string) string {
	if len(value) != 8 {
		return "0.0.0.0"
	}
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 4 {
		return "0.0.0.0"
	}
	return net.IPv4(raw[3], raw[2], raw[1], raw[0]).String()
}

// netParseIPV6 decodes four little-endian 32-bit words. Each word is
// byte-swapped individually, which is why ::1 is stored as ...01000000.
func netParseIPV6(value string) string {
	if len(value) != 32 {
		return "::"
	}
	raw := make([]byte, 0, 16)
	for i := 0; i < 32; i += 8 {
		word, err := hex.DecodeString(value[i : i+8])
		if err != nil || len(word) != 4 {
			return "::"
		}
		for j := 3; j >= 0; j-- {
			raw = append(raw, word[j])
		}
	}
	return net.IP(raw).String()
}

func netCut(value, sep string) (string, string) {
	before, after, _ := strings.Cut(value, sep)
	return before, after
}

// netParseSocketTable parses a /proc/net/{tcp,udp} table, skipping its header.
func netParseSocketTable(text, family string) []NetworkConnection {
	lines := strings.Split(text, "\n")
	out := make([]NetworkConnection, 0, len(lines))
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		localAddr, localPort := netParseAddr(fields[1], family)
		remoteAddr, remotePort := netParseAddr(fields[2], family)

		conn := NetworkConnection{
			Family:       family,
			LocalAddress: localAddr,
			LocalPort:    localPort,
			PIDs:         []int{},
			ProcessNames: []string{},
		}
		if remoteHex, _, _ := strings.Cut(fields[2], ":"); remoteHex != "00000000" {
			conn.RemoteAddress = netStringPtr(remoteAddr)
			conn.RemotePort = netIntPtr(remotePort)
		}
		if strings.HasPrefix(family, "tcp") {
			state := netTCPStates[strings.ToUpper(fields[3])]
			if state == "" {
				state = fields[3]
			}
			conn.State = netStringPtr(state)
		}
		if inode, err := strconv.ParseInt(fields[9], 10, 64); err == nil {
			conn.Inode = &inode
		}
		if uid, err := strconv.Atoi(fields[7]); err == nil {
			conn.UID = netIntPtr(uid)
		}
		tx, rx := netCut(fields[4], ":")
		conn.TxQueue = netStringPtr(tx)
		conn.RxQueue = netStringPtr(rx)
		retransmit, _ := netCut(fields[5], ":")
		conn.RetransmitCount = netStringPtr(retransmit)
		out = append(out, conn)
	}
	return out
}

type netUnixEntry struct {
	Num      string
	RefCount string
	Protocol string
	Flags    string
	Type     string
	State    string
	Inode    string
	Path     *string
}

// netParseUnixTable parses /proc/net/unix. Names are data, never interpreted.
func netParseUnixTable(text string) []netUnixEntry {
	lines := strings.Split(text, "\n")
	out := make([]netUnixEntry, 0, len(lines))
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		entry := netUnixEntry{
			Num:      strings.TrimRight(fields[0], ":"),
			RefCount: fields[1],
			Protocol: fields[2],
			Flags:    fields[3],
			Type:     fields[4],
			State:    fields[5],
			Inode:    fields[6],
		}
		if len(fields) > 7 {
			entry.Path = netStringPtr(fields[7])
		}
		out = append(out, entry)
	}
	return out
}

func netStringPtr(value string) *string { return &value }

func netIntPtr(value int) *int { return &value }

type netInodeInfo struct {
	PIDs  []int
	Names []string
}

// netBuildInodeMap scans /proc/*/fd and maps socket inode -> (pids, names).
func netBuildInodeMap(procRoot string) map[int64]*netInodeInfo {
	mapping := map[int64]*netInodeInfo{}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return mapping
	}
	pids := make([]int, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		pids = append(pids, pid)
	}
	sort.Ints(pids)

	for _, pid := range pids {
		pidDir := filepath.Join(procRoot, strconv.Itoa(pid))
		fdDir := filepath.Join(pidDir, "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
				continue
			}
			inodeText := target[len("socket:[") : len(target)-1]
			inode, err := strconv.ParseInt(inodeText, 10, 64)
			if err != nil {
				continue
			}
			info := mapping[inode]
			if info == nil {
				info = &netInodeInfo{PIDs: []int{}, Names: []string{}}
				mapping[inode] = info
			}
			if !netContainsInt(info.PIDs, pid) {
				info.PIDs = append(info.PIDs, pid)
			}
			if len(info.Names) == 0 {
				if raw, err := procReadLimited(filepath.Join(pidDir, "comm"), 256); err == nil {
					if comm := strings.TrimSpace(raw); comm != "" {
						info.Names = append(info.Names, comm)
					}
				}
			}
		}
	}
	return mapping
}

func netContainsInt(values []int, wanted int) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

// ReadNetwork parses /proc/net/{tcp,tcp6,udp,udp6,unix} and attributes socket
// inodes to PIDs through /proc/*/fd. It never resolves hostnames or opens a
// socket. Missing tables are reported in skipped_files rather than failing.
func ReadNetwork(procRoot string, limit int, includeUnix, attributePIDs, listeningOnly bool, states []string) (NetworkConnections, error) {
	connections := []NetworkConnection{}
	skipped := []string{}

	for _, family := range netSocketFamilies {
		text, err := procReadLimited(filepath.Join(procRoot, "net", family), 1<<20)
		if err != nil {
			skipped = append(skipped, family)
			continue
		}
		connections = append(connections, netParseSocketTable(text, family)...)
	}

	if includeUnix {
		text, err := procReadLimited(filepath.Join(procRoot, "net", "unix"), 1<<20)
		if err != nil {
			skipped = append(skipped, "unix")
		} else {
			for _, entry := range netParseUnixTable(text) {
				local := "unix"
				if entry.Path != nil && *entry.Path != "" {
					local = *entry.Path
				}
				state := entry.State
				connections = append(connections, NetworkConnection{
					Family:       "unix",
					LocalAddress: local,
					LocalPort:    0,
					State:        &state,
					PIDs:         []int{},
					ProcessNames: []string{},
				})
			}
		}
	}

	if len(states) > 0 {
		wanted := make(map[string]bool, len(states))
		for _, state := range states {
			wanted[strings.ToUpper(state)] = true
		}
		filtered := connections[:0]
		for _, conn := range connections {
			current := ""
			if conn.State != nil {
				current = *conn.State
			}
			if wanted[strings.ToUpper(current)] {
				filtered = append(filtered, conn)
			}
		}
		connections = filtered
	}
	if listeningOnly {
		filtered := connections[:0]
		for _, conn := range connections {
			if conn.State != nil && *conn.State == "LISTEN" {
				filtered = append(filtered, conn)
			}
		}
		connections = filtered
	}

	attributed := 0
	if attributePIDs && len(connections) > 0 {
		inodeMap := netBuildInodeMap(procRoot)
		for i := range connections {
			if connections[i].Inode == nil {
				continue
			}
			if info := inodeMap[*connections[i].Inode]; info != nil {
				connections[i].PIDs = info.PIDs
				connections[i].ProcessNames = info.Names
				attributed++
			}
		}
	}

	byState := map[string]int{}
	byTransport := map[string]int{}
	for _, conn := range connections {
		byTransport[conn.Family]++
		key := "NONE"
		if conn.State != nil {
			key = *conn.State
		}
		byState[key]++
	}

	if limit < 0 {
		limit = 0
	}
	truncated := len(connections) > limit
	summary := NetworkSummary{
		Total:        len(connections),
		ByState:      byState,
		ByTransport:  byTransport,
		Attributed:   attributed,
		Unattributed: len(connections) - attributed,
		Truncated:    truncated,
	}
	if len(connections) > limit {
		connections = connections[:limit]
	}
	return NetworkConnections{
		Connections:  connections,
		Summary:      summary,
		SkippedFiles: skipped,
	}, nil
}
