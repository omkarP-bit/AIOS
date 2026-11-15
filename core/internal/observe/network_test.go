package observe

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func netTestWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

const netTestTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000 100 0 0 10 0
   1: 0100007F:C1AF 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 12346 1 0000 100 0 0 10 0
   2: 0200007F:0050 0200A8C0:C350 01 00012345:00006789 00:00000000 00000000  1000        0 12347 1 0000 100 0 0 10 0
   3: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12348 1 0000 100 0 0 10 0
`

const netTestTCP6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:1F91 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12350 1 0000 100 0 0 10 0
`

const netTestUDP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  447: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12360 2 0000000000000000 0
`

const netTestUnix = `Num       RefCount Protocol Flags    Type St Inode Path
ffff9a0b: 00000002 00000000 00010000 0001 01 12370 /run/user/1000/systemd/private
ffff9a0c: 00000003 00000000 00000000 0001 01 12371 @/tmp/dbus-abc
ffff9a0d: 00000002 00000000 00000000 0002 01 12372
`

func TestNetParseAddr(t *testing.T) {
	cases := []struct {
		name    string
		spec    string
		family  string
		address string
		port    int
	}{
		{"v4 loopback", "0100007F:1F90", "tcp", "127.0.0.1", 8080},
		{"v4 wildcard", "00000000:0000", "tcp", "0.0.0.0", 0},
		{"v6 loopback", "00000000000000000000000001000000:0050", "tcp6", "::1", 80},
		{"v6 wildcard", strings.Repeat("0", 32) + ":0000", "tcp6", "::", 0},
		{"bad v4", "zz", "udp", "0.0.0.0", 0},
		{"bad v6", "zz", "udp6", "::", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			address, port := netParseAddr(tc.spec, tc.family)
			if address != tc.address || port != tc.port {
				t.Fatalf("netParseAddr(%q, %q) = (%q, %d), want (%q, %d)",
					tc.spec, tc.family, address, port, tc.address, tc.port)
			}
		})
	}
}

func TestNetParseSocketTable(t *testing.T) {
	conns := netParseSocketTable(netTestTCP, "tcp")
	if len(conns) != 4 {
		t.Fatalf("got %d connections", len(conns))
	}
	listener := conns[0]
	if listener.LocalAddress != "127.0.0.1" || listener.LocalPort != 8080 {
		t.Fatalf("listener local = %s:%d", listener.LocalAddress, listener.LocalPort)
	}
	if listener.State == nil || *listener.State != "LISTEN" {
		t.Fatalf("listener state = %v", listener.State)
	}
	if listener.RemoteAddress != nil || listener.RemotePort != nil {
		t.Fatalf("wildcard remote should be null: %v/%v", listener.RemoteAddress, listener.RemotePort)
	}
	if listener.Inode == nil || *listener.Inode != 12345 || listener.UID == nil || *listener.UID != 0 {
		t.Fatalf("listener inode/uid = %v/%v", listener.Inode, listener.UID)
	}
	if listener.PIDs == nil || listener.ProcessNames == nil {
		t.Fatal("attribution lists must be non-nil")
	}
	if listener.TxQueue == nil || *listener.TxQueue != "00000000" || listener.RxQueue == nil || *listener.RxQueue != "00000000" {
		t.Fatalf("queues = %v/%v", listener.TxQueue, listener.RxQueue)
	}
	if listener.RetransmitCount == nil || *listener.RetransmitCount != "00" {
		t.Fatalf("retransmit = %v", listener.RetransmitCount)
	}

	established := conns[1]
	if established.State == nil || *established.State != "ESTABLISHED" {
		t.Fatalf("state = %v", established.State)
	}
	if established.RemoteAddress == nil || *established.RemoteAddress != "127.0.0.1" || *established.RemotePort != 8080 {
		t.Fatalf("remote = %v:%v", established.RemoteAddress, established.RemotePort)
	}

	queued := conns[2]
	if queued.TxQueue == nil || *queued.TxQueue != "00012345" || queued.RxQueue == nil || *queued.RxQueue != "00006789" {
		t.Fatalf("queues = %v/%v", queued.TxQueue, queued.RxQueue)
	}

	udp := netParseSocketTable(netTestUDP, "udp")
	if len(udp) != 1 || udp[0].State != nil {
		t.Fatalf("udp state should be nil: %+v", udp)
	}

	unknown := netParseSocketTable(`header
0: 0100007F:0001 00000000:0000 FF 00000000:00000000 00:00000000 00000000 0 0 7 1 0
not enough fields
`, "tcp")
	if len(unknown) != 1 || unknown[0].State == nil || *unknown[0].State != "FF" {
		t.Fatalf("unknown tcp state = %+v", unknown)
	}
}

func TestNetParseUnixTable(t *testing.T) {
	entries := netParseUnixTable(netTestUnix)
	if len(entries) != 3 {
		t.Fatalf("got %d entries", len(entries))
	}
	if entries[0].Path == nil || *entries[0].Path != "/run/user/1000/systemd/private" {
		t.Fatalf("path[0] = %v", entries[0].Path)
	}
	if entries[1].Path == nil || *entries[1].Path != "@/tmp/dbus-abc" {
		t.Fatalf("abstract path = %v", entries[1].Path)
	}
	if entries[2].Path != nil {
		t.Fatalf("unnamed socket path = %v", entries[2].Path)
	}
	if entries[0].Inode != "12370" || entries[0].State != "01" {
		t.Fatalf("entry[0] = %+v", entries[0])
	}
}

func netTestFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	netTestWrite(t, filepath.Join(root, "net", "tcp"), netTestTCP)
	netTestWrite(t, filepath.Join(root, "net", "tcp6"), netTestTCP6)
	netTestWrite(t, filepath.Join(root, "net", "udp"), netTestUDP)
	netTestWrite(t, filepath.Join(root, "net", "unix"), netTestUnix)
	return root
}

func TestReadNetworkAggregatesAllFamilies(t *testing.T) {
	root := netTestFixture(t)
	result, err := ReadNetwork(root, 200, true, false, false, nil)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if result.Summary.Total != 4+1+1+3 {
		t.Fatalf("total = %d", result.Summary.Total)
	}
	wantTransport := map[string]int{"tcp": 4, "tcp6": 1, "udp": 1, "unix": 3}
	for family, want := range wantTransport {
		if result.Summary.ByTransport[family] != want {
			t.Errorf("%s count = %d, want %d", family, result.Summary.ByTransport[family], want)
		}
	}
	if result.Summary.ByState["LISTEN"] == 0 {
		t.Errorf("LISTEN missing from by_state: %v", result.Summary.ByState)
	}
	if len(result.SkippedFiles) != 1 || result.SkippedFiles[0] != "udp6" {
		t.Fatalf("skipped = %v", result.SkippedFiles)
	}
	if result.Connections == nil {
		t.Fatal("connections must be non-nil")
	}
	var unixConn *NetworkConnection
	for i := range result.Connections {
		if result.Connections[i].Family == "unix" {
			unixConn = &result.Connections[i]
			break
		}
	}
	if unixConn == nil || unixConn.LocalAddress != "/run/user/1000/systemd/private" || unixConn.LocalPort != 0 {
		t.Fatalf("unix connection = %+v", unixConn)
	}
	if unixConn.State == nil || *unixConn.State != "01" {
		t.Fatalf("unix state = %v", unixConn.State)
	}
}

func TestReadNetworkStateAndListeningFilters(t *testing.T) {
	root := netTestFixture(t)

	states, err := ReadNetwork(root, 200, false, false, false, []string{"listen"})
	if err != nil {
		t.Fatalf("states: %v", err)
	}
	if len(states.Connections) != 3 {
		t.Fatalf("listeners = %d", len(states.Connections))
	}
	for _, conn := range states.Connections {
		if conn.State == nil || *conn.State != "LISTEN" {
			t.Fatalf("non-listen row: %+v", conn)
		}
	}

	listening, err := ReadNetwork(root, 200, false, false, true, nil)
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	if len(listening.Connections) != 3 {
		t.Fatalf("listening only = %d", len(listening.Connections))
	}

	filtered, err := ReadNetwork(root, 200, true, false, false, []string{"01"})
	if err != nil {
		t.Fatalf("unix state filter: %v", err)
	}
	if len(filtered.Connections) != 3 {
		t.Fatalf("unix state filter = %d", len(filtered.Connections))
	}
	for _, conn := range filtered.Connections {
		if conn.Family != "unix" {
			t.Fatalf("state filter leaked non-unix row: %+v", conn)
		}
	}
}

func TestReadNetworkLimitAndTruncation(t *testing.T) {
	root := netTestFixture(t)
	result, err := ReadNetwork(root, 2, true, false, false, nil)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(result.Connections) != 2 || result.Summary.Total != 9 || !result.Summary.Truncated {
		t.Fatalf("limit result = len %d total %d truncated %v",
			len(result.Connections), result.Summary.Total, result.Summary.Truncated)
	}
}

func TestReadNetworkMissingTablesAreSkipped(t *testing.T) {
	root := t.TempDir()
	result, err := ReadNetwork(root, 200, true, false, false, nil)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(result.SkippedFiles) != 5 {
		t.Fatalf("skipped = %v", result.SkippedFiles)
	}
	if result.Summary.Total != 0 || result.Connections == nil {
		t.Fatalf("empty result = %+v", result)
	}
	if result.Summary.ByState == nil || result.Summary.ByTransport == nil {
		t.Fatal("summary maps must be non-nil")
	}
}

func TestReadNetworkAttributesInodesToPIDs(t *testing.T) {
	root := t.TempDir()
	netTestWrite(t, filepath.Join(root, "net", "tcp"), netTestTCP)
	netTestWrite(t, filepath.Join(root, "net", "tcp6"), netTestTCP6)
	netTestWrite(t, filepath.Join(root, "net", "udp"), netTestUDP)
	netTestWrite(t, filepath.Join(root, "net", "unix"), netTestUnix)

	netTestWrite(t, filepath.Join(root, "4242", "comm"), "server\n")
	netTestWrite(t, filepath.Join(root, "5555", "comm"), "client\n")
	if err := os.MkdirAll(filepath.Join(root, "4242", "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "5555", "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[12345]", filepath.Join(root, "4242", "fd", "3")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[12346]", filepath.Join(root, "5555", "fd", "4")); err != nil {
		t.Fatal(err)
	}

	result, err := ReadNetwork(root, 200, false, true, false, nil)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if result.Summary.Attributed != 2 || result.Summary.Unattributed != result.Summary.Total-2 {
		t.Fatalf("attribution counts = %d/%d of %d",
			result.Summary.Attributed, result.Summary.Unattributed, result.Summary.Total)
	}
	byInode := map[int64]NetworkConnection{}
	for _, conn := range result.Connections {
		if conn.Inode != nil {
			byInode[*conn.Inode] = conn
		}
	}
	server := byInode[12345]
	if fmt.Sprint(server.PIDs) != "[4242]" || fmt.Sprint(server.ProcessNames) != "[server]" {
		t.Fatalf("12345 attribution = %v/%v", server.PIDs, server.ProcessNames)
	}
	client := byInode[12346]
	if fmt.Sprint(client.PIDs) != "[5555]" || fmt.Sprint(client.ProcessNames) != "[client]" {
		t.Fatalf("12346 attribution = %v/%v", client.PIDs, client.ProcessNames)
	}
	if unattributed := byInode[12348]; len(unattributed.PIDs) != 0 || len(unattributed.ProcessNames) != 0 {
		t.Fatalf("12348 unexpectedly attributed: %+v", unattributed)
	}
	if _, ok := byInode[12347]; !ok {
		t.Fatal("inode 12347 missing")
	}
}

func TestReadNetworkLiveSmoke(t *testing.T) {
	if _, err := os.Stat("/proc/net/tcp"); err != nil {
		t.Skip("live /proc/net unavailable")
	}
	result, err := ReadNetwork("/proc", 10, false, false, false, nil)
	if err != nil {
		t.Skipf("live network unavailable: %v", err)
	}
	if result.Summary.Total == 0 {
		t.Skip("live socket tables empty")
	}
	if len(result.Connections) > 10 {
		t.Fatalf("limit ignored: %d", len(result.Connections))
	}
}
