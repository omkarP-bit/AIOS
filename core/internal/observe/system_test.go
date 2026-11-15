package observe

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sysTestWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func sysTestMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

// sysTestFixture builds a miniature procfs and sysfs. The shape mirrors the
// Python fixture tree closely enough to exercise every reader.
func sysTestFixture(t *testing.T) (string, string) {
	t.Helper()
	proc := t.TempDir()
	sys := t.TempDir()

	sysTestWrite(t, filepath.Join(proc, "sys", "kernel", "hostname"), "aios-fixture\n")
	sysTestWrite(t, filepath.Join(proc, "uptime"), "1234567.89 9876543.21\n")
	sysTestWrite(t, filepath.Join(proc, "loadavg"), "0.42 0.51 0.55 2/431 12345\n")
	sysTestWrite(t, filepath.Join(proc, "stat"), `cpu  1000 200 300 80000 500 0 0 0 0 0
cpu0 500 100 150 40000 250 0 0 0 0 0
cpu1 500 100 150 40000 250 0 0 0 0 0
intr 123456 0 0
ctxt 987654
btime 1700000000
processes 321
`)
	sysTestWrite(t, filepath.Join(proc, "sys", "kernel", "pid_max"), "4194304\n")
	sysTestWrite(t, filepath.Join(proc, "sys", "fs", "file-nr"), "2048\t0\t9223372036854775807\n")
	for _, name := range []string{"1", "4312", "9999"} {
		sysTestMkdir(t, filepath.Join(proc, name))
	}
	sysTestMkdir(t, filepath.Join(proc, "notapid"))

	for _, name := range []string{"sda", "nvme0n1", "loop0"} {
		sysTestMkdir(t, filepath.Join(sys, "block", name))
	}
	for _, name := range []string{"eth0", "wlan0", "lo"} {
		sysTestMkdir(t, filepath.Join(sys, "class", "net", name))
	}
	sysTestWrite(t, filepath.Join(sys, "class", "thermal", "thermal_zone0", "temp"), "47000\n")
	sysTestWrite(t, filepath.Join(sys, "class", "thermal", "thermal_zone0", "type"), "x86_pkg_temp\n")
	sysTestWrite(t, filepath.Join(sys, "class", "thermal", "thermal_zone1", "temp"), "not-a-number\n")
	sysTestWrite(t, filepath.Join(sys, "class", "thermal", "thermal_zone1", "type"), "acpitz\n")
	sysTestWrite(t, filepath.Join(sys, "class", "thermal", "cooling_device0", "temp"), "123\n")

	return proc, sys
}

func TestReadSystemAggregates(t *testing.T) {
	proc, sys := sysTestFixture(t)
	info, err := ReadSystem(proc, sys, true, true)
	if err != nil {
		t.Fatalf("ReadSystem: %v", err)
	}

	if info.Hostname != "aios-fixture" {
		t.Errorf("hostname = %q", info.Hostname)
	}
	if info.UptimeS == nil || *info.UptimeS != 1234567.89 {
		t.Errorf("uptime = %v, want 1234567.89", info.UptimeS)
	}
	wantBoot := "2023-11-14T22:13:20+00:00"
	if info.BootTimeUTC == nil || *info.BootTimeUTC != wantBoot {
		t.Errorf("boot time = %v, want %s", info.BootTimeUTC, wantBoot)
	}
	if info.PidMax == nil || *info.PidMax != 4194304 {
		t.Errorf("pid_max = %v, want 4194304", info.PidMax)
	}
	if info.PageSize == nil || *info.PageSize != int64(os.Getpagesize()) {
		t.Errorf("page_size = %v, want %d", info.PageSize, os.Getpagesize())
	}
	if info.ProcessesRunning == nil || *info.ProcessesRunning != 2 {
		t.Errorf("processes_running = %v, want 2", info.ProcessesRunning)
	}
	if info.ThreadsTotal == nil || *info.ThreadsTotal != 431 {
		t.Errorf("threads_total = %v, want 431", info.ThreadsTotal)
	}
	if info.ProcessesTotal == nil || *info.ProcessesTotal != 3 {
		t.Errorf("processes_total = %v, want 3", info.ProcessesTotal)
	}
	if info.OpenFiles == nil || *info.OpenFiles != 2048 {
		t.Errorf("open_files = %v, want 2048", info.OpenFiles)
	}
	if info.LogicalCores == nil || *info.LogicalCores <= 0 {
		t.Errorf("logical_cores = %v, want positive", info.LogicalCores)
	}
	if got := strings.Join(info.BlockDevices, ","); got != "nvme0n1,sda" {
		t.Errorf("block devices = %q, want nvme0n1,sda", got)
	}
	if got := strings.Join(info.NetDevices, ","); got != "eth0,wlan0" {
		t.Errorf("net devices = %q, want eth0,wlan0", got)
	}
	if info.ThermalZones["thermal_zone0:x86_pkg_temp"] != 47 {
		t.Errorf("thermal zones = %v", info.ThermalZones)
	}
	if len(info.ThermalZones) != 1 {
		t.Errorf("thermal zones = %v, want only the valid zone", info.ThermalZones)
	}
	if info.ReadErrors == nil || len(info.ReadErrors) != 0 {
		t.Errorf("read_errors = %v, want empty non-nil", info.ReadErrors)
	}
	if _, err := time.Parse(time.RFC3339Nano, info.NowUTC); err != nil {
		t.Errorf("now_utc %q is not parseable: %v", info.NowUTC, err)
	}
	if info.Kernel == nil || *info.Kernel == "" || *info.Kernel == "Linux" {
		t.Errorf("kernel = %v, want the release string", info.Kernel)
	}
	if info.OSName == nil || *info.OSName == "" {
		t.Errorf("os_name = %v", info.OSName)
	}
	if info.Architecture == nil || *info.Architecture == "" {
		t.Errorf("architecture = %v", info.Architecture)
	}
}

func TestReadSystemFlags(t *testing.T) {
	proc, sys := sysTestFixture(t)
	info, err := ReadSystem(proc, sys, false, false)
	if err != nil {
		t.Fatalf("ReadSystem: %v", err)
	}
	if info.BlockDevices == nil || len(info.BlockDevices) != 0 {
		t.Errorf("block devices = %v, want empty non-nil", info.BlockDevices)
	}
	if info.ThermalZones == nil || len(info.ThermalZones) != 0 {
		t.Errorf("thermal zones = %v, want empty non-nil", info.ThermalZones)
	}
	if len(info.NetDevices) != 2 {
		t.Errorf("net devices = %v, want unaffected by disk flag", info.NetDevices)
	}
}

func TestReadSystemSparseRoot(t *testing.T) {
	proc := t.TempDir()
	sysTestWrite(t, filepath.Join(proc, "uptime"), "1234.56 100.00\n")

	info, err := ReadSystem(proc, filepath.Join(t.TempDir(), "nosys"), true, true)
	if err != nil {
		t.Fatalf("ReadSystem: %v", err)
	}
	if info.UptimeS == nil || *info.UptimeS != 1234.56 {
		t.Errorf("uptime = %v, want 1234.56", info.UptimeS)
	}
	if info.Hostname != "unknown" {
		t.Errorf("hostname = %q, want unknown", info.Hostname)
	}
	if len(info.ReadErrors) == 0 {
		t.Error("read_errors is empty, want the failed hostname read")
	}
	if info.ProcessesTotal == nil || *info.ProcessesTotal != 0 {
		t.Errorf("processes_total = %v, want 0", info.ProcessesTotal)
	}
	if info.ProcessesRunning != nil || info.ThreadsTotal != nil {
		t.Errorf("loadavg counts = %v/%v, want nil", info.ProcessesRunning, info.ThreadsTotal)
	}
	if info.PidMax != nil || info.OpenFiles != nil {
		t.Errorf("pid_max/open_files = %v/%v, want nil", info.PidMax, info.OpenFiles)
	}
	if info.BootTimeUTC != nil {
		t.Errorf("boot_time_utc = %v, want nil", info.BootTimeUTC)
	}
	if info.BlockDevices == nil || info.NetDevices == nil || info.ThermalZones == nil {
		t.Error("optional collections must be empty slices/maps, not nil")
	}
	if info.PageSize == nil || info.LogicalCores == nil {
		t.Error("page_size and logical_cores must always be populated")
	}

	raw, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{`"pid_max":null`, `"boot_time_utc":null`, `"block_devices":[]`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("JSON %s does not contain %s", raw, want)
		}
	}
}

func TestReadSystemMissingRoot(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	info, err := ReadSystem(missing, missing, true, true)
	if err != nil {
		t.Fatalf("ReadSystem: %v", err)
	}
	if info.Hostname != "unknown" {
		t.Errorf("hostname = %q, want unknown", info.Hostname)
	}
	if len(info.ReadErrors) == 0 {
		t.Error("read_errors is empty, want the failed root")
	}
	if info.ProcessesTotal != nil {
		t.Errorf("processes_total = %v, want nil for an unreadable root", info.ProcessesTotal)
	}
	if info.UptimeS != nil || info.BootTimeUTC != nil {
		t.Errorf("uptime/boot = %v/%v, want nil", info.UptimeS, info.BootTimeUTC)
	}
	if len(info.BlockDevices) != 0 || len(info.NetDevices) != 0 || len(info.ThermalZones) != 0 {
		t.Errorf("collections = %v/%v/%v, want empty", info.BlockDevices, info.NetDevices, info.ThermalZones)
	}
}

func TestSysBootTime(t *testing.T) {
	tests := []struct {
		name string
		text string
		want *string
	}{
		{
			name: "valid",
			text: "cpu 1 2 3 4\nbtime 1700000000\nprocesses 3\n",
			want: sysTestString("2023-11-14T22:13:20+00:00"),
		},
		{name: "missing", text: "cpu 1 2 3 4\n", want: nil},
		{name: "not an integer", text: "btime nope\n", want: nil},
		{name: "missing argument", text: "btime\n", want: nil},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			proc := t.TempDir()
			sysTestWrite(t, filepath.Join(proc, "stat"), test.text)
			got := sysBootTime(proc)
			if (test.want == nil) != (got == nil) || (test.want != nil && *test.want != *got) {
				t.Errorf("boot time = %v, want %v", got, test.want)
			}
		})
	}
}

func TestSysLoadAvgCounts(t *testing.T) {
	tests := []struct {
		name      string
		text      string
		wantRun   *int64
		wantTotal *int64
	}{
		{name: "valid", text: "0.42 0.51 0.55 2/431 12345\n", wantRun: sysTestInt64(2), wantTotal: sysTestInt64(431)},
		{name: "too few fields", text: "0.42 0.51 0.55\n", wantRun: nil, wantTotal: nil},
		{name: "no slash", text: "0.42 0.51 0.55 2431 12345\n", wantRun: nil, wantTotal: nil},
		{name: "not integers", text: "0.42 0.51 0.55 x/y 12345\n", wantRun: nil, wantTotal: nil},
		{name: "empty", text: "", wantRun: nil, wantTotal: nil},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			proc := t.TempDir()
			sysTestWrite(t, filepath.Join(proc, "loadavg"), test.text)
			run, total := sysLoadAvgCounts(proc)
			if (test.wantRun == nil) != (run == nil) || (test.wantRun != nil && *test.wantRun != *run) {
				t.Errorf("runnable = %v, want %v", run, test.wantRun)
			}
			if (test.wantTotal == nil) != (total == nil) || (test.wantTotal != nil && *test.wantTotal != *total) {
				t.Errorf("threads = %v, want %v", total, test.wantTotal)
			}
		})
	}
}

func TestSysResolveUnder(t *testing.T) {
	root := t.TempDir()
	sysTestWrite(t, filepath.Join(root, "4312", "stat"), "data")

	tests := []struct {
		name    string
		parts   []string
		wantErr bool
	}{
		{name: "inner path", parts: []string{"4312", "stat"}},
		{name: "current directory skipped", parts: []string{".", "4312", "stat"}},
		{name: "dotdot escape", parts: []string{"..", "..", "etc", "passwd"}, wantErr: true},
		{name: "absolute component", parts: []string{"/etc/shadow"}, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := sysResolveUnder(root, test.parts...)
			if (err != nil) != test.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}

	t.Run("symlink escape", func(t *testing.T) {
		outside := t.TempDir()
		secret := filepath.Join(outside, "secret")
		sysTestWrite(t, secret, "do not read")
		link := filepath.Join(root, "escape")
		if err := os.Symlink(secret, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if _, err := sysResolveUnder(root, "escape"); err == nil {
			t.Fatal("symlink escaping the root was accepted")
		}
	})
}

// TestReadSystemLiveSmoke only checks that the shape is populated; it asserts
// no volatile value.
func TestReadSystemLiveSmoke(t *testing.T) {
	if _, err := os.Stat("/proc/uptime"); err != nil {
		t.Skip("no live /proc/uptime on this platform")
	}
	info, err := ReadSystem("/proc", "/sys", true, true)
	if err != nil {
		t.Fatalf("ReadSystem(/proc): %v", err)
	}
	if info.Hostname == "" {
		t.Error("hostname is empty on a live host")
	}
	if info.NowUTC == "" {
		t.Error("now_utc is empty")
	}
	if info.ProcessesTotal == nil {
		t.Error("processes_total is nil on a live host")
	}
}

func sysTestString(value string) *string { return &value }

func sysTestInt64(value int64) *int64 { return &value }
