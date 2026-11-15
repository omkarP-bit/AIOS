package observe

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func procTestWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// procTestStatLine builds a well-formed /proc/<pid>/stat body with 22 fields
// after comm so the parser accepts it.
func procTestStatLine(pid int, comm, state string, ppid, threads int, starttime, vsize, rss int64) string {
	values := make([]string, 22)
	for i := range values {
		values[i] = "0"
	}
	values[0] = state
	values[1] = strconv.Itoa(ppid)
	values[17] = strconv.Itoa(threads)
	values[19] = strconv.FormatInt(starttime, 10)
	values[20] = strconv.FormatInt(vsize, 10)
	values[21] = strconv.FormatInt(rss, 10)
	return fmt.Sprintf("%d (%s) %s", pid, comm, strings.Join(values, " "))
}

func procTestAddProcess(t *testing.T, root string, pid int, comm, state string, ppid, threads int, starttime, vsize, rss int64, uid int, cmdline []string) {
	t.Helper()
	base := filepath.Join(root, strconv.Itoa(pid))
	procTestWrite(t, filepath.Join(base, "stat"), procTestStatLine(pid, comm, state, ppid, threads, starttime, vsize, rss))
	status := fmt.Sprintf("Name:\t%s\nState:\t%s\nPPid:\t%d\nUid:\t%d\t%d\t%d\t%d\nGid:\t%d\t%d\t%d\t%d\nThreads:\t%d\n",
		comm, state, ppid, uid, uid, uid, uid, uid, uid, uid, uid, threads)
	procTestWrite(t, filepath.Join(base, "status"), status)
	procTestWrite(t, filepath.Join(base, "cmdline"), strings.Join(cmdline, "\x00")+"\x00")
	procTestWrite(t, filepath.Join(base, "task", strconv.Itoa(pid), "children"), "")
}

func TestProcParseStatHandlesParensAndSpaces(t *testing.T) {
	text := "7777 (evil (script)) D 4312 4312 4312 0 -1 0 100 0 0 0 10 5 0 0 20 0 1 0 8777 900000 30 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0 0 0 0 0 0 0 0"
	stat, err := procParseStat(text)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if stat.PID != 7777 || stat.Comm != "evil (script)" || stat.State != "D" || stat.PPID != 4312 {
		t.Fatalf("unexpected stat: %+v", stat)
	}
	if stat.NumThreads != 1 || stat.Utime != 10 || stat.Stime != 5 {
		t.Fatalf("numeric fields wrong: %+v", stat)
	}
	if stat.Starttime == nil || *stat.Starttime != 8777 {
		t.Fatalf("starttime = %v", stat.Starttime)
	}
	if stat.Vsize == nil || *stat.Vsize != 900000 || stat.RSS == nil || *stat.RSS != 30 {
		t.Fatalf("size fields wrong: %+v", stat)
	}
}

func TestProcParseStatRejectsJunkAndShort(t *testing.T) {
	cases := []string{
		"not a stat file",
		"12 (short) R 1 2 3",
		"abc (name) R 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21",
	}
	for _, text := range cases {
		if _, err := procParseStat(text); err == nil {
			t.Errorf("expected error for %q", text)
		}
	}
}

func TestProcParseStatusIdentity(t *testing.T) {
	text := "Name:\tfirefox\nUid:\t1000\t1000\t1000\t1000\nGid:\t100\t100\t100\t100\nThreads:\t48\n"
	status := procParseStatus(text)
	if status.UID == nil || *status.UID != 1000 {
		t.Fatalf("uid = %v", status.UID)
	}
	if status.GID == nil || *status.GID != 100 {
		t.Fatalf("gid = %v", status.GID)
	}
}

func TestReadProcessListSortingFilteringAndSkipping(t *testing.T) {
	root := t.TempDir()
	procTestWrite(t, filepath.Join(root, "uptime"), "1000.00 0.00\n")
	procTestAddProcess(t, root, 10, "alpha", "S", 1, 2, 100, 1000, 100, 1000, []string{"/bin/alpha"})
	procTestAddProcess(t, root, 20, "Beta", "R", 1, 4, 200, 5000, 1000, 0, []string{"/bin/beta"})
	procTestAddProcess(t, root, 30, "gamma", "Z", 1, 1, 300, 3000, 500, 1000, nil)
	// No stat: must be recorded in skipped, not fail the listing.
	procTestWrite(t, filepath.Join(root, "99", "status"), "Uid:\t1000\t1000\t1000\t1000\n")
	// Non-pid entries are ignored entirely.
	procTestWrite(t, filepath.Join(root, "net", "tcp"), "")

	memory, err := ReadProcessList(root, 50, "memory", nil, nil, false)
	if err != nil {
		t.Fatalf("memory sort: %v", err)
	}
	if got := []int{memory.Processes[0].PID, memory.Processes[1].PID, memory.Processes[2].PID}; fmt.Sprint(got) != "[20 30 10]" {
		t.Fatalf("memory order = %v", got)
	}
	if memory.TotalFound != 3 || memory.Returned != 3 {
		t.Fatalf("counts = %d/%d", memory.TotalFound, memory.Returned)
	}
	if len(memory.Skipped) != 1 || memory.Skipped[0]["pid"] != "99" {
		t.Fatalf("skipped = %v", memory.Skipped)
	}
	if memory.CPUPercentAvailable {
		t.Fatal("cpu percent should be unavailable on a stateless first pass")
	}
	if memory.Processes[0].Cmdline[0] != "/bin/beta" {
		t.Fatalf("cmdline not populated: %v", memory.Processes[0].Cmdline)
	}

	name, err := ReadProcessList(root, 50, "name", nil, nil, false)
	if err != nil {
		t.Fatalf("name sort: %v", err)
	}
	if got := []string{name.Processes[0].Name, name.Processes[1].Name, name.Processes[2].Name}; fmt.Sprint(got) != "[alpha Beta gamma]" {
		t.Fatalf("name order = %v", got)
	}

	pids, err := ReadProcessList(root, 50, "pid", nil, nil, false)
	if err != nil {
		t.Fatalf("pid sort: %v", err)
	}
	if got := []int{pids.Processes[0].PID, pids.Processes[1].PID, pids.Processes[2].PID}; fmt.Sprint(got) != "[10 20 30]" {
		t.Fatalf("pid order = %v", got)
	}

	filter := "bet"
	filtered, err := ReadProcessList(root, 50, "pid", &filter, nil, true)
	if err != nil {
		t.Fatalf("name filter: %v", err)
	}
	if len(filtered.Processes) != 1 || filtered.Processes[0].PID != 20 {
		t.Fatalf("name filter = %+v", filtered.Processes)
	}

	uid := 1000
	byUID, err := ReadProcessList(root, 50, "pid", nil, &uid, false)
	if err != nil {
		t.Fatalf("uid filter: %v", err)
	}
	if len(byUID.Processes) != 2 || byUID.Processes[0].PID != 10 || byUID.Processes[1].PID != 30 {
		t.Fatalf("uid filter = %+v", byUID.Processes)
	}

	limited, err := ReadProcessList(root, 2, "pid", nil, nil, false)
	if err != nil {
		t.Fatalf("limit: %v", err)
	}
	if limited.TotalFound != 3 || limited.Returned != 2 || len(limited.Processes) != 2 {
		t.Fatalf("limit counts = %d/%d", limited.TotalFound, limited.Returned)
	}
}

func TestReadProcessListRejectsBadArguments(t *testing.T) {
	root := t.TempDir()
	if _, err := ReadProcessList(root, 0, "cpu", nil, nil, false); err == nil {
		t.Fatal("limit 0 accepted")
	}
	if _, err := ReadProcessList(root, -1, "cpu", nil, nil, false); err == nil {
		t.Fatal("negative limit accepted")
	}
	if _, err := ReadProcessList(root, 5, "; rm -rf /", nil, nil, false); err == nil {
		t.Fatal("bad sort_by accepted")
	}
}

func TestReadProcessInspectExtras(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "7777")
	procTestWrite(t, filepath.Join(root, "uptime"), "100000.00 0.00\n")
	procTestWrite(t, filepath.Join(base, "stat"),
		"7777 (evil (script)) D 4312 4312 4312 0 -1 0 100 0 0 0 10 5 0 0 20 0 1 0 8777 900000 30 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0 0 0 0 0 0 0 0")
	procTestWrite(t, filepath.Join(base, "status"), "Name:\tevil (script)\nState:\tD\nPPid:\t4312\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nThreads:\t1\n")
	procTestWrite(t, filepath.Join(base, "cmdline"), "/tmp/evil.sh\x00--name\x00; rm -rf /\x00")
	procTestWrite(t, filepath.Join(base, "io"), "rchar: 123456\nwchar: 654321\nread_bytes: 4096\nwrite_bytes: 8192\n")
	procTestWrite(t, filepath.Join(base, "limits"),
		"Limit                     Soft Limit           Hard Limit           Units     \n"+
			"Max cpu time              unlimited            unlimited            seconds   \n"+
			"Max processes             62811                62811                processes \n"+
			"Max open files            1024                 524288               files     \n")
	procTestWrite(t, filepath.Join(base, "schedstat"), "123456789 1000 42\n")
	procTestWrite(t, filepath.Join(base, "cgroup"), "0::/user.slice/user-1000.slice\n")
	if err := os.MkdirAll(filepath.Join(base, "task", "7777"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(base, "task", "7778"), 0o755); err != nil {
		t.Fatal(err)
	}
	cwdTarget := t.TempDir()
	if err := os.Symlink(cwdTarget, filepath.Join(base, "cwd")); err != nil {
		t.Fatal(err)
	}
	exeTarget := filepath.Join(t.TempDir(), "evil-bin")
	procTestWrite(t, exeTarget, "#!/bin/sh\n")
	if err := os.Symlink(exeTarget, filepath.Join(base, "exe")); err != nil {
		t.Fatal(err)
	}

	info, err := ReadProcessInspect(root, 7777, true)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if info.PID != 7777 || info.PPID != 4312 || info.Name != "evil (script)" || info.State != "D" {
		t.Fatalf("identity = %+v", info)
	}
	if !strings.HasPrefix(info.StateDescription, "uninterruptible") {
		t.Fatalf("state description = %q", info.StateDescription)
	}
	if info.UID == nil || *info.UID != 1000 || info.GID == nil || *info.GID != 1000 {
		t.Fatalf("uid/gid = %v/%v", info.UID, info.GID)
	}
	if info.Threads == nil || *info.Threads != 1 {
		t.Fatalf("threads = %v", info.Threads)
	}
	if info.VsizeBytes == nil || *info.VsizeBytes != 900000 {
		t.Fatalf("vsize = %v", info.VsizeBytes)
	}
	if info.RSSBytes == nil || *info.RSSBytes != 30*4096 {
		t.Fatalf("rss = %v", info.RSSBytes)
	}
	if len(info.Cmdline) != 3 || !strings.Contains(info.Cmdline[2], "rm -rf /") {
		t.Fatalf("cmdline = %v", info.Cmdline)
	}
	if info.Executable == nil || *info.Executable != "evil-bin" {
		t.Fatalf("executable = %v", info.Executable)
	}
	if info.Cwd == nil || *info.Cwd != cwdTarget {
		t.Fatalf("cwd = %v", info.Cwd)
	}
	if info.IO["rchar"] != 123456 || info.IO["write_bytes"] != 8192 {
		t.Fatalf("io = %v", info.IO)
	}
	if info.Limits["Max processes"] != 62811 {
		t.Fatalf("soft process limit = %#v", info.Limits["Max processes"])
	}
	if info.Limits["Max cpu time"] != "unlimited" {
		t.Fatalf("cpu limit = %#v", info.Limits["Max cpu time"])
	}
	if info.Sched["time_on_cpu_ns"] != 123456789 || info.Sched["timeslices"] != 42 {
		t.Fatalf("sched = %v", info.Sched)
	}
	if info.Cgroup == nil || *info.Cgroup != "0::/user.slice/user-1000.slice" {
		t.Fatalf("cgroup = %v", info.Cgroup)
	}
	if fmt.Sprint(info.ThreadsList) != "[7777 7778]" {
		t.Fatalf("threads list = %v", info.ThreadsList)
	}
	if info.ElapsedS == nil || *info.ElapsedS != 99912.23 {
		t.Fatalf("elapsed = %v", info.ElapsedS)
	}

	lean, err := ReadProcessInspect(root, 7777, false)
	if err != nil {
		t.Fatalf("lean inspect: %v", err)
	}
	if lean.IO != nil || lean.Sched != nil || lean.Cwd != nil {
		t.Fatalf("extras leaked into lean inspect: %+v", lean)
	}
	if lean.Limits == nil || len(lean.Limits) != 0 {
		t.Fatalf("limits should be empty non-nil map: %v", lean.Limits)
	}
	if lean.Executable == nil || *lean.Executable != "/tmp/evil.sh" {
		t.Fatalf("lean executable = %v", lean.Executable)
	}
}

func TestReadProcessInspectRejectsInvalidAndZombie(t *testing.T) {
	root := t.TempDir()
	for _, pid := range []int{0, -1, -99999} {
		if _, err := ReadProcessInspect(root, pid, true); err == nil {
			t.Errorf("pid %d accepted", pid)
		}
	}
	procTestAddProcess(t, root, 8888, "<defunct>", "Z", 4312, 1, 0, 0, 0, 1000, nil)
	if _, err := ReadProcessInspect(root, 8888, true); err == nil {
		t.Fatal("zombie accepted")
	}
	if _, err := ReadProcessInspect(root, 424242, true); err == nil {
		t.Fatal("missing pid accepted")
	}
}

func TestProcessInfoJSONNullsAndEmptyLists(t *testing.T) {
	root := t.TempDir()
	line := procTestStatLine(42, "minimal", "S", 1, 0, 0, 0, 0)
	// Make rss unparsable so the nullable field stays nil, as Python does when
	// a stat field is not an integer.
	line = line[:strings.LastIndex(line, " ")] + " x"
	procTestWrite(t, filepath.Join(root, "42", "stat"), line)

	info, err := ReadProcessInspect(root, 42, false)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	raw, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"uid", "gid", "threads", "rss_bytes", "cpu_percent", "cwd", "cgroup"} {
		value, ok := decoded[key]
		if !ok {
			t.Errorf("%s missing from JSON", key)
			continue
		}
		if value != nil {
			t.Errorf("%s = %#v, want null", key, value)
		}
	}
	for _, key := range []string{"cmdline", "threads_list"} {
		value, ok := decoded[key].([]any)
		if !ok || len(value) != 0 {
			t.Errorf("%s = %#v, want []", key, decoded[key])
		}
	}
	if limits, ok := decoded["limits"].(map[string]any); !ok || len(limits) != 0 {
		t.Errorf("limits = %#v, want {}", decoded["limits"])
	}
}

func TestLiveProcessListSmoke(t *testing.T) {
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("live /proc unavailable")
	}
	result, err := ReadProcessList("/proc", 5, "pid", nil, nil, false)
	if err != nil {
		t.Skipf("live process list unavailable: %v", err)
	}
	if result.Returned == 0 || result.Returned > 5 {
		t.Fatalf("live returned = %d", result.Returned)
	}
}
