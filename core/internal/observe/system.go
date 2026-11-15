package observe

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// SystemInfo aggregates the small /proc and /sys reads that describe the
// machine as a whole.
type SystemInfo struct {
	Hostname         string             `json:"hostname"`
	Kernel           *string            `json:"kernel"`
	KernelVersion    *string            `json:"kernel_version"`
	Architecture     *string            `json:"architecture"`
	OSName           *string            `json:"os_name"`
	UptimeS          *float64           `json:"uptime_s"`
	BootTimeUTC      *string            `json:"boot_time_utc"`
	NowUTC           string             `json:"now_utc"`
	PidMax           *int64             `json:"pid_max"`
	PageSize         *int64             `json:"page_size"`
	ProcessesRunning *int64             `json:"processes_running"`
	ProcessesTotal   *int64             `json:"processes_total"`
	ThreadsTotal     *int64             `json:"threads_total"`
	OpenFiles        *int64             `json:"open_files"`
	LogicalCores     *int64             `json:"logical_cores"`
	BlockDevices     []string           `json:"block_devices"`
	NetDevices       []string           `json:"net_devices"`
	ThermalZones     map[string]float64 `json:"thermal_zones"`
	ReadErrors       []string           `json:"read_errors"`
}

// ReadSystem reads the system-wide observers. Unreadable optional files
// degrade to null and are listed in ReadErrors; only the hostname falls back to
// a placeholder, exactly as in Python.
//
// includeDisks gates block_devices and includeThermal gates thermal_zones.
// net_devices is always collected.
func ReadSystem(procRoot, sysRoot string, includeDisks, includeThermal bool) (SystemInfo, error) {
	readErrors := []string{}
	info := SystemInfo{
		Hostname:     "unknown",
		NowUTC:       time.Now().UTC().Format("2006-01-02T15:04:05.000000+00:00"),
		BlockDevices: []string{},
		NetDevices:   []string{},
		ThermalZones: map[string]float64{},
	}

	if path, err := sysResolveUnder(procRoot, "sys/kernel/hostname"); err != nil {
		readErrors = append(readErrors, "hostname: "+sysErrName(err))
	} else if text, err := sysReadText(path, 256); err != nil {
		readErrors = append(readErrors, "hostname: "+sysErrName(err))
	} else if host := strings.TrimSpace(text); host != "" {
		info.Hostname = host
	}

	// uname describes the running kernel, not the mounted fixture tree, which
	// is why it is read from the process environment rather than from a root.
	var uts syscall.Utsname
	if err := syscall.Uname(&uts); err == nil {
		if value := sysUnameString(uts.Sysname[:]); value != "" {
			info.OSName = &value
		}
		if value := sysUnameString(uts.Release[:]); value != "" {
			info.Kernel = &value
		}
		if value := sysUnameString(uts.Version[:]); value != "" {
			info.KernelVersion = &value
		}
		if value := sysUnameString(uts.Machine[:]); value != "" {
			info.Architecture = &value
		}
	}

	info.UptimeS, _ = sysReadUptime(procRoot)
	info.BootTimeUTC = sysBootTime(procRoot)
	info.ProcessesRunning, info.ThreadsTotal = sysLoadAvgCounts(procRoot)
	info.ProcessesTotal = sysCountProcesses(procRoot)

	if path, err := sysResolveUnder(procRoot, "sys/kernel/pid_max"); err == nil {
		info.PidMax = sysReadInt(path)
	}
	pageSize := int64(os.Getpagesize())
	info.PageSize = &pageSize
	if path, err := sysResolveUnder(procRoot, "sys/fs/file-nr"); err == nil {
		info.OpenFiles = sysFirstInt(path)
	}
	logicalCores := int64(runtime.NumCPU())
	info.LogicalCores = &logicalCores

	if includeDisks {
		info.BlockDevices = sysBlockDevices(sysRoot)
	}
	info.NetDevices = sysNetDevices(sysRoot)
	if includeThermal {
		info.ThermalZones = sysThermalZones(sysRoot)
	}

	info.ReadErrors = readErrors
	return info, nil
}

// sysResolveUnder joins path components onto root and verifies the result stays
// inside it: absolute components, ".." escapes, and symlinks that leave the
// root are rejected. Nonexistent paths are allowed, since the caller decides
// whether a missing file is an error.
func sysResolveUnder(root string, parts ...string) (string, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	candidate := rootAbs
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if filepath.IsAbs(part) {
			return "", fmt.Errorf("absolute path component not allowed: %q", part)
		}
		candidate = filepath.Join(candidate, part)
	}

	realRoot := sysEvalExisting(rootAbs)
	realCandidate := sysEvalExisting(candidate)
	relative, err := filepath.Rel(realRoot, realCandidate)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%s escapes root %s", candidate, rootAbs)
	}
	return candidate, nil
}

// sysEvalExisting resolves symlinks in the longest existing prefix of path,
// leaving the nonexistent tail appended verbatim.
func sysEvalExisting(path string) string {
	current := path
	tail := []string{}
	for {
		if resolved, err := filepath.EvalSymlinks(current); err == nil {
			for i := len(tail) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, tail[i])
			}
			return resolved
		}
		parent := filepath.Dir(current)
		if parent == current {
			return path
		}
		tail = append(tail, filepath.Base(current))
		current = parent
	}
}

// sysReadText reads a small text file with a hard byte ceiling. Kernel
// pseudo-files report size zero, so the limit is enforced on bytes actually
// read.
func sysReadText(path string, maxBytes int) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(maxBytes)+1))
	if err != nil {
		return "", err
	}
	if len(data) > maxBytes {
		return "", fmt.Errorf("%s exceeds read limit of %d bytes", path, maxBytes)
	}
	return string(data), nil
}

func sysReadUptime(procRoot string) (*float64, *float64) {
	path, err := sysResolveUnder(procRoot, "uptime")
	if err != nil {
		return nil, nil
	}
	text, err := sysReadText(path, 256)
	if err != nil {
		return nil, nil
	}
	parts := strings.Fields(text)
	if len(parts) < 2 {
		return nil, nil
	}
	uptime, uptimeErr := strconv.ParseFloat(parts[0], 64)
	idle, idleErr := strconv.ParseFloat(parts[1], 64)
	if uptimeErr != nil || idleErr != nil {
		return nil, nil
	}
	uptimeValue := sysRound2(uptime)
	idleValue := sysRound2(idle)
	return &uptimeValue, &idleValue
}

func sysBootTime(procRoot string) *string {
	path, err := sysResolveUnder(procRoot, "stat")
	if err != nil {
		return nil
	}
	text, err := sysReadText(path, 1<<20)
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(line, "btime") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			return nil
		}
		seconds, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			return nil
		}
		formatted := time.Unix(seconds, 0).UTC().Format("2006-01-02T15:04:05+00:00")
		return &formatted
	}
	return nil
}

// sysLoadAvgCounts returns (runnable, threads_total) from loadavg's fourth
// field, which is runnable/total and counts threads, not processes.
func sysLoadAvgCounts(procRoot string) (*int64, *int64) {
	path, err := sysResolveUnder(procRoot, "loadavg")
	if err != nil {
		return nil, nil
	}
	text, err := sysReadText(path, 256)
	if err != nil {
		return nil, nil
	}
	parts := strings.Fields(text)
	if len(parts) < 4 || !strings.Contains(parts[3], "/") {
		return nil, nil
	}
	runnableText, totalText, found := strings.Cut(parts[3], "/")
	if !found {
		return nil, nil
	}
	runnable, runnableErr := strconv.ParseInt(runnableText, 10, 64)
	total, totalErr := strconv.ParseInt(totalText, 10, 64)
	if runnableErr != nil || totalErr != nil {
		return nil, nil
	}
	return &runnable, &total
}

func sysCountProcesses(procRoot string) *int64 {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil
	}
	var count int64
	for _, entry := range entries {
		if sysAllDigits(entry.Name()) {
			count++
		}
	}
	return &count
}

func sysBlockDevices(sysRoot string) []string {
	out := []string{}
	base, err := sysResolveUnder(sysRoot, "block")
	if err != nil {
		return out
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		return out
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, "sd") || strings.HasPrefix(name, "nvme") ||
			strings.HasPrefix(name, "vd") || strings.HasPrefix(name, "hd") ||
			strings.HasPrefix(name, "mmcblk") || strings.HasPrefix(name, "dm-") {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func sysNetDevices(sysRoot string) []string {
	out := []string{}
	base, err := sysResolveUnder(sysRoot, "class", "net")
	if err != nil {
		return out
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		return out
	}
	for _, entry := range entries {
		if name := entry.Name(); name != "lo" {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func sysThermalZones(sysRoot string) map[string]float64 {
	zones := map[string]float64{}
	base, err := sysResolveUnder(sysRoot, "class", "thermal")
	if err != nil {
		return zones
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		return zones
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "thermal_zone") {
			continue
		}
		tempPath, err := sysResolveUnder(base, name, "temp")
		if err != nil {
			continue
		}
		raw, err := sysReadText(tempPath, 64)
		if err != nil {
			continue
		}
		millidegrees, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil {
			continue
		}
		kind := "unknown"
		if typePath, err := sysResolveUnder(base, name, "type"); err == nil {
			if text, err := sysReadText(typePath, 64); err == nil {
				if trimmed := strings.TrimSpace(text); trimmed != "" {
					kind = trimmed
				}
			}
		}
		zones[name+":"+kind] = sysRound1(float64(millidegrees) / 1000.0)
	}
	return zones
}

func sysReadInt(path string) *int64 {
	text, err := sysReadText(path, 4096)
	if err != nil {
		return nil
	}
	value, err := strconv.ParseInt(strings.TrimSpace(text), 10, 64)
	if err != nil {
		return nil
	}
	return &value
}

func sysFirstInt(path string) *int64 {
	text, err := sysReadText(path, 4096)
	if err != nil {
		return nil
	}
	parts := strings.Fields(text)
	if len(parts) == 0 {
		return nil
	}
	value, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return nil
	}
	return &value
}

func sysErrName(err error) string {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "FileNotFoundError"
	case errors.Is(err, fs.ErrPermission):
		return "PermissionError"
	default:
		return "OSError"
	}
}

func sysUnameString[T ~int8 | ~uint8](chars []T) string {
	var builder strings.Builder
	for _, char := range chars {
		if char == 0 {
			break
		}
		builder.WriteByte(byte(char))
	}
	return builder.String()
}

func sysAllDigits(text string) bool {
	for _, r := range text {
		if r < '0' || r > '9' {
			return false
		}
	}
	return text != ""
}

func sysRound1(value float64) float64 {
	rounded := math.Round(value*10) / 10
	if rounded == 0 {
		return 0
	}
	return rounded
}

func sysRound2(value float64) float64 {
	rounded := math.Round(value*100) / 100
	if rounded == 0 {
		return 0
	}
	return rounded
}
