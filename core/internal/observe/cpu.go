// Package observe reads host state from procfs and sysfs.
//
// Every reader in this package is read-only: it opens files under the roots it
// is given and never writes, execs, or opens a socket. The roots exist so tests
// can point the readers at fixture trees instead of the live host.
package observe

import (
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// CPUTimes is one sample of the fields in /proc/stat's cpu lines, in USER_HZ
// ticks. It mirrors the Python “CpuTimes“ dataclass.
type CPUTimes struct {
	User    int64
	Nice    int64
	System  int64
	Idle    int64
	IOWait  int64
	IRQ     int64
	SoftIRQ int64
	Steal   int64
}

// Total is the sum of every counter.
func (t CPUTimes) Total() int64 {
	return t.User + t.Nice + t.System + t.Idle + t.IOWait + t.IRQ + t.SoftIRQ + t.Steal
}

// Busy is total minus idle and iowait.
func (t CPUTimes) Busy() int64 {
	return t.Total() - t.Idle - t.IOWait
}

// Diff returns other minus t, component by component.
func (t CPUTimes) Diff(other CPUTimes) CPUTimes {
	return CPUTimes{
		User:    other.User - t.User,
		Nice:    other.Nice - t.Nice,
		System:  other.System - t.System,
		Idle:    other.Idle - t.Idle,
		IOWait:  other.IOWait - t.IOWait,
		IRQ:     other.IRQ - t.IRQ,
		SoftIRQ: other.SoftIRQ - t.SoftIRQ,
		Steal:   other.Steal - t.Steal,
	}
}

// Percent reports utilisation between t and other, in percent. A non-positive
// total delta (identical samples, or a counter reset) yields zeros rather than
// a division by zero or an invented number.
func (t CPUTimes) Percent(other CPUTimes) map[string]float64 {
	delta := t.Diff(other)
	total := delta.Total()
	if total <= 0 {
		return map[string]float64{
			"total": 0, "user": 0, "nice": 0, "system": 0, "iowait": 0,
			"irq": 0, "softirq": 0, "steal": 0, "idle": 0,
		}
	}
	pct := 100.0 / float64(total)
	return map[string]float64{
		"total":   cpuRound2(float64(delta.Busy()) * pct),
		"user":    cpuRound2(float64(delta.User) * pct),
		"nice":    cpuRound2(float64(delta.Nice) * pct),
		"system":  cpuRound2(float64(delta.System) * pct),
		"iowait":  cpuRound2(float64(delta.IOWait) * pct),
		"irq":     cpuRound2(float64(delta.IRQ) * pct),
		"softirq": cpuRound2(float64(delta.SoftIRQ) * pct),
		"steal":   cpuRound2(float64(delta.Steal) * pct),
		"idle":    cpuRound2(float64(delta.Idle) * pct),
	}
}

// CPUCore is one logical CPU and its utilisation over the sample window.
type CPUCore struct {
	Name    string   `json:"name"`
	Percent *float64 `json:"percent"` // nil when there is no prior sample
}

// CPUFrequency is one CPU's sysfs cpufreq state. KHz is nil when the kernel
// exposes no scaling_cur_freq.
type CPUFrequency struct {
	CPU             string  `json:"cpu"`
	KHz             *int64  `json:"khz"`
	ScalingGovernor *string `json:"scaling_governor"`
}

// MHz converts kHz to MHz. sysfs reports kHz, so a division by 1000 is MHz.
func (f CPUFrequency) MHz() *float64 {
	if f.KHz == nil {
		return nil
	}
	value := float64(*f.KHz) / 1000.0
	return &value
}

// GHz converts kHz to GHz (a division by 1e6, not 1e3).
func (f CPUFrequency) GHz() *float64 {
	if f.KHz == nil {
		return nil
	}
	value := float64(*f.KHz) / 1_000_000.0
	return &value
}

// Human renders the frequency in whichever unit keeps it readable.
func (f CPUFrequency) Human() string {
	if f.KHz == nil {
		return "-"
	}
	mhz := float64(*f.KHz) / 1000.0
	if mhz >= 1000 {
		return fmt.Sprintf("%.2f GHz", mhz/1000.0)
	}
	return fmt.Sprintf("%.0f MHz", mhz)
}

// CPUInfo is the CPU observer's result.
type CPUInfo struct {
	LogicalCores   int                `json:"logical_cores"`
	LoadAverage1m  *float64           `json:"load_average_1m"`
	LoadAverage5m  *float64           `json:"load_average_5m"`
	LoadAverage15m *float64           `json:"load_average_15m"`
	Percent        map[string]float64 `json:"percent"`
	PerCore        []CPUCore          `json:"per_core"`
	Frequencies    []CPUFrequency     `json:"frequencies"`
}

// cpuCoreTimes pairs a /proc/stat cpuN label with its sample.
type cpuCoreTimes struct {
	name  string
	times CPUTimes
}

// cpuParseLine parses a "cpu0  100 0 100 700 ..." line. Missing trailing
// counters are padded with zero, matching the Python parser; any non-integer
// counter rejects the whole line.
func cpuParseLine(line string) (string, CPUTimes, bool) {
	parts := strings.Fields(line)
	if len(parts) < 5 {
		return "", CPUTimes{}, false
	}
	var values [8]int64
	limit := len(parts) - 1
	if limit > len(values) {
		limit = len(values)
	}
	for i := 0; i < limit; i++ {
		value, err := strconv.ParseInt(parts[i+1], 10, 64)
		if err != nil {
			return "", CPUTimes{}, false
		}
		values[i] = value
	}
	return parts[0], CPUTimes{
		User: values[0], Nice: values[1], System: values[2], Idle: values[3],
		IOWait: values[4], IRQ: values[5], SoftIRQ: values[6], Steal: values[7],
	}, true
}

// cpuParseStat returns the aggregate "cpu" sample plus the per-core samples,
// in file order. A missing aggregate line is an error, as in Python.
func cpuParseStat(text string) (CPUTimes, []cpuCoreTimes, error) {
	var aggregate CPUTimes
	found := false
	cores := []cpuCoreTimes{}
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(line, "cpu") {
			continue
		}
		label, times, ok := cpuParseLine(line)
		if !ok {
			continue
		}
		if label == "cpu" {
			aggregate = times
			found = true
		} else if strings.HasPrefix(label, "cpu") {
			cores = append(cores, cpuCoreTimes{name: label, times: times})
		}
	}
	if !found {
		return CPUTimes{}, nil, fmt.Errorf("no aggregate 'cpu' line in stat output")
	}
	return aggregate, cores, nil
}

// cpuProcInfo is what /proc/cpuinfo contributes. The Python observer does not
// read cpuinfo, but the port uses it as a fallback when /proc/stat carries no
// per-core lines.
type cpuProcInfo struct {
	processors int
	modelName  string
}

func cpuParseInfo(text string) cpuProcInfo {
	var info cpuProcInfo
	for _, line := range strings.Split(text, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "processor":
			info.processors++
		case "model name":
			if info.modelName == "" {
				info.modelName = strings.TrimSpace(value)
			}
		}
	}
	return info
}

func cpuReadStat(procRoot string) (CPUTimes, []cpuCoreTimes, error) {
	path, err := sysResolveUnder(procRoot, "stat")
	if err != nil {
		return CPUTimes{}, nil, err
	}
	text, err := sysReadText(path, 1<<20)
	if err != nil {
		return CPUTimes{}, nil, err
	}
	return cpuParseStat(text)
}

func cpuReadInfo(procRoot string) cpuProcInfo {
	path, err := sysResolveUnder(procRoot, "cpuinfo")
	if err != nil {
		return cpuProcInfo{}
	}
	text, err := sysReadText(path, 1<<20)
	if err != nil {
		return cpuProcInfo{}
	}
	return cpuParseInfo(text)
}

func cpuReadLoadAvg(procRoot string) (*float64, *float64, *float64) {
	path, err := sysResolveUnder(procRoot, "loadavg")
	if err != nil {
		return nil, nil, nil
	}
	text, err := sysReadText(path, 4096)
	if err != nil {
		return nil, nil, nil
	}
	parts := strings.Fields(text)
	var loads [3]*float64
	for i := 0; i < len(parts) && i < len(loads); i++ {
		value, err := strconv.ParseFloat(parts[i], 64)
		if err != nil {
			continue
		}
		v := value
		loads[i] = &v
	}
	return loads[0], loads[1], loads[2]
}

func cpuReadFrequencies(sysRoot string) []CPUFrequency {
	out := []CPUFrequency{}
	base, err := sysResolveUnder(sysRoot, "devices/system/cpu")
	if err != nil {
		return out
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		return out
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "cpu") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		suffix := strings.TrimPrefix(name, "cpu")
		if suffix == "" || !cpuAllDigits(suffix) {
			continue
		}
		var khz *int64
		if path, err := sysResolveUnder(base, name, "cpufreq", "scaling_cur_freq"); err == nil {
			if text, err := sysReadText(path, 64); err == nil {
				if value, err := strconv.ParseInt(strings.TrimSpace(text), 10, 64); err == nil {
					khz = &value
				}
			}
		}
		var governor *string
		if path, err := sysResolveUnder(base, name, "cpufreq", "scaling_governor"); err == nil {
			if text, err := sysReadText(path, 256); err == nil {
				value := strings.TrimSpace(text)
				governor = &value
			}
		}
		if khz != nil || governor != nil {
			out = append(out, CPUFrequency{CPU: name, KHz: khz, ScalingGovernor: governor})
		}
	}
	return out
}

// ReadCPU samples /proc/stat twice, separated by intervalS, and reports the
// utilisation between the samples. The first sample is only a baseline, so
// percentages are always a real delta rather than a fabricated number.
func ReadCPU(procRoot, sysRoot string, intervalS float64, includeFrequencies bool) (CPUInfo, error) {
	baseline, baselineCores, err := cpuReadStat(procRoot)
	if err != nil {
		return CPUInfo{}, err
	}
	if intervalS > 0 {
		time.Sleep(time.Duration(intervalS * float64(time.Second)))
	}
	aggregate, cores, err := cpuReadStat(procRoot)
	if err != nil {
		return CPUInfo{}, err
	}

	prior := make(map[string]CPUTimes, len(baselineCores))
	for _, core := range baselineCores {
		prior[core.name] = core.times
	}

	info := CPUInfo{
		LogicalCores: len(cores),
		Percent:      baseline.Percent(aggregate),
		PerCore:      make([]CPUCore, 0, len(cores)),
		Frequencies:  []CPUFrequency{},
	}
	info.LoadAverage1m, info.LoadAverage5m, info.LoadAverage15m = cpuReadLoadAvg(procRoot)
	if info.LogicalCores == 0 {
		// No cpuN lines in stat: fall back to cpuinfo, then to Python's floor
		// of one core.
		if count := cpuReadInfo(procRoot).processors; count > 0 {
			info.LogicalCores = count
		} else {
			info.LogicalCores = 1
		}
	}
	for _, core := range cores {
		entry := CPUCore{Name: core.name}
		if before, ok := prior[core.name]; ok {
			total := before.Percent(core.times)["total"]
			entry.Percent = &total
		}
		info.PerCore = append(info.PerCore, entry)
	}
	if includeFrequencies {
		info.Frequencies = cpuReadFrequencies(sysRoot)
	}
	return info, nil
}

func cpuRound2(value float64) float64 {
	rounded := math.Round(value*100) / 100
	if rounded == 0 {
		return 0
	}
	return rounded
}

func cpuAllDigits(text string) bool {
	for _, r := range text {
		if r < '0' || r > '9' {
			return false
		}
	}
	return text != ""
}
