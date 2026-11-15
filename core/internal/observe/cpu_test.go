package observe

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func cpuTestWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func cpuTestInt64(value int64) *int64 { return &value }

func cpuTestFloat64(value float64) *float64 { return &value }

func cpuTestClose(t *testing.T, got, want float64) {
	t.Helper()
	if math.Abs(got-want) > 0.011 {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestCPUParseStat(t *testing.T) {
	const fixture = `cpu  1000 200 300 80000 500 10 20 30 0 0
cpu0 500 100 150 40000 250 5 10 15 0 0
cpu1 500 100 150 40000 250 5 10 15 0 0
intr 123456 0 0
ctxt 987654
btime 1700000000
`

	tests := []struct {
		name      string
		text      string
		wantErr   string
		wantCores []string
		check     func(*testing.T, CPUTimes, []cpuCoreTimes)
	}{
		{
			name:      "aggregate and cores",
			text:      fixture,
			wantCores: []string{"cpu0", "cpu1"},
			check: func(t *testing.T, aggregate CPUTimes, cores []cpuCoreTimes) {
				if aggregate.User != 1000 || aggregate.Nice != 200 || aggregate.System != 300 {
					t.Errorf("aggregate counters = %+v", aggregate)
				}
				if aggregate.Idle != 80000 || aggregate.IOWait != 500 {
					t.Errorf("aggregate idle counters = %+v", aggregate)
				}
				if aggregate.IRQ != 10 || aggregate.SoftIRQ != 20 || aggregate.Steal != 30 {
					t.Errorf("aggregate irq counters = %+v", aggregate)
				}
				if aggregate.Total() != 82060 {
					t.Errorf("total = %d, want 82060", aggregate.Total())
				}
				if aggregate.Busy() != 1560 {
					t.Errorf("busy = %d, want 1560", aggregate.Busy())
				}
				if cores[0].times.User != 500 || cores[1].times.Idle != 40000 {
					t.Errorf("core samples = %+v", cores)
				}
			},
		},
		{
			name:    "missing aggregate",
			text:    "cpu0 1 2 3 4\nintr 1\n",
			wantErr: "aggregate",
		},
		{
			name:      "short line padded with zero",
			text:      "cpu 1 2 3 4\n",
			wantCores: []string{},
			check: func(t *testing.T, aggregate CPUTimes, _ []cpuCoreTimes) {
				want := CPUTimes{User: 1, Nice: 2, System: 3, Idle: 4}
				if aggregate != want {
					t.Errorf("aggregate = %+v, want %+v", aggregate, want)
				}
			},
		},
		{
			name:      "junk core is skipped",
			text:      "cpu 1 2 3 4 5\ncpu0 1 x 3 4 5\ncpu1 6 7 8 9 10\n",
			wantCores: []string{"cpu1"},
			check: func(t *testing.T, _ CPUTimes, cores []cpuCoreTimes) {
				if cores[0].name != "cpu1" || cores[0].times.User != 6 {
					t.Errorf("cores = %+v", cores)
				}
			},
		},
		{
			name:    "too few fields",
			text:    "cpu 1 2 3\n",
			wantErr: "aggregate",
		},
		{
			name:    "non cpu lines ignored",
			text:    "intr 42\nctxt 7\n",
			wantErr: "aggregate",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			aggregate, cores, err := cpuParseStat(test.text)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("error = %v, want substring %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if test.wantCores != nil {
				names := make([]string, 0, len(cores))
				for _, core := range cores {
					names = append(names, core.name)
				}
				if strings.Join(names, ",") != strings.Join(test.wantCores, ",") {
					t.Errorf("core names = %v, want %v", names, test.wantCores)
				}
			}
			if test.check != nil {
				test.check(t, aggregate, cores)
			}
		})
	}
}

func TestCPUPercent(t *testing.T) {
	idle := CPUTimes{User: 100, Idle: 100}
	tests := []struct {
		name      string
		before    CPUTimes
		after     CPUTimes
		wantTotal float64
		wantIdle  float64
		wantUser  float64
	}{
		{
			name: "identical samples are zero", before: idle, after: idle,
			wantTotal: 0, wantIdle: 0, wantUser: 0,
		},
		{
			name:      "evenly split window",
			before:    CPUTimes{User: 100, Idle: 100},
			after:     CPUTimes{User: 200, Idle: 200},
			wantTotal: 50, wantIdle: 50, wantUser: 50,
		},
		{
			name:      "idle only",
			before:    CPUTimes{User: 100, Idle: 100},
			after:     CPUTimes{User: 100, Idle: 200},
			wantTotal: 0, wantIdle: 100, wantUser: 0,
		},
		{
			name:      "counter reset is not negative",
			before:    CPUTimes{User: 500, Idle: 500},
			after:     CPUTimes{User: 100, Idle: 100},
			wantTotal: 0, wantIdle: 0, wantUser: 0,
		},
		{
			name:   "all components",
			before: CPUTimes{},
			after: CPUTimes{
				User: 10, Nice: 10, System: 10, Idle: 60,
				IOWait: 5, IRQ: 5, SoftIRQ: 0, Steal: 10,
			},
			wantTotal: 40.91, wantIdle: 54.55, wantUser: 9.09,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			percent := test.before.Percent(test.after)
			if len(percent) != 9 {
				t.Fatalf("percent has %d keys, want 9: %v", len(percent), percent)
			}
			cpuTestClose(t, percent["total"], test.wantTotal)
			cpuTestClose(t, percent["idle"], test.wantIdle)
			cpuTestClose(t, percent["user"], test.wantUser)
			for key, value := range percent {
				if value < 0 || value > 100 {
					t.Errorf("%s = %v, outside 0..100", key, value)
				}
			}
			if test.wantIdle+test.wantTotal > 0 {
				// "total" is the busy share and idle/iowait are the rest of
				// the window, so these three always partition 100%.
				cpuTestClose(t, percent["idle"]+percent["iowait"]+percent["total"], 100)
			}
		})
	}
}

func TestCPUFrequencyUnits(t *testing.T) {
	tests := []struct {
		name  string
		khz   *int64
		mhz   *float64
		ghz   *float64
		human string
	}{
		{name: "4.4 GHz", khz: cpuTestInt64(4_400_000), mhz: cpuTestFloat64(4400), ghz: cpuTestFloat64(4.4), human: "4.40 GHz"},
		{name: "400 MHz", khz: cpuTestInt64(400_000), mhz: cpuTestFloat64(400), ghz: cpuTestFloat64(0.4), human: "400 MHz"},
		{name: "996 MHz", khz: cpuTestInt64(996_000), mhz: cpuTestFloat64(996), ghz: cpuTestFloat64(0.996), human: "996 MHz"},
		{name: "exactly 1 GHz stays GHz", khz: cpuTestInt64(1_000_000), mhz: cpuTestFloat64(1000), ghz: cpuTestFloat64(1), human: "1.00 GHz"},
		{name: "900 MHz is not 0.90 GHz", khz: cpuTestInt64(900_000), mhz: cpuTestFloat64(900), ghz: cpuTestFloat64(0.9), human: "900 MHz"},
		{name: "absent", khz: nil, mhz: nil, ghz: nil, human: "-"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			frequency := CPUFrequency{CPU: "cpu0", KHz: test.khz}
			gotMHz, gotGHz := frequency.MHz(), frequency.GHz()
			if (test.mhz == nil) != (gotMHz == nil) || (test.mhz != nil && *test.mhz != *gotMHz) {
				t.Errorf("MHz = %v, want %v", gotMHz, test.mhz)
			}
			if (test.ghz == nil) != (gotGHz == nil) || (test.ghz != nil && *test.ghz != *gotGHz) {
				t.Errorf("GHz = %v, want %v", gotGHz, test.ghz)
			}
			if got := frequency.Human(); got != test.human {
				t.Errorf("Human = %q, want %q", got, test.human)
			}
		})
	}
}

func TestCPUParseInfo(t *testing.T) {
	tests := []struct {
		name       string
		text       string
		processors int
		model      string
	}{
		{
			name:       "two processors",
			text:       "processor\t: 0\nmodel name\t: Example CPU\n\nprocessor\t: 1\nmodel name\t: Example CPU\n",
			processors: 2,
			model:      "Example CPU",
		},
		{name: "junk", text: "not cpuinfo at all\n", processors: 0, model: ""},
		{name: "empty", text: "", processors: 0, model: ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			info := cpuParseInfo(test.text)
			if info.processors != test.processors || info.modelName != test.model {
				t.Errorf("info = %+v, want processors=%d model=%q", info, test.processors, test.model)
			}
		})
	}
}

func TestReadCPU(t *testing.T) {
	proc := t.TempDir()
	sys := t.TempDir()
	cpuTestWrite(t, filepath.Join(proc, "stat"), `cpu  1000 200 300 80000 500 10 20 30 0 0
cpu0 500 100 150 40000 250 5 10 15 0 0
cpu1 500 100 150 40000 250 5 10 15 0 0
`)
	cpuTestWrite(t, filepath.Join(proc, "loadavg"), "0.42 0.51 0.55 2/431 12345\n")
	for _, cpu := range []string{"cpu0", "cpu1"} {
		base := filepath.Join(sys, "devices", "system", "cpu", cpu, "cpufreq")
		cpuTestWrite(t, filepath.Join(base, "scaling_cur_freq"), "2400000\n")
		cpuTestWrite(t, filepath.Join(base, "scaling_governor"), "powersave\n")
	}

	info, err := ReadCPU(proc, sys, 0, true)
	if err != nil {
		t.Fatalf("ReadCPU: %v", err)
	}
	if info.LogicalCores != 2 {
		t.Errorf("logical cores = %d, want 2", info.LogicalCores)
	}
	if info.Percent == nil {
		t.Fatal("percent is nil")
	}
	cpuTestClose(t, info.Percent["total"], 0)
	cpuTestClose(t, info.Percent["idle"], 0)
	if len(info.PerCore) != 2 {
		t.Fatalf("per core = %d, want 2", len(info.PerCore))
	}
	for _, core := range info.PerCore {
		if core.Percent == nil {
			t.Errorf("%s has no percent", core.Name)
		} else {
			cpuTestClose(t, *core.Percent, 0)
		}
	}
	if info.LoadAverage1m == nil || *info.LoadAverage1m != 0.42 {
		t.Errorf("load 1m = %v, want 0.42", info.LoadAverage1m)
	}
	if info.LoadAverage5m == nil || *info.LoadAverage5m != 0.51 {
		t.Errorf("load 5m = %v, want 0.51", info.LoadAverage5m)
	}
	if info.LoadAverage15m == nil || *info.LoadAverage15m != 0.55 {
		t.Errorf("load 15m = %v, want 0.55", info.LoadAverage15m)
	}
	if len(info.Frequencies) != 2 {
		t.Fatalf("frequencies = %d, want 2", len(info.Frequencies))
	}
	for _, frequency := range info.Frequencies {
		if frequency.KHz == nil || *frequency.KHz != 2_400_000 {
			t.Errorf("%s khz = %v, want 2400000", frequency.CPU, frequency.KHz)
		}
		if frequency.ScalingGovernor == nil || *frequency.ScalingGovernor != "powersave" {
			t.Errorf("%s governor = %v, want powersave", frequency.CPU, frequency.ScalingGovernor)
		}
	}

	withoutFrequencies, err := ReadCPU(proc, sys, 0, false)
	if err != nil {
		t.Fatalf("ReadCPU without frequencies: %v", err)
	}
	if withoutFrequencies.Frequencies == nil {
		t.Error("frequencies must be an empty slice, not nil")
	}
	if len(withoutFrequencies.Frequencies) != 0 {
		t.Errorf("frequencies = %v, want empty", withoutFrequencies.Frequencies)
	}
}

func TestReadCPUUsesCPUInfoFallback(t *testing.T) {
	proc := t.TempDir()
	cpuTestWrite(t, filepath.Join(proc, "stat"), "cpu 10 0 10 80 0 0 0 0\n")
	cpuTestWrite(t, filepath.Join(proc, "cpuinfo"), strings.Repeat("processor\t: 0\n", 4))

	info, err := ReadCPU(proc, t.TempDir(), 0, false)
	if err != nil {
		t.Fatalf("ReadCPU: %v", err)
	}
	if info.LogicalCores != 4 {
		t.Errorf("logical cores = %d, want cpuinfo fallback 4", info.LogicalCores)
	}
	if info.PerCore == nil || len(info.PerCore) != 0 {
		t.Errorf("per core = %v, want empty non-nil", info.PerCore)
	}
}

func TestReadCPURejectsMissingStat(t *testing.T) {
	if _, err := ReadCPU(t.TempDir(), t.TempDir(), 0, false); err == nil {
		t.Fatal("expected an error for a missing /proc/stat")
	}
}

func TestCPUJSONNullableFields(t *testing.T) {
	raw, err := json.Marshal(CPUCore{Name: "cpu0"})
	if err != nil {
		t.Fatalf("marshal core: %v", err)
	}
	if got, want := string(raw), `{"name":"cpu0","percent":null}`; got != want {
		t.Errorf("core JSON = %s, want %s", got, want)
	}

	raw, err = json.Marshal(CPUFrequency{CPU: "cpu0"})
	if err != nil {
		t.Fatalf("marshal frequency: %v", err)
	}
	if got, want := string(raw), `{"cpu":"cpu0","khz":null,"scaling_governor":null}`; got != want {
		t.Errorf("frequency JSON = %s, want %s", got, want)
	}
}

// TestReadCPULiveSmoke is deliberately shallow: a live host must produce a
// usable shape, without asserting any volatile value.
func TestReadCPULiveSmoke(t *testing.T) {
	if _, err := os.Stat("/proc/stat"); err != nil {
		t.Skip("no live /proc/stat on this platform")
	}
	info, err := ReadCPU("/proc", "/sys", 0, false)
	if err != nil {
		t.Fatalf("ReadCPU(/proc): %v", err)
	}
	if info.LogicalCores <= 0 {
		t.Errorf("logical cores = %d, want positive", info.LogicalCores)
	}
	if info.Percent == nil {
		t.Error("percent is nil on a live host")
	}
}
