package observe

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func memTestWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func memTestClose(t *testing.T, got, want float64) {
	t.Helper()
	if math.Abs(got-want) > 0.011 {
		t.Errorf("got %v, want %v", got, want)
	}
}

func memTestBase() map[string]int64 {
	return map[string]int64{
		"MemTotal":     1000,
		"MemFree":      100,
		"MemAvailable": 250,
		"Buffers":      10,
		"Cached":       20,
		"SwapTotal":    100,
		"SwapFree":     40,
	}
}

func TestMemParseInfo(t *testing.T) {
	tests := []struct {
		name string
		text string
		want map[string]int64
	}{
		{
			name: "kB and mB and junk",
			text: "MemTotal: 1000 kB\nHugeTotalSize: 2 mB\nBogus: x kB\n",
			want: map[string]int64{"MemTotal": 1000, "HugeTotalSize": 2048},
		},
		{
			name: "uppercase MB",
			text: "Upper: 3 MB\n",
			want: map[string]int64{"Upper": 3072},
		},
		{
			name: "missing unit is kB",
			text: "NoUnit: 7\n",
			want: map[string]int64{"NoUnit": 7},
		},
		{
			name: "unknown unit keeps value",
			text: "Odd: 9 B\n",
			want: map[string]int64{"Odd": 9},
		},
		{
			name: "empty value skipped",
			text: "NoValue:\n",
			want: map[string]int64{},
		},
		{
			name: "line without colon skipped",
			text: "NoColon 1 kB\n",
			want: map[string]int64{},
		},
		{
			name: "non integer skipped",
			text: "Bad: 1.5 kB\nGood: 5 kB\n",
			want: map[string]int64{"Good": 5},
		},
		{
			name: "empty text",
			text: "",
			want: map[string]int64{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := memParseInfo(test.text)
			if len(got) != len(test.want) {
				t.Fatalf("got %v, want %v", got, test.want)
			}
			for key, value := range test.want {
				if got[key] != value {
					t.Errorf("%s = %d, want %d", key, got[key], value)
				}
			}
		})
	}
}

func TestMemInfoModel(t *testing.T) {
	tests := []struct {
		name          string
		fields        map[string]int64
		includeSwap   bool
		includeFields bool
		wantErr       string
		check         func(*testing.T, MemoryInfo)
	}{
		{
			name: "derives percentages and swap",
			fields: map[string]int64{
				"MemTotal": 1000, "MemFree": 100, "MemAvailable": 250,
				"Buffers": 10, "Cached": 20,
				"SwapTotal": 100, "SwapFree": 40,
				"Dirty": 5, "HugePages_Total": 0, "Hugepagesize": 2048,
			},
			includeSwap:   true,
			includeFields: true,
			check: func(t *testing.T, info MemoryInfo) {
				if info.UsedKB != 750 || info.SwapUsedKB != 60 {
					t.Errorf("used = %d swap_used = %d", info.UsedKB, info.SwapUsedKB)
				}
				memTestClose(t, info.UsedPercent, 75)
				memTestClose(t, info.AvailablePercent, 25)
				memTestClose(t, info.SwapUsedPercent, 60)
				if info.FieldsKB["Dirty"] != 5 || info.FieldsKB["Hugepagesize"] != 2048 {
					t.Errorf("fields_kb = %v", info.FieldsKB)
				}
				if _, ok := info.FieldsKB["MemTotal"]; ok {
					t.Error("MemTotal must not be copied into fields_kb")
				}
				if info.HugepagesTotal == nil || *info.HugepagesTotal != 0 {
					t.Errorf("hugepages_total = %v, want 0", info.HugepagesTotal)
				}
				if info.HugepageSizeKB == nil || *info.HugepageSizeKB != 2048 {
					t.Errorf("hugepage_size_kb = %v, want 2048", info.HugepageSizeKB)
				}
			},
		},
		{
			name:        "missing required fields",
			fields:      map[string]int64{"MemTotal": 100},
			includeSwap: false,
			wantErr:     "missing required",
		},
		{
			name:        "swap required when requested",
			fields:      memTestBaseWithoutSwap(),
			includeSwap: true,
			wantErr:     "SwapTotal",
		},
		{
			name:        "swap not required when excluded",
			fields:      memTestBaseWithoutSwap(),
			includeSwap: false,
			check: func(t *testing.T, info MemoryInfo) {
				if info.SwapTotalKB != 0 || info.SwapUsedKB != 0 || info.SwapUsedPercent != 0 {
					t.Errorf("swap = %+v, want zeros", info)
				}
			},
		},
		{
			name: "zero total does not divide by zero",
			fields: map[string]int64{
				"MemTotal": 0, "MemFree": 0, "MemAvailable": 0,
				"Buffers": 0, "Cached": 0, "SwapTotal": 0, "SwapFree": 0,
			},
			includeSwap: true,
			check: func(t *testing.T, info MemoryInfo) {
				if info.UsedPercent != 0 || info.AvailablePercent != 0 || info.SwapUsedPercent != 0 {
					t.Errorf("percentages = %+v, want zeros", info)
				}
			},
		},
		{
			name:          "fields can be omitted",
			fields:        memTestBase(),
			includeSwap:   true,
			includeFields: false,
			check: func(t *testing.T, info MemoryInfo) {
				if info.FieldsKB == nil {
					t.Fatal("fields_kb must be an empty map, not nil")
				}
				if len(info.FieldsKB) != 0 {
					t.Errorf("fields_kb = %v, want empty", info.FieldsKB)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			info, err := memInfoModel(test.fields, test.includeSwap, test.includeFields)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("error = %v, want substring %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if test.check != nil {
				test.check(t, info)
			}
		})
	}
}

func memTestBaseWithoutSwap() map[string]int64 {
	return map[string]int64{
		"MemTotal": 1000, "MemFree": 100, "MemAvailable": 250,
		"Buffers": 10, "Cached": 20,
	}
}

func TestReadMemory(t *testing.T) {
	proc := t.TempDir()
	memTestWrite(t, filepath.Join(proc, "meminfo"), `MemTotal:       16307636 kB
MemFree:         882316 kB
MemAvailable:    5510288 kB
Buffers:          212400 kB
Cached:          4210996 kB
Dirty:              1204 kB
HugePages_Total:       3
HugePages_Free:        2
Hugepagesize:       2048 kB
SwapTotal:       2097148 kB
SwapFree:        2097148 kB
`)

	info, err := ReadMemory(proc, true, true)
	if err != nil {
		t.Fatalf("ReadMemory: %v", err)
	}
	if info.TotalKB != 16_307_636 || info.AvailableKB != 5_510_288 {
		t.Errorf("total/available = %d/%d", info.TotalKB, info.AvailableKB)
	}
	if info.UsedKB != info.TotalKB-info.AvailableKB {
		t.Errorf("used = %d, want total-available", info.UsedKB)
	}
	memTestClose(t, info.UsedPercent, 66.21)
	memTestClose(t, info.AvailablePercent, 33.79)
	memTestClose(t, info.UsedPercent+info.AvailablePercent, 100)
	if info.SwapUsedKB != 0 || info.SwapUsedPercent != 0 {
		t.Errorf("swap = %d/%v, want zero", info.SwapUsedKB, info.SwapUsedPercent)
	}
	if info.FieldsKB["Dirty"] != 1204 {
		t.Errorf("fields_kb[Dirty] = %d, want 1204", info.FieldsKB["Dirty"])
	}
	if info.HugepagesTotal == nil || *info.HugepagesTotal != 3 {
		t.Errorf("hugepages_total = %v, want 3", info.HugepagesTotal)
	}
	if info.HugepagesFree == nil || *info.HugepagesFree != 2 {
		t.Errorf("hugepages_free = %v, want 2", info.HugepagesFree)
	}
}

func TestReadMemoryWithoutSwap(t *testing.T) {
	proc := t.TempDir()
	memTestWrite(t, filepath.Join(proc, "meminfo"),
		"MemTotal: 1000 kB\nMemFree: 100 kB\nMemAvailable: 250 kB\n"+
			"Buffers: 10 kB\nCached: 20 kB\n")

	info, err := ReadMemory(proc, false, false)
	if err != nil {
		t.Fatalf("ReadMemory: %v", err)
	}
	if info.SwapTotalKB != 0 || info.SwapUsedKB != 0 || info.SwapUsedPercent != 0 {
		t.Errorf("swap = %+v, want zeros", info)
	}
}

func TestReadMemoryRejectsMissingFile(t *testing.T) {
	if _, err := ReadMemory(t.TempDir(), true, true); err == nil {
		t.Fatal("expected an error for a missing meminfo")
	}
}

func TestMemoryJSONNullableFields(t *testing.T) {
	info, err := memInfoModel(memTestBase(), true, true)
	if err != nil {
		t.Fatalf("memInfoModel: %v", err)
	}
	raw, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{
		`"hugepages_total":null`,
		`"hugepages_free":null`,
		`"hugepage_size_kb":null`,
		`"fields_kb":{}`,
	} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("JSON %s does not contain %s", raw, want)
		}
	}
}
