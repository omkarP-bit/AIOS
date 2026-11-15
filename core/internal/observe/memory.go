package observe

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// MemoryInfo is the memory observer's result. Every size is in kibibytes,
// matching /proc/meminfo. Derived percentages are computed here rather than
// read from a vendor field.
type MemoryInfo struct {
	TotalKB          int64            `json:"total_kb"`
	FreeKB           int64            `json:"free_kb"`
	AvailableKB      int64            `json:"available_kb"`
	BuffersKB        int64            `json:"buffers_kb"`
	CachedKB         int64            `json:"cached_kb"`
	SwapTotalKB      int64            `json:"swap_total_kb"`
	SwapFreeKB       int64            `json:"swap_free_kb"`
	UsedKB           int64            `json:"used_kb"`
	UsedPercent      float64          `json:"used_percent"`
	AvailablePercent float64          `json:"available_percent"`
	SwapUsedKB       int64            `json:"swap_used_kb"`
	SwapUsedPercent  float64          `json:"swap_used_percent"`
	FieldsKB         map[string]int64 `json:"fields_kb"`
	HugepagesTotal   *int64           `json:"hugepages_total"`
	HugepagesFree    *int64           `json:"hugepages_free"`
	HugepageSizeKB   *int64           `json:"hugepage_size_kb"`
}

// memRequired are always needed. SwapTotal/SwapFree are only required when
// swap is requested, because includeSwap=false does not compute swap figures.
var memRequired = []string{
	"MemTotal", "MemFree", "MemAvailable", "Buffers", "Cached",
}

var memSwapRequired = []string{"SwapTotal", "SwapFree"}

// memOptional are the extra meminfo keys promoted into fields_kb.
var memOptional = []string{
	"Dirty",
	"Shmem",
	"Slab",
	"SReclaimable",
	"SUnreclaim",
	"Active",
	"Inactive",
	"Active(anon)",
	"Inactive(anon)",
	"Active(file)",
	"Inactive(file)",
	"Unevictable",
	"Mlocked",
	"SwapCached",
	"VmallocTotal",
	"VmallocUsed",
	"VmallocChunk",
	"AnonPages",
	"Mapped",
	"PageTables",
	"KernelStack",
	"CommitLimit",
	"Committed_AS",
	"HugePages_Total",
	"HugePages_Free",
	"Hugepagesize",
}

// memParseInfo parses "Key:   1234 kB" lines into a kibibyte-keyed map. Any
// unit other than kB is normalised so downstream arithmetic is uniform.
func memParseInfo(text string) map[string]int64 {
	out := map[string]int64{}
	for _, line := range strings.Split(text, "\n") {
		key, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		parts := strings.Fields(rest)
		if len(parts) == 0 {
			continue
		}
		value, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			continue
		}
		unit := "kB"
		if len(parts) > 1 {
			unit = parts[1]
		}
		switch unit {
		case "kB":
			out[key] = value
		case "mB", "MB":
			out[key] = value * 1024
		default:
			out[key] = value
		}
	}
	return out
}

// memInfoModel derives the response from parsed meminfo fields. includeSwap
// controls whether swap fields are required and computed; includeFields
// controls whether the optional keys are copied into fields_kb.
func memInfoModel(fields map[string]int64, includeSwap, includeFields bool) (MemoryInfo, error) {
	required := append([]string{}, memRequired...)
	if includeSwap {
		required = append(required, memSwapRequired...)
	}
	missing := []string{}
	for _, key := range required {
		if _, ok := fields[key]; !ok {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		return MemoryInfo{}, fmt.Errorf("meminfo missing required fields: %v", missing)
	}

	total := fields["MemTotal"]
	available := fields["MemAvailable"]

	var swapTotal, swapFree int64
	if includeSwap {
		swapTotal = fields["SwapTotal"]
		swapFree = fields["SwapFree"]
	}

	used := total - available
	var usedPct float64
	if total != 0 {
		usedPct = memRound2(100.0 * float64(used) / float64(total))
	}
	var availPct float64
	if total != 0 {
		availPct = memRound2(100.0 * float64(available) / float64(total))
	}
	swapUsed := swapTotal - swapFree
	var swapPct float64
	if swapTotal != 0 {
		swapPct = memRound2(100.0 * float64(swapUsed) / float64(swapTotal))
	}

	extra := map[string]int64{}
	if includeFields {
		for _, key := range memOptional {
			if value, ok := fields[key]; ok {
				extra[key] = value
			}
		}
	}

	info := MemoryInfo{
		TotalKB:          total,
		FreeKB:           fields["MemFree"],
		AvailableKB:      available,
		BuffersKB:        fields["Buffers"],
		CachedKB:         fields["Cached"],
		SwapTotalKB:      swapTotal,
		SwapFreeKB:       swapFree,
		UsedKB:           used,
		UsedPercent:      usedPct,
		AvailablePercent: availPct,
		SwapUsedKB:       swapUsed,
		SwapUsedPercent:  swapPct,
		FieldsKB:         extra,
	}
	info.HugepagesTotal = memIntPtr(fields, "HugePages_Total")
	info.HugepagesFree = memIntPtr(fields, "HugePages_Free")
	info.HugepageSizeKB = memIntPtr(fields, "Hugepagesize")
	return info, nil
}

// ReadMemory parses procRoot/meminfo. A missing or unreadable file is an error;
// a file missing required keys is also an error, never a plausible guess.
func ReadMemory(procRoot string, includeSwap, includeFields bool) (MemoryInfo, error) {
	path, err := sysResolveUnder(procRoot, "meminfo")
	if err != nil {
		return MemoryInfo{}, err
	}
	text, err := sysReadText(path, 1<<20)
	if err != nil {
		return MemoryInfo{}, err
	}
	return memInfoModel(memParseInfo(text), includeSwap, includeFields)
}

func memIntPtr(fields map[string]int64, key string) *int64 {
	value, ok := fields[key]
	if !ok {
		return nil
	}
	return &value
}

func memRound2(value float64) float64 {
	rounded := math.Round(value*100) / 100
	if rounded == 0 {
		return 0
	}
	return rounded
}
