package injection

import (
	"fmt"

	"aios/internal/model"
	"aios/internal/plan"
)

// ScanResultFields returns the display-bound fields of a deterministic scan.
// Only the core labels are fixed here; every value comes from the filesystem
// and is untrusted, even though the scanner produced it.
func ScanResultFields(scan *model.ScanResult) []Field {
	if scan == nil {
		return nil
	}
	fields := []Field{{Name: "scan.root", Value: scan.Root}}
	for index, candidate := range scan.Candidates {
		label := fmt.Sprintf("scan.candidate[%d]", index)
		fields = append(fields,
			Field{Name: label + ".path", Value: candidate.Path},
			Field{Name: label + ".reason", Value: candidate.Reason},
		)
		for tagIndex, tag := range candidate.Tags {
			fields = append(fields, Field{
				Name:  fmt.Sprintf("%s.tag[%d]", label, tagIndex),
				Value: tag,
			})
		}
	}
	return fields
}

// PlanFields returns the display-bound fields of an engine-owned cleanup plan.
// Entry realpaths are captured file names, not instructions; they are scanned
// again at approval and execution as defence in depth.
func PlanFields(p *plan.CleanupPlan) []Field {
	if p == nil {
		return nil
	}
	fields := []Field{
		{Name: "plan.root", Value: p.Root},
		{Name: "plan.criteria.root", Value: p.Criteria.Root},
	}
	for index, extension := range p.Criteria.Extensions {
		fields = append(fields, Field{
			Name:  fmt.Sprintf("plan.criteria.extension[%d]", index),
			Value: extension,
		})
	}
	for index, entry := range p.Entries {
		fields = append(fields, Field{
			Name:  fmt.Sprintf("plan.entry[%d].realpath", index),
			Value: entry.Realpath,
		})
	}
	return fields
}
