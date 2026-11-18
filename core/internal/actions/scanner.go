// Package actions implements the deterministic cleanup scanner and the fixed
// quarantine/restore executor. Neither interprets model output.
package actions

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"aios/internal/filesafety"
	"aios/internal/model"
	"aios/internal/protocol"
)

// ProtectedPrefixes are never scanned, whatever the model asks for.
var ProtectedPrefixes = []string{
	"/etc/shadow", "/etc/sudoers", "/etc/ssh", "/root",
	"/proc/kcore", "/dev/mem", "/dev/kmem", "/dev/port",
	"/sys/kernel/security", "/boot",
	"/proc", "/sys", "/dev", "/run",
}

var skipSuffixes = []string{".sock", ".socket", ".pid", ".lock"}

// ScanOptions bounds a scan. Zero values take the documented defaults.
type ScanOptions struct {
	MinAgeDays    int
	MinSizeBytes  int64
	Extensions    []string // canonical ".log" values; empty means all
	MaxCandidates int
	IncludeHidden bool
	ExcludeRoots  []string
	Rules         *filesafety.Rules
	Now           time.Time
	UID           *uint32
}

func (o *ScanOptions) defaults() {
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	if o.MaxCandidates == 0 {
		o.MaxCandidates = 500
	}
}

func (o *ScanOptions) rules() filesafety.Rules {
	if o.Rules != nil {
		return *o.Rules
	}
	return filesafety.Default()
}

// ScanCandidates walks root and returns bounded, deterministic candidates.
// The scanner, not the model, decides what is a candidate.
func ScanCandidates(root string, opts ScanOptions) (model.ScanResult, error) {
	opts.defaults()
	rules := opts.rules()
	if err := protocol.ValidAbsolutePath(root); err != nil {
		return model.ScanResult{}, err
	}
	cleanRoot := filepath.Clean(root)
	resolved, err := filepath.EvalSymlinks(cleanRoot)
	if err != nil {
		return model.ScanResult{}, err
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return model.ScanResult{}, err
	}
	if resolved != cleanRoot {
		return model.ScanResult{}, errors.New("symlinked scan roots are not allowed")
	}
	if rules.IsProtected(cleanRoot) || rules.IsProtected(resolved) {
		return model.ScanResult{}, errors.New("scan root is protected")
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return model.ScanResult{}, err
	}
	if !info.IsDir() {
		return model.ScanResult{}, fmt.Errorf("not a directory: %s", resolved)
	}
	rootDev, err := deviceOf(resolved)
	if err != nil {
		return model.ScanResult{}, err
	}
	owner := uint32(os.Getuid())
	if opts.UID != nil {
		owner = *opts.UID
	}
	excluded := make([]string, 0, len(opts.ExcludeRoots))
	for _, path := range opts.ExcludeRoots {
		if real, err := filepath.EvalSymlinks(path); err == nil {
			excluded = append(excluded, real)
		}
	}
	openFiles := openInodes()
	cutoff := opts.Now.AddDate(0, 0, -opts.MinAgeDays).UnixNano()

	result := model.ScanResult{
		Root: resolved, Candidates: []model.Candidate{},
		GeneratedAt: model.Timestamp{Time: opts.Now.UTC().Truncate(time.Microsecond)},
	}
	var truncated bool
	err = walkFilesFirst(resolved, opts.IncludeHidden, excluded, rules, func(path string) bool {
		if truncated {
			return false
		}
		name := filepath.Base(path)
		if !opts.IncludeHidden && strings.HasPrefix(name, ".") {
			result.Skipped++
			return true
		}
		if rules.IsProtected(path) || isExcluded(path, excluded) {
			result.Skipped++
			return true
		}
		for _, suffix := range skipSuffixes {
			if strings.HasSuffix(name, suffix) {
				result.Skipped++
				return true
			}
		}
		info, err := os.Lstat(path)
		if err != nil {
			result.Skipped++
			return true
		}
		result.ScannedFiles++
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() {
			result.Skipped++
			return true
		}
		if st.Dev != rootDev || st.Nlink > 1 || st.Uid != owner {
			result.Skipped++
			return true
		}
		if info.ModTime().UnixNano() > cutoff || info.Size() < opts.MinSizeBytes {
			result.Skipped++
			return true
		}
		if len(opts.Extensions) > 0 && !extensionAllowed(name, opts.Extensions) {
			result.Skipped++
			return true
		}
		if openFiles[[2]uint64{st.Dev, st.Ino}] {
			result.Skipped++
			return true
		}
		if len(result.Candidates) >= opts.MaxCandidates {
			truncated = true
			result.Truncated = true
			return false
		}
		reason, tags := classify(path)
		mtimeNS := info.ModTime().UnixNano()
		candidate := model.Candidate{
			CandidateID: candidateID(path, st.Dev, st.Ino, mtimeNS),
			Path:        path, Dev: st.Dev, Ino: st.Ino, SizeBytes: info.Size(),
			MtimeNS: mtimeNS, Mode: st.Mode, UID: st.Uid,
			Reason: fmt.Sprintf("%s older than %d days", reason, opts.MinAgeDays),
			Tags:   tags,
		}
		result.Candidates = append(result.Candidates, candidate)
		result.Total++
		result.TotalBytes += info.Size()
		return true
	})
	if err != nil {
		return model.ScanResult{}, err
	}
	return result, nil
}

// walkFilesFirst visits regular files before recursing into subdirectories,
// matching the Python walker's order.
func walkFilesFirst(dir string, includeHidden bool, excluded []string, rules filesafety.Rules, visit func(string) bool) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil // unreadable directory: skip, as the reference does
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	files := []string{}
	dirs := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			if !includeHidden && strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			child := filepath.Join(dir, entry.Name())
			if rules.IsProtected(child) || isExcluded(child, excluded) {
				continue
			}
			dirs = append(dirs, child)
			continue
		}
		files = append(files, filepath.Join(dir, entry.Name()))
	}
	for _, file := range files {
		if !visit(file) {
			return nil
		}
	}
	for _, child := range dirs {
		if err := walkFilesFirst(child, includeHidden, excluded, rules, visit); err != nil {
			return err
		}
	}
	return nil
}

func isExcluded(path string, excluded []string) bool {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		resolved = path
	}
	for _, root := range excluded {
		if resolved == root || strings.HasPrefix(resolved, root+"/") {
			return true
		}
	}
	return false
}

func deviceOf(path string) (uint64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("stat unavailable")
	}
	return st.Dev, nil
}

func openInodes() map[[2]uint64]bool {
	open := map[[2]uint64]bool{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return open
	}
	for _, entry := range entries {
		if !entry.IsDir() || !numeric(entry.Name()) {
			continue
		}
		fds, err := os.ReadDir(filepath.Join("/proc", entry.Name(), "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			info, err := os.Stat(filepath.Join("/proc", entry.Name(), "fd", fd.Name()))
			if err != nil {
				continue
			}
			if st, ok := info.Sys().(*syscall.Stat_t); ok {
				open[[2]uint64{st.Dev, st.Ino}] = true
			}
		}
	}
	return open
}

func numeric(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func extensionAllowed(name string, extensions []string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	for _, allowed := range extensions {
		if ext == strings.ToLower(allowed) {
			return true
		}
	}
	return false
}

func classify(path string) (string, []string) {
	lower := strings.ToLower(path)
	suffix := strings.ToLower(filepath.Ext(path))
	switch {
	case strings.Contains(lower, "/.cache/") || strings.HasSuffix(lower, "/.cache") || strings.Contains(lower, "/cache/"):
		return "cache entry", []string{"cache", "regenerable"}
	case suffix == ".log" || strings.Contains(lower, "/log/"):
		return "log file", []string{"log", "regenerable"}
	case strings.Contains(lower, "/tmp/") || suffix == ".tmp" || suffix == ".temp" || suffix == ".swp" || suffix == ".part":
		return "temporary file", []string{"temporary"}
	default:
		return "old file", []string{"old"}
	}
}

func candidateID(path string, dev, ino uint64, mtimeNS int64) string {
	material := fmt.Sprintf("%s\x00%d\x00%d\x00%d", path, dev, ino, mtimeNS)
	sum := sha256.Sum256([]byte(material))
	return "c-" + hex.EncodeToString(sum[:])[:16]
}
