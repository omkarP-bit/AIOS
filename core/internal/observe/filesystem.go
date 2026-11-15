package observe

import (
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// FilesystemEntry is one row of the mount table.
type FilesystemEntry struct {
	Name        string   `json:"name"`
	MountPoint  string   `json:"mount_point"`
	FSType      string   `json:"fs_type"`
	Options     []string `json:"options"`
	TotalBytes  *int64   `json:"total_bytes"`
	UsedBytes   *int64   `json:"used_bytes"`
	FreeBytes   *int64   `json:"free_bytes"`
	UsedPercent *float64 `json:"used_percent"`
	InodesTotal *int64   `json:"inodes_total"`
	InodesUsed  *int64   `json:"inodes_used"`
}

// FilesystemList is the mount table result.
type FilesystemList struct {
	Mounts []FilesystemEntry `json:"mounts"`
	Total  int               `json:"total"`
}

// PathMetadata is metadata only: names, modes, and timestamps, never contents.
type PathMetadata struct {
	Path        string  `json:"path"`
	Exists      bool    `json:"exists"`
	IsDir       bool    `json:"is_dir"`
	IsFile      bool    `json:"is_file"`
	IsSymlink   bool    `json:"is_symlink"`
	SizeBytes   *int64  `json:"size_bytes"`
	Mode        *string `json:"mode"`
	OwnerUID    *int    `json:"owner_uid"`
	OwnerGID    *int    `json:"owner_gid"`
	ModifiedUTC *string `json:"modified_utc"`
	AccessedUTC *string `json:"accessed_utc"`
	Inode       *int64  `json:"inode"`
	Nlink       *int64  `json:"nlink"`
}

// fsBlockedTypes are filesystems that can serve attacker-chosen bytes from
// outside the kernel, so reads through AIOS are refused.
var fsBlockedTypes = map[string]bool{
	"fuseblk":     true,
	"fuse.sshfs":  true,
	"fuse.rclone": true,
	"nfs":         true,
	"nfs4":        true,
	"cifs":        true,
	"smbfs":       true,
	"9p":          true,
	"afs":         true,
	"ceph":        true,
	"glusterfs":   true,
	"beegfs":      true,
}

// fsSensitivePrefixes are checked after symlink resolution, so a symlink
// cannot dodge the list.
var fsSensitivePrefixes = []string{
	"/etc/shadow",
	"/etc/sudoers",
	"/etc/ssh",
	"/root",
	"/proc/kcore",
	"/dev/mem",
	"/dev/kmem",
	"/dev/port",
	"/sys/kernel/security",
	"/boot",
}

// fsRealFSTypes is the allow-list used when pseudo filesystems are excluded.
var fsRealFSTypes = []string{
	"ext2", "ext3", "ext4", "btrfs", "xfs", "f2fs", "vfat", "exfat",
	"ntfs", "ntfs3", "zfs", "overlay", "bcachefs", "reiserfs", "jfs",
}

// fsUnescape decodes /proc/mounts octal escapes such as \040 for space.
func fsUnescape(value string) string {
	var out strings.Builder
	out.Grow(len(value))
	for i := 0; i < len(value); {
		if value[i] == '\\' && i+3 < len(value) &&
			fsIsOctal(value[i+1]) && fsIsOctal(value[i+2]) && fsIsOctal(value[i+3]) {
			n, _ := strconv.ParseUint(value[i+1:i+4], 8, 8)
			out.WriteByte(byte(n))
			i += 4
			continue
		}
		out.WriteByte(value[i])
		i++
	}
	return out.String()
}

func fsIsOctal(ch byte) bool { return ch >= '0' && ch <= '7' }

// fsParseMounts parses /proc/mounts, collapsing duplicate mount points so a
// bind mount cannot present a second, friendlier view of the same path.
func fsParseMounts(text string, fstypes map[string]bool) []FilesystemEntry {
	order := []string{}
	byPoint := map[string]FilesystemEntry{}
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		if len(fstypes) > 0 && !fstypes[fields[2]] {
			continue
		}
		mountPoint := fsUnescape(fields[1])
		if _, seen := byPoint[mountPoint]; !seen {
			order = append(order, mountPoint)
		}
		byPoint[mountPoint] = FilesystemEntry{
			Name:       fields[0],
			MountPoint: mountPoint,
			FSType:     fields[2],
			Options:    strings.Split(fields[3], ","),
		}
	}

	entries := make([]FilesystemEntry, 0, len(order))
	for _, mountPoint := range order {
		entries = append(entries, byPoint[mountPoint])
	}
	for i := range entries {
		fsFillUsage(&entries[i])
	}
	return entries
}

func fsFillUsage(entry *FilesystemEntry) {
	var usage syscall.Statfs_t
	if err := syscall.Statfs(entry.MountPoint, &usage); err != nil {
		return
	}
	block := usage.Frsize
	total := int64(usage.Blocks) * block
	free := int64(usage.Bavail) * block
	used := total - int64(usage.Bfree)*block
	denominator := used + free
	percent := 0.0
	if denominator != 0 {
		percent = math.Round(100.0*float64(used)/float64(denominator)*100) / 100
	}
	entry.TotalBytes = &total
	entry.FreeBytes = &free
	entry.UsedBytes = &used
	entry.UsedPercent = &percent
	inodesTotal := int64(usage.Files)
	inodesUsed := int64(usage.Files) - int64(usage.Ffree)
	entry.InodesTotal = &inodesTotal
	entry.InodesUsed = &inodesUsed
}

// ListMounts reads <procRoot>/mounts. With includePseudo false, only real
// filesystems are reported; when true, every mount (including proc/sysfs) is.
func ListMounts(procRoot string, includePseudo bool) (FilesystemList, error) {
	text, err := procReadLimited(filepath.Join(procRoot, "mounts"), 1<<20)
	if err != nil {
		return FilesystemList{Mounts: []FilesystemEntry{}, Total: 0}, err
	}
	var allowed map[string]bool
	if !includePseudo {
		allowed = make(map[string]bool, len(fsRealFSTypes))
		for _, fstype := range fsRealFSTypes {
			allowed[fstype] = true
		}
	}
	mounts := fsParseMounts(text, allowed)
	return FilesystemList{Mounts: mounts, Total: len(mounts)}, nil
}

// StatPath stats a path, following symlinks (stat semantics, not lstat).
func StatPath(path string) PathMetadata {
	info, err := os.Stat(path)
	if err != nil {
		return PathMetadata{Path: path, Exists: false}
	}
	meta := fsBuildMetadata(path, info, true)
	if linkInfo, err := os.Lstat(path); err == nil && linkInfo.Mode()&os.ModeSymlink != 0 {
		meta.IsSymlink = true
	}
	return meta
}

// CheckReadable returns a denial reason, or "" when the path is a regular
// readable file. Sensitivity is checked on the resolved real path first.
func CheckReadable(path string) string {
	if fsIsSensitive(path) {
		return fmt.Sprintf("path matches sensitive prefix: %s", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Sprintf("path does not exist: %s", path)
		}
		return fmt.Sprintf("cannot stat %s: %v", path, err)
	}
	if info.IsDir() {
		return fmt.Sprintf("path is a directory, use filesystem.list: %s", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Sprintf("not a regular file: %s", path)
	}
	if dev, ok := fsDevice(info); ok {
		if fstype := fsFSTypeForDevice(dev); fstype != "" && fsBlockedTypes[fstype] {
			return fmt.Sprintf("filesystem type %s is not readable through AIOS: %s", fstype, path)
		}
	}
	return ""
}

func fsIsSensitive(path string) bool {
	resolved := fsRealPath(path)
	for _, prefix := range fsSensitivePrefixes {
		if resolved == prefix {
			return true
		}
		if strings.HasPrefix(resolved, strings.TrimSuffix(prefix, "/")+"/") {
			return true
		}
	}
	return false
}

// fsRealPath resolves symlinks where possible. When the path does not exist,
// it falls back to an absolute, cleaned path so a missing sensitive path is
// still denied by the sensitivity check.
func fsRealPath(path string) string {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		if abs, err := filepath.Abs(resolved); err == nil {
			return filepath.Clean(abs)
		}
		return filepath.Clean(resolved)
	}
	if abs, err := filepath.Abs(path); err == nil {
		return filepath.Clean(abs)
	}
	return path
}

func fsDevice(info os.FileInfo) (uint64, bool) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(stat.Dev), true
	}
	return 0, false
}

func fsDevMajor(dev uint64) uint64 {
	return (dev >> 8) & 0xfff
}

func fsDevMinor(dev uint64) uint64 {
	return (dev & 0xff) | ((dev >> 12) & 0xfff00)
}

// fsFSTypeForDevice finds the filesystem type for a device in
// /proc/self/mountinfo. mountinfo's third field is "major:minor" in decimal.
func fsFSTypeForDevice(dev uint64) string {
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return ""
	}
	wantMajor, wantMinor := fsDevMajor(dev), fsDevMinor(dev)
	for _, line := range strings.Split(string(raw), "\n") {
		parts := strings.SplitN(line, " - ", 2)
		if len(parts) != 2 {
			continue
		}
		left := strings.Fields(parts[0])
		if len(left) < 3 {
			continue
		}
		majorText, minorText, ok := strings.Cut(left[2], ":")
		if !ok {
			continue
		}
		major, err1 := strconv.ParseUint(majorText, 10, 64)
		minor, err2 := strconv.ParseUint(minorText, 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		if major == wantMajor && minor == wantMinor {
			right := strings.Fields(parts[1])
			if len(right) > 0 {
				return right[0]
			}
		}
	}
	return ""
}

// ListDirectory lists a directory as metadata only. Entries are lstat'ed, so
// a symlink is reported as a symlink rather than its target.
func ListDirectory(path string, maxEntries int, showHidden bool) ([]PathMetadata, error) {
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("not a directory: %s", path)
	}
	out := make([]PathMetadata, 0)
	if maxEntries <= 0 {
		return out, nil
	}

	dir, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer dir.Close()

	names, err := dir.Readdirnames(maxEntries)
	if err != nil && err != io.EOF {
		return nil, err
	}
	for _, name := range names {
		if !showHidden && strings.HasPrefix(name, ".") {
			continue
		}
		child := filepath.Join(path, name)
		childInfo, err := os.Lstat(child)
		if err != nil {
			out = append(out, PathMetadata{Path: child, Exists: false})
			continue
		}
		out = append(out, fsBuildMetadata(child, childInfo, false))
	}
	return out, nil
}

func fsBuildMetadata(path string, info os.FileInfo, includeAccess bool) PathMetadata {
	size := info.Size()
	mode := fsFileMode(info.Mode())
	modified := fsISOUTC(info.ModTime())
	meta := PathMetadata{
		Path:        path,
		Exists:      true,
		IsDir:       info.IsDir(),
		IsFile:      info.Mode().IsRegular(),
		IsSymlink:   info.Mode()&os.ModeSymlink != 0,
		SizeBytes:   &size,
		Mode:        &mode,
		ModifiedUTC: &modified,
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		uid := int(stat.Uid)
		gid := int(stat.Gid)
		inode := int64(stat.Ino)
		nlink := int64(stat.Nlink)
		meta.OwnerUID = &uid
		meta.OwnerGID = &gid
		meta.Inode = &inode
		meta.Nlink = &nlink
		if includeAccess {
			accessed := fsISOUTC(time.Unix(stat.Atim.Sec, stat.Atim.Nsec))
			meta.AccessedUTC = &accessed
		}
	}
	return meta
}

// fsISOUTC formats like Python's datetime.isoformat(): microseconds are
// included only when non-zero, and the zone is always +00:00.
func fsISOUTC(value time.Time) string {
	value = value.UTC()
	base := value.Format("2006-01-02T15:04:05")
	micros := value.Nanosecond() / 1000
	if micros != 0 {
		base += fmt.Sprintf(".%06d", micros)
	}
	return base + "+00:00"
}

// fsFileMode renders a 10-character mode like Python stat.filemode.
func fsFileMode(mode os.FileMode) string {
	kind := byte('-')
	switch {
	case mode.IsDir():
		kind = 'd'
	case mode&os.ModeSymlink != 0:
		kind = 'l'
	case mode&os.ModeCharDevice != 0:
		kind = 'c'
	case mode&os.ModeDevice != 0:
		kind = 'b'
	case mode&os.ModeNamedPipe != 0:
		kind = 'p'
	case mode&os.ModeSocket != 0:
		kind = 's'
	}
	out := []byte{kind, '-', '-', '-', '-', '-', '-', '-', '-', '-'}
	perms := []byte("rwxrwxrwx")
	perm := mode.Perm()
	for i := 0; i < 9; i++ {
		if perm&(1<<uint(8-i)) != 0 {
			out[i+1] = perms[i]
		}
	}
	if mode&os.ModeSetuid != 0 {
		if out[3] == 'x' {
			out[3] = 's'
		} else {
			out[3] = 'S'
		}
	}
	if mode&os.ModeSetgid != 0 {
		if out[6] == 'x' {
			out[6] = 's'
		} else {
			out[6] = 'S'
		}
	}
	if mode&os.ModeSticky != 0 {
		if out[9] == 'x' {
			out[9] = 't'
		} else {
			out[9] = 'T'
		}
	}
	return string(out)
}

// ReadFileBounded reads at most maxBytes and replaces invalid UTF-8. The
// caller must run CheckReadable first; the returned content is data, never
// authority.
func ReadFileBounded(path string, maxBytes int) (string, error) {
	if maxBytes < 0 {
		maxBytes = 0
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, int64(maxBytes)))
	if err != nil {
		return "", err
	}
	return strings.ToValidUTF8(string(data), "\uFFFD"), nil
}
