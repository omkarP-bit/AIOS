package observe

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fsTestWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestFsUnescape(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/plain/path", "/plain/path"},
		{`/a\040b\011c`, "/a b\tc"},
		{"", ""},
		{`/a\134b`, `/a\b`},
		{`/not\09`, `/not\09`},
		{`/trailing\04`, `/trailing\04`},
	}
	for _, tc := range cases {
		if got := fsUnescape(tc.in); got != tc.want {
			t.Errorf("fsUnescape(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestFsParseMountsUnescapesAndCollapsesDuplicates(t *testing.T) {
	text := "/dev/sda1 /data ext4 rw 0 0\n" +
		"/dev/sdb1 /data btrfs ro 0 0\n" +
		"/dev/sdc1 /mnt/usb\\040backup ext4 rw,noatime 0 0\n"
	entries := fsParseMounts(text, nil)
	if len(entries) != 2 {
		t.Fatalf("got %d entries: %+v", len(entries), entries)
	}
	if entries[0].MountPoint != "/data" || entries[0].FSType != "btrfs" {
		t.Fatalf("duplicate did not keep last value: %+v", entries[0])
	}
	if fmt.Sprint(entries[0].Options) != "[ro]" {
		t.Fatalf("options = %v", entries[0].Options)
	}
	if entries[1].MountPoint != "/mnt/usb backup" {
		t.Fatalf("escape not decoded: %q", entries[1].MountPoint)
	}
	if fmt.Sprint(entries[1].Options) != "[rw noatime]" {
		t.Fatalf("options = %v", entries[1].Options)
	}

	filtered := fsParseMounts(text, map[string]bool{"ext4": true})
	if len(filtered) != 2 || filtered[0].MountPoint != "/data" || filtered[0].FSType != "ext4" ||
		filtered[1].MountPoint != "/mnt/usb backup" {
		t.Fatalf("fstype filter = %+v", filtered)
	}
}

func TestListMountsFiltersPseudoFilesystems(t *testing.T) {
	root := t.TempDir()
	rootMount := filepath.Join(root, "rootfs")
	procMount := filepath.Join(root, "procfs")
	spaceMount := filepath.Join(root, "usb backup")
	for _, dir := range []string{rootMount, procMount, spaceMount} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mounts := fmt.Sprintf(
		"/dev/sda1 %s ext4 rw 0 0\nproc %s proc rw 0 0\n/dev/sdb1 %s ext4 rw 0 0\n",
		rootMount, procMount, strings.ReplaceAll(spaceMount, " ", `\040`))
	fsTestWrite(t, filepath.Join(root, "mounts"), []byte(mounts))

	real, err := ListMounts(root, false)
	if err != nil {
		t.Fatalf("list mounts: %v", err)
	}
	if real.Total != 2 || len(real.Mounts) != 2 {
		t.Fatalf("real mounts = %+v", real)
	}
	for _, mount := range real.Mounts {
		if mount.FSType != "ext4" {
			t.Fatalf("pseudo mount leaked: %+v", mount)
		}
		if mount.TotalBytes == nil || mount.FreeBytes == nil || mount.UsedBytes == nil ||
			mount.UsedPercent == nil || mount.InodesTotal == nil || mount.InodesUsed == nil {
			t.Fatalf("usage not filled for %s: %+v", mount.MountPoint, mount)
		}
	}
	if real.Mounts[1].MountPoint != spaceMount {
		t.Fatalf("escaped mount point = %q", real.Mounts[1].MountPoint)
	}

	all, err := ListMounts(root, true)
	if err != nil {
		t.Fatalf("list all mounts: %v", err)
	}
	if all.Total != 3 {
		t.Fatalf("all mounts total = %d", all.Total)
	}
	foundProc := false
	for _, mount := range all.Mounts {
		if mount.FSType == "proc" {
			foundProc = true
		}
	}
	if !foundProc {
		t.Fatalf("pseudo mount missing with includePseudo: %+v", all.Mounts)
	}
}

func TestStatPathFollowsSymlinksAndReportsMetadata(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "report.txt")
	fsTestWrite(t, target, []byte("0123456789"))

	meta := StatPath(target)
	if !meta.Exists || !meta.IsFile || meta.IsDir || meta.IsSymlink {
		t.Fatalf("metadata flags = %+v", meta)
	}
	if meta.SizeBytes == nil || *meta.SizeBytes != 10 {
		t.Fatalf("size = %v", meta.SizeBytes)
	}
	if meta.Mode == nil || len(*meta.Mode) != 10 || (*meta.Mode)[0] != '-' {
		t.Fatalf("mode = %v", meta.Mode)
	}
	if meta.OwnerUID == nil || meta.OwnerGID == nil {
		t.Fatalf("owner = %v/%v", meta.OwnerUID, meta.OwnerGID)
	}
	if meta.ModifiedUTC == nil || !strings.HasSuffix(*meta.ModifiedUTC, "+00:00") {
		t.Fatalf("mtime = %v", meta.ModifiedUTC)
	}
	if meta.AccessedUTC == nil || !strings.HasSuffix(*meta.AccessedUTC, "+00:00") {
		t.Fatalf("atime = %v", meta.AccessedUTC)
	}
	if meta.Inode == nil || meta.Nlink == nil {
		t.Fatalf("inode/nlink = %v/%v", meta.Inode, meta.Nlink)
	}

	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink("report.txt", link); err != nil {
		t.Fatal(err)
	}
	linkMeta := StatPath(link)
	if !linkMeta.Exists || !linkMeta.IsFile || !linkMeta.IsSymlink {
		t.Fatalf("symlink stat did not follow: %+v", linkMeta)
	}
	if linkMeta.SizeBytes == nil || *linkMeta.SizeBytes != 10 {
		t.Fatalf("symlink target size = %v", linkMeta.SizeBytes)
	}

	dirMeta := StatPath(dir)
	if !dirMeta.Exists || !dirMeta.IsDir || dirMeta.IsFile {
		t.Fatalf("directory metadata = %+v", dirMeta)
	}

	missing := StatPath(filepath.Join(dir, "nope"))
	if missing.Exists || missing.Path != filepath.Join(dir, "nope") {
		t.Fatalf("missing metadata = %+v", missing)
	}
	if missing.SizeBytes != nil || missing.Mode != nil || missing.ModifiedUTC != nil {
		t.Fatalf("missing metadata should be null-filled: %+v", missing)
	}
}

func TestListDirectoryUsesLstatAndFiltersHidden(t *testing.T) {
	dir := t.TempDir()
	fsTestWrite(t, filepath.Join(dir, "a.txt"), []byte("abcdef"))
	fsTestWrite(t, filepath.Join(dir, ".hidden"), []byte("secret"))
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a.txt", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing-target", filepath.Join(dir, "broken")); err != nil {
		t.Fatal(err)
	}

	visible, err := ListDirectory(dir, 100, false)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(visible) != 4 {
		t.Fatalf("visible entries = %d: %+v", len(visible), visible)
	}
	byName := map[string]PathMetadata{}
	for _, entry := range visible {
		byName[filepath.Base(entry.Path)] = entry
		if entry.AccessedUTC != nil {
			t.Fatalf("list entries must not carry atime: %+v", entry)
		}
	}
	if _, ok := byName[".hidden"]; ok {
		t.Fatal("hidden entry leaked")
	}
	if file, ok := byName["a.txt"]; !ok || !file.IsFile || file.SizeBytes == nil || *file.SizeBytes != 6 {
		t.Fatalf("a.txt = %+v", file)
	}
	if sub, ok := byName["sub"]; !ok || !sub.IsDir || sub.IsFile {
		t.Fatalf("sub = %+v", sub)
	}
	if link, ok := byName["link"]; !ok || !link.IsSymlink || link.IsFile || link.IsDir {
		t.Fatalf("link lstat semantics wrong: %+v", link)
	}
	if broken, ok := byName["broken"]; !ok || !broken.IsSymlink || !broken.Exists {
		t.Fatalf("broken symlink = %+v", broken)
	}

	hidden, err := ListDirectory(dir, 100, true)
	if err != nil {
		t.Fatalf("list hidden: %v", err)
	}
	if len(hidden) != 5 {
		t.Fatalf("hidden included entries = %d", len(hidden))
	}

	limited, err := ListDirectory(dir, 2, true)
	if err != nil {
		t.Fatalf("list limited: %v", err)
	}
	if len(limited) > 2 {
		t.Fatalf("max entries ignored: %d", len(limited))
	}

	empty, err := ListDirectory(dir, 0, true)
	if err != nil || len(empty) != 0 {
		t.Fatalf("zero max entries = %v, %v", empty, err)
	}

	file := filepath.Join(dir, "a.txt")
	if _, err := ListDirectory(file, 10, false); err == nil {
		t.Fatal("file accepted as directory")
	}
	if _, err := ListDirectory(filepath.Join(dir, "missing"), 10, false); err == nil {
		t.Fatal("missing directory accepted")
	}
}

func TestCheckReadableDenialsAndAllow(t *testing.T) {
	for _, path := range []string{"/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config", "/dev/mem", "/root/.ssh/id_rsa"} {
		if reason := CheckReadable(path); reason == "" {
			t.Errorf("sensitive path %s allowed", path)
		}
	}

	dir := t.TempDir()
	if reason := CheckReadable(dir); reason == "" {
		t.Fatal("directory allowed")
	}
	if reason := CheckReadable(filepath.Join(dir, "missing.txt")); reason == "" {
		t.Fatal("missing path allowed")
	}
	if reason := CheckReadable("/dev/null"); reason == "" {
		t.Fatal("device node allowed")
	}

	ordinary := filepath.Join(dir, "report.txt")
	fsTestWrite(t, ordinary, []byte("hello"))
	if reason := CheckReadable(ordinary); reason != "" {
		t.Fatalf("ordinary file denied: %s", reason)
	}

	if err := os.Symlink("/etc/shadow", filepath.Join(dir, "shadow-link")); err == nil {
		if reason := CheckReadable(filepath.Join(dir, "shadow-link")); reason == "" {
			t.Fatal("symlink to sensitive path allowed")
		}
	}
}

func TestReadFileBoundedTruncatesAndReplacesInvalidUTF8(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bytes.bin")
	fsTestWrite(t, path, []byte("hello\xffworld"))

	short, err := ReadFileBounded(path, 5)
	if err != nil {
		t.Fatalf("read short: %v", err)
	}
	if short != "hello" {
		t.Fatalf("short = %q", short)
	}

	full, err := ReadFileBounded(path, 100)
	if err != nil {
		t.Fatalf("read full: %v", err)
	}
	if !strings.HasPrefix(full, "hello") || !strings.HasSuffix(full, "world") {
		t.Fatalf("full = %q", full)
	}
	if !strings.Contains(full, "\uFFFD") {
		t.Fatalf("invalid UTF-8 not replaced: %q", full)
	}

	zero, err := ReadFileBounded(path, 0)
	if err != nil || zero != "" {
		t.Fatalf("zero bytes = %q, %v", zero, err)
	}

	if _, err := ReadFileBounded(filepath.Join(dir, "missing"), 10); err == nil {
		t.Fatal("missing file read succeeded")
	}
}

func TestFilesystemLiveSmoke(t *testing.T) {
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("live /proc unavailable")
	}
	meta := StatPath("/proc/self/stat")
	if !meta.Exists || !meta.IsFile {
		t.Fatalf("live stat metadata = %+v", meta)
	}
	text, err := ReadFileBounded("/proc/self/stat", 64)
	if err != nil {
		t.Skipf("live bounded read unavailable: %v", err)
	}
	if text == "" {
		t.Fatal("live bounded read returned nothing")
	}
}

func TestReadFilesystemUsageMatchesListMounts(t *testing.T) {
	root := t.TempDir()
	mountPoint := filepath.Join(root, "data")
	if err := os.MkdirAll(mountPoint, 0o755); err != nil {
		t.Fatal(err)
	}
	fileMount := filepath.Join(root, "hosts")
	fsTestWrite(t, fileMount, []byte("127.0.0.1 localhost\n"))
	fsTestWrite(t, filepath.Join(root, "mounts"), []byte(
		"/dev/sda1 "+mountPoint+" ext4 rw 0 0\n"+
			"/dev/sda1 "+fileMount+" ext4 rw 0 0\n"+
			"proc /proc proc rw 0 0\n"))

	usage, err := ReadFilesystemUsage(root, false)
	if err != nil {
		t.Fatalf("read usage: %v", err)
	}
	list, err := ListMounts(root, false)
	if err != nil {
		t.Fatalf("list mounts: %v", err)
	}
	if list.Total != 2 {
		t.Fatalf("list mounts total = %d", list.Total)
	}
	if usage.Total != 1 {
		t.Fatalf("file bind mounts must be dropped: %+v", usage)
	}
	if usage.Mounts[0].MountPoint != mountPoint {
		t.Fatalf("mount point = %q", usage.Mounts[0].MountPoint)
	}
	if usage.Mounts[0].TotalBytes == nil || usage.Mounts[0].UsedPercent == nil {
		t.Fatalf("capacity missing: %+v", usage.Mounts[0])
	}
}
