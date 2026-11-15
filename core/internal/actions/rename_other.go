//go:build !linux || (!amd64 && !arm64)

package actions

// renameNoReplace refuses rather than falling back to a non-atomic rename.
func renameNoReplace(_, _ string) error {
	return errRenameUnavailable
}
