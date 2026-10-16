//go:build !windows

package transfer

import (
	"errors"
	"os"
	"syscall"
)

func validatePrivateDirectoryOwner(info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("state directory must be owned by you and have mode 700")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Getuid() {
		return errors.New("state directory must be owned by you and have mode 700")
	}
	return nil
}
