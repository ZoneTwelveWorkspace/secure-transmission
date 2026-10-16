//go:build windows

package transfer

import "os"

func openReadNoFollow(filename string) (*os.File, error) {
	info, err := os.Lstat(filename)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, os.ErrPermission
	}
	return os.Open(filename)
}
