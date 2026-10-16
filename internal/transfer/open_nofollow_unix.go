//go:build !windows

package transfer

import (
	"os"
	"syscall"
)

func openReadNoFollow(filename string) (*os.File, error) {
	fd, err := syscall.Open(filename, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), filename), nil
}
