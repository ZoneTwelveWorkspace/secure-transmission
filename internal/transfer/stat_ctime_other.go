//go:build !darwin && !linux

package transfer

import "os"

func changeTime(_ os.FileInfo) (int64, bool) { return 0, false }
