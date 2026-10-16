//go:build windows

package transfer

import "os"

func validatePrivateDirectoryOwner(_ os.FileInfo) error { return nil }
