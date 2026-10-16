package transfer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	projectsource "secure-transmission"
)

type generateOptions struct{ output, goos, goarch string }

var targetPattern = regexp.MustCompile(`^[a-z0-9]+$`)

func generateClient(ctx context.Context, p profile, options generateOptions) error {
	if _, err := decodeProfile(encodeProfile(p)); err != nil {
		return err
	}
	if options.output == "" {
		return errors.New("generate requires --out")
	}
	if options.goos == "" {
		options.goos = runtime.GOOS
	}
	if options.goarch == "" {
		options.goarch = runtime.GOARCH
	}
	if !targetPattern.MatchString(options.goos) || !targetPattern.MatchString(options.goarch) {
		return errors.New("invalid build target")
	}
	output, err := filepath.Abs(options.output)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		return errors.New("output already exists or is inaccessible; choose a new filename")
	}
	compiler, err := exec.LookPath("go")
	if err != nil {
		return errors.New("client generation requires Go 1.24 or newer on the generating computer")
	}
	directory, err := os.MkdirTemp("", "secure-transmission-build-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	if err := fs.WalkDir(projectsource.Files, ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		body, err := projectsource.Files.ReadFile(name)
		if err != nil {
			return err
		}
		target := filepath.Join(directory, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		return writePrivate(target, body)
	}); err != nil {
		return err
	}
	binary := filepath.Join(directory, "client")
	command := exec.CommandContext(ctx, compiler, "build", "-trimpath", "-mod=readonly", "-ldflags", "-s -w -X main.pinnedProfile="+encodeProfile(p), "-o", binary, "./cmd/client")
	command.Dir = directory
	// Replace inherited target settings without invoking a shell.
	command.Env = filteredEnvironment("GOOS", "GOARCH", "CGO_ENABLED", "GOWORK", "GOFLAGS", "GOTOOLCHAIN")
	command.Env = append(command.Env, "GOOS="+options.goos, "GOARCH="+options.goarch, "CGO_ENABLED=0", "GOWORK=off", "GOFLAGS=", "GOTOOLCHAIN=local")
	var diagnostics boundedOutput
	command.Stdout = &diagnostics
	command.Stderr = &diagnostics
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("build client: %w\n%s", err, strings.TrimSpace(diagnostics.String()))
	}
	source, err := os.Open(binary)
	if err != nil {
		return err
	}
	defer source.Close()
	destination, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		return err
	}
	published := false
	defer func() {
		_ = destination.Close()
		if !published {
			_ = os.Remove(output)
		}
	}()
	if _, err := io.Copy(destination, source); err != nil {
		return err
	}
	if err := destination.Sync(); err != nil {
		return err
	}
	if err := destination.Close(); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(output)); err != nil {
		return err
	}
	published = true
	return nil
}

func filteredEnvironment(excluded ...string) []string {
	result := make([]string, 0, len(os.Environ()))
	for _, variable := range os.Environ() {
		key, _, _ := strings.Cut(variable, "=")
		skip := false
		for _, name := range excluded {
			if strings.EqualFold(key, name) {
				skip = true
				break
			}
		}
		if !skip {
			result = append(result, variable)
		}
	}
	return result
}

type boundedOutput struct{ bytes.Buffer }

func (b *boundedOutput) Write(data []byte) (int, error) {
	length := len(data)
	if remaining := 16*1024 - b.Len(); remaining > 0 {
		_, _ = b.Buffer.Write(data[:min(remaining, len(data))])
	}
	return length, nil
}
