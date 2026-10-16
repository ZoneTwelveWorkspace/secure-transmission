package transfer

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type profile struct {
	V             int    `json:"v"`
	EncryptionKey string `json:"encryptionKey"`
	SigningKey    string `json:"signingKey"`
	Token         string `json:"token"`
	Endpoint      string `json:"endpoint"`
}

func decodeProfile(text string) (profile, error) {
	text = strings.TrimSpace(text)
	var data []byte
	var err error
	if strings.HasPrefix(text, "{") {
		data = []byte(text)
	} else {
		data, err = base64.RawURLEncoding.DecodeString(text)
		if err != nil {
			return profile{}, errors.New("invalid client profile")
		}
	}
	var result profile
	if err := json.Unmarshal(data, &result); err != nil || result.V != 1 ||
		!tokenPattern.MatchString(result.EncryptionKey) || !tokenPattern.MatchString(result.Token) {
		return profile{}, errors.New("invalid client profile")
	}
	if _, err := decodePublicEncryptionKey(result.EncryptionKey); err != nil {
		return profile{}, err
	}
	if _, err := decodePublicSigningKey(result.SigningKey); err != nil {
		return profile{}, err
	}
	if _, err := validatedEndpoint(result.Endpoint); err != nil {
		return profile{}, err
	}
	return result, nil
}

func validatedEndpoint(endpoint string) (*url.URL, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("endpoint must be an HTTP(S) or WS(S) URL without credentials, query, or fragment")
	}
	switch parsed.Scheme {
	case "http", "https", "ws", "wss":
	default:
		return nil, errors.New("endpoint must be an HTTP(S) or WS(S) URL without credentials, query, or fragment")
	}
	return parsed, nil
}

func privateDirectory(directory string) (string, error) {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("state directory must be a real directory")
	}
	if err := validatePrivateDirectoryOwner(info); err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(directory)
}

func writePrivate(filename string, data []byte) error {
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
	}()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	closed = true
	return file.Close()
}

type arguments struct {
	command    string
	positional []string
	flags      map[string]string
	booleans   map[string]bool
}

func parseArguments(argv []string) (arguments, error) {
	booleanNames := map[string]bool{"stdin": true, "tor": true, "allow-http": true, "no-browse": true}
	valueNames := map[string]bool{
		"profile": true, "profile-file": true, "endpoint": true, "transport": true,
		"spool": true, "proxy": true, "timeout": true, "attempts": true, "name": true,
	}
	result := arguments{command: "help", flags: make(map[string]string), booleans: make(map[string]bool)}
	if len(argv) == 0 {
		return result, nil
	}
	result.command = argv[0]
	for i := 1; i < len(argv); i++ {
		argument := argv[i]
		if argument == "--" {
			result.positional = append(result.positional, argv[i+1:]...)
			break
		}
		if !strings.HasPrefix(argument, "--") {
			result.positional = append(result.positional, argument)
			continue
		}
		nameValue := strings.SplitN(strings.TrimPrefix(argument, "--"), "=", 2)
		name := nameValue[0]
		if name == "" || (!booleanNames[name] && !valueNames[name]) {
			return arguments{}, fmt.Errorf("unknown option: %s", argument)
		}
		if result.booleans[name] {
			return arguments{}, fmt.Errorf("repeated option: --%s", name)
		}
		if _, exists := result.flags[name]; exists {
			return arguments{}, fmt.Errorf("repeated option: --%s", name)
		}
		if booleanNames[name] {
			if len(nameValue) == 2 {
				return arguments{}, fmt.Errorf("--%s does not take a value", name)
			}
			result.booleans[name] = true
			continue
		}
		var value string
		if len(nameValue) == 2 {
			value = nameValue[1]
		} else {
			i++
			if i >= len(argv) || strings.HasPrefix(argv[i], "--") {
				return arguments{}, fmt.Errorf("--%s needs a value", name)
			}
			value = argv[i]
		}
		result.flags[name] = value
	}
	return result, nil
}

func (a arguments) option(name, fallback string) string {
	if value, ok := a.flags[name]; ok {
		return value
	}
	return fallback
}

func (a arguments) numeric(name string, fallback, minimum, maximum int) (int, error) {
	value, err := strconv.Atoi(a.option(name, strconv.Itoa(fallback)))
	if err != nil || value < minimum || value > maximum {
		return 0, fmt.Errorf("invalid --%s", name)
	}
	return value, nil
}

func isLoopbackHostname(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}
