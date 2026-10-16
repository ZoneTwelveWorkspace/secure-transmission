package transfer

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

type serverKeys struct {
	V                 int    `json:"v"`
	EncryptionPrivate string `json:"encryptionPrivate"`
	EncryptionPublic  string `json:"encryptionPublic"`
	SigningPrivate    string `json:"signingPrivate"`
	SigningPublic     string `json:"signingPublic"`
	TokenHash         string `json:"tokenHash"`
}

func encodeProfile(p profile) string {
	data, _ := json.Marshal(p)
	return base64.RawURLEncoding.EncodeToString(data)
}

func initializeServer(state, endpoint string) (profile, error) {
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8080/"
	}
	if _, err := validatedEndpoint(endpoint); err != nil {
		return profile{}, err
	}
	root, err := privateDirectory(state)
	if err != nil {
		return profile{}, err
	}
	for _, name := range []string{"keys.json", "client.profile"} {
		if _, err := os.Lstat(filepath.Join(root, name)); !errors.Is(err, os.ErrNotExist) {
			return profile{}, errors.New("server already initialized or state is inaccessible")
		}
	}
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return profile{}, err
	}
	public, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return profile{}, err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(signing)
	if err != nil {
		return profile{}, err
	}
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return profile{}, err
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return profile{}, err
	}
	p := profile{V: 1, EncryptionKey: base64RawURL(private.PublicKey().Bytes()), SigningKey: base64RawURL(publicDER), Token: base64RawURL(token), Endpoint: endpoint}
	keys := serverKeys{V: 1, EncryptionPrivate: base64RawURL(private.Bytes()), EncryptionPublic: p.EncryptionKey, SigningPrivate: base64RawURL(privateDER), SigningPublic: p.SigningKey, TokenHash: digest([]byte(p.Token))}
	encoded, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		return profile{}, err
	}
	if err := writePrivate(filepath.Join(root, "keys.json"), append(encoded, '\n')); err != nil {
		return profile{}, err
	}
	if err := writePrivate(filepath.Join(root, "client.profile"), []byte(encodeProfile(p)+"\n")); err != nil {
		return profile{}, err
	}
	if err := syncDirectory(root); err != nil {
		return profile{}, err
	}
	return p, nil
}

func loadServerKeys(state string) (serverKeys, *ecdh.PrivateKey, ed25519.PrivateKey, error) {
	var keys serverKeys
	data, err := readPrivate(filepath.Join(state, "keys.json"), 64*1024)
	if err != nil {
		return keys, nil, nil, err
	}
	if err := json.Unmarshal(data, &keys); err != nil || keys.V != 1 || !digestPattern.MatchString(keys.TokenHash) {
		return keys, nil, nil, errors.New("invalid server key file")
	}
	secret, err := base64.RawURLEncoding.DecodeString(keys.EncryptionPrivate)
	if err != nil {
		return keys, nil, nil, errors.New("invalid encryption private key")
	}
	defer clear(secret)
	private, err := ecdh.X25519().NewPrivateKey(secret)
	if err != nil || base64RawURL(private.PublicKey().Bytes()) != keys.EncryptionPublic {
		return keys, nil, nil, errors.New("mismatched encryption keys")
	}
	der, err := base64.RawURLEncoding.DecodeString(keys.SigningPrivate)
	if err != nil {
		return keys, nil, nil, errors.New("invalid signing private key")
	}
	defer clear(der)
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return keys, nil, nil, err
	}
	signing, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return keys, nil, nil, errors.New("signing key must be Ed25519")
	}
	public, err := decodePublicSigningKey(keys.SigningPublic)
	if err != nil || !bytes.Equal(public, signing.Public().(ed25519.PublicKey)) {
		return keys, nil, nil, errors.New("mismatched signing keys")
	}
	return keys, private, signing, nil
}

func readPrivate(filename string, limit int64) ([]byte, error) {
	file, err := openReadNoFollow(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("invalid private file")
	}
	if err := validatePrivateDirectoryOwner(info); err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(file, limit+1))
}
