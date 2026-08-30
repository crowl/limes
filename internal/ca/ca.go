// Package ca manages the local certificate authority used by HTTPS backends.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	certificateFilename = "ca-cert.pem"
	privateKeyFilename  = "ca-key.pem"
)

// Authority is a loaded Limes certificate authority. It issues short-lived
// server certificates and caches them in memory for the process lifetime.
type Authority struct {
	certificate *x509.Certificate
	privateKey  *ecdsa.PrivateKey

	mu    sync.Mutex
	leafs map[string]*tls.Certificate
}

// Run executes a CA lifecycle subcommand.
func Run(args []string, getenv func(string) string, output, flagOutput io.Writer) error {
	if len(args) == 0 {
		return errors.New("CA command is required: init, status, certificate, or rotate")
	}

	directory, err := resolveDirectory(getenv)
	if err != nil {
		return err
	}
	certificatePath := filepath.Join(directory, certificateFilename)
	privateKeyPath := filepath.Join(directory, privateKeyFilename)

	switch args[0] {
	case "init":
		flags := flag.NewFlagSet("ca init", flag.ContinueOnError)
		flags.SetOutput(flagOutput)
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return fmt.Errorf("unexpected positional argument %q", flags.Arg(0))
		}
		if err := initialize(directory, certificatePath, privateKeyPath, false); err != nil {
			return err
		}
		_, err := fmt.Fprintf(output, "initialized Limes CA\ncertificate: %s\nprivate key: %s\n", certificatePath, privateKeyPath)
		return err
	case "status":
		flags := flag.NewFlagSet("ca status", flag.ContinueOnError)
		flags.SetOutput(flagOutput)
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return fmt.Errorf("unexpected positional argument %q", flags.Arg(0))
		}
		authority, err := load(certificatePath, privateKeyPath)
		if err != nil {
			return err
		}
		fingerprint := x509Fingerprint(authority.certificate.Raw)
		_, err = fmt.Fprintf(output, "certificate: %s\nprivate key: %s\nsubject: %s\nfingerprint: %s\nnot before: %s\nnot after: %s\n",
			certificatePath,
			privateKeyPath,
			authority.certificate.Subject.String(),
			fingerprint,
			authority.certificate.NotBefore.UTC().Format(time.RFC3339),
			authority.certificate.NotAfter.UTC().Format(time.RFC3339),
		)
		return err
	case "certificate":
		flags := flag.NewFlagSet("ca certificate", flag.ContinueOnError)
		flags.SetOutput(flagOutput)
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return fmt.Errorf("unexpected positional argument %q", flags.Arg(0))
		}
		if _, err := load(certificatePath, privateKeyPath); err != nil {
			return err
		}
		contents, err := os.ReadFile(certificatePath)
		if err != nil {
			return fmt.Errorf("read CA certificate: %w", err)
		}
		_, err = output.Write(contents)
		return err
	case "rotate":
		flags := flag.NewFlagSet("ca rotate", flag.ContinueOnError)
		flags.SetOutput(flagOutput)
		force := flags.Bool("force", false, "replace the existing CA")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return fmt.Errorf("unexpected positional argument %q", flags.Arg(0))
		}
		if !*force {
			return errors.New("CA rotation invalidates existing trust; rerun with --force")
		}
		if _, err := load(certificatePath, privateKeyPath); err != nil {
			return fmt.Errorf("load existing CA before rotation: %w", err)
		}
		if err := initialize(directory, certificatePath, privateKeyPath, true); err != nil {
			return err
		}
		_, err := fmt.Fprintf(output, "rotated Limes CA\ncertificate: %s\nprivate key: %s\n", certificatePath, privateKeyPath)
		return err
	default:
		return fmt.Errorf("unknown CA command %q: expected init, status, certificate, or rotate", args[0])
	}
}

// Load loads and validates the managed CA from the Limes configuration directory.
func Load(getenv func(string) string) (*Authority, error) {
	directory, err := resolveDirectory(getenv)
	if err != nil {
		return nil, err
	}
	return load(filepath.Join(directory, certificateFilename), filepath.Join(directory, privateKeyFilename))
}

// Certificate returns a short-lived certificate for exactly host.
func (authority *Authority) Certificate(host string) (*tls.Certificate, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return nil, errors.New("certificate host is empty")
	}

	authority.mu.Lock()
	defer authority.mu.Unlock()
	if certificate := authority.leafs[host]; certificate != nil {
		return certificate, nil
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf private key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	notAfter := now.Add(24 * time.Hour)
	if notAfter.After(authority.certificate.NotAfter) {
		notAfter = authority.certificate.NotAfter
	}
	if !notAfter.After(now) {
		return nil, errors.New("Limes CA has expired")
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, authority.certificate, &privateKey.PublicKey, authority.privateKey)
	if err != nil {
		return nil, fmt.Errorf("create leaf certificate: %w", err)
	}
	certificate := &tls.Certificate{
		Certificate: [][]byte{certificateDER, authority.certificate.Raw},
		PrivateKey:  privateKey,
	}
	authority.leafs[host] = certificate
	return certificate, nil
}

func resolveDirectory(getenv func(string) string) (string, error) {
	if directory := getenv("XDG_CONFIG_HOME"); directory != "" {
		return filepath.Join(directory, "limes"), nil
	}
	if home := getenv("HOME"); home != "" {
		return filepath.Join(home, ".config", "limes"), nil
	}
	return "", errors.New("cannot resolve CA directory: set XDG_CONFIG_HOME or HOME")
}

func initialize(directory, certificatePath, privateKeyPath string, replace bool) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create CA directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return fmt.Errorf("secure CA directory: %w", err)
	}
	if !replace {
		for _, path := range []string{certificatePath, privateKeyPath} {
			if _, err := os.Lstat(path); err == nil {
				return fmt.Errorf("CA file already exists: %s", path)
			} else if !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("inspect CA file %s: %w", path, err)
			}
		}
	}

	certificatePEM, privateKeyPEM, err := generate()
	if err != nil {
		return err
	}
	certificateTemporary, err := writeTemporary(directory, certificateFilename, certificatePEM, 0o644)
	if err != nil {
		return err
	}
	defer os.Remove(certificateTemporary)
	privateKeyTemporary, err := writeTemporary(directory, privateKeyFilename, privateKeyPEM, 0o600)
	if err != nil {
		return err
	}
	defer os.Remove(privateKeyTemporary)

	if replace {
		return replacePair(certificatePath, privateKeyPath, certificateTemporary, privateKeyTemporary)
	}
	if err := os.Rename(privateKeyTemporary, privateKeyPath); err != nil {
		return fmt.Errorf("install CA private key: %w", err)
	}
	if err := os.Rename(certificateTemporary, certificatePath); err != nil {
		_ = os.Remove(privateKeyPath)
		return fmt.Errorf("install CA certificate: %w", err)
	}
	return nil
}

func generate() ([]byte, []byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate CA private key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Limes Local CA", Organization: []string{"Limes"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create CA certificate: %w", err)
	}
	privateKeyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal CA private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyDER}), nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	return serial, nil
}

func writeTemporary(directory, pattern string, contents []byte, mode os.FileMode) (string, error) {
	file, err := os.CreateTemp(directory, "."+pattern+".*")
	if err != nil {
		return "", fmt.Errorf("create temporary CA file: %w", err)
	}
	path := file.Name()
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(mode); err != nil {
		return "", fmt.Errorf("set temporary CA file permissions: %w", err)
	}
	if _, err := file.Write(contents); err != nil {
		return "", fmt.Errorf("write temporary CA file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return "", fmt.Errorf("sync temporary CA file: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close temporary CA file: %w", err)
	}
	ok = true
	return path, nil
}

func replacePair(certificatePath, privateKeyPath, certificateTemporary, privateKeyTemporary string) error {
	certificateBackup := certificatePath + ".previous"
	privateKeyBackup := privateKeyPath + ".previous"
	_ = os.Remove(certificateBackup)
	_ = os.Remove(privateKeyBackup)
	if err := os.Rename(certificatePath, certificateBackup); err != nil {
		return fmt.Errorf("back up CA certificate: %w", err)
	}
	if err := os.Rename(privateKeyPath, privateKeyBackup); err != nil {
		_ = os.Rename(certificateBackup, certificatePath)
		return fmt.Errorf("back up CA private key: %w", err)
	}
	rollback := func() {
		_ = os.Remove(certificatePath)
		_ = os.Remove(privateKeyPath)
		_ = os.Rename(certificateBackup, certificatePath)
		_ = os.Rename(privateKeyBackup, privateKeyPath)
	}
	if err := os.Rename(privateKeyTemporary, privateKeyPath); err != nil {
		rollback()
		return fmt.Errorf("install rotated CA private key: %w", err)
	}
	if err := os.Rename(certificateTemporary, certificatePath); err != nil {
		_ = os.Remove(privateKeyPath)
		rollback()
		return fmt.Errorf("install rotated CA certificate: %w", err)
	}
	_ = os.Remove(certificateBackup)
	_ = os.Remove(privateKeyBackup)
	return nil
}

func load(certificatePath, privateKeyPath string) (*Authority, error) {
	certificateInfo, err := os.Lstat(certificatePath)
	if err != nil {
		return nil, fmt.Errorf("inspect CA certificate: %w", err)
	}
	if !certificateInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("CA certificate must be a regular file: %s", certificatePath)
	}
	info, err := os.Lstat(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("inspect CA private key: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("CA private key must be a regular file inaccessible to group and others: %s", privateKeyPath)
	}
	certificatePEM, err := os.ReadFile(certificatePath)
	if err != nil {
		return nil, fmt.Errorf("read CA certificate: %w", err)
	}
	privateKeyPEM, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read CA private key: %w", err)
	}
	pair, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse CA key pair: %w", err)
	}
	certificate, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	privateKey, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("CA private key is not ECDSA")
	}
	if !certificate.IsCA || !certificate.BasicConstraintsValid || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("CA certificate is not valid for certificate signing")
	}
	now := time.Now()
	if now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
		return nil, errors.New("CA certificate is not currently valid")
	}
	return &Authority{certificate: certificate, privateKey: privateKey, leafs: make(map[string]*tls.Certificate)}, nil
}

func x509Fingerprint(der []byte) string {
	digest := sha256.Sum256(der)
	encoded := strings.ToUpper(hex.EncodeToString(digest[:]))
	parts := make([]string, 0, len(encoded)/2)
	for index := 0; index < len(encoded); index += 2 {
		parts = append(parts, encoded[index:index+2])
	}
	return strings.Join(parts, ":")
}
