package ca

import (
	"bytes"
	"crypto/x509"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLifecycleAndLeafCertificates(t *testing.T) {
	home := t.TempDir()
	getenv := func(name string) string {
		if name == "HOME" {
			return home
		}
		return ""
	}

	var output bytes.Buffer
	if err := Run([]string{"init"}, getenv, &output, io.Discard); err != nil {
		t.Fatal(err)
	}
	certificatePath := filepath.Join(home, ".config", "limes", certificateFilename)
	privateKeyPath := filepath.Join(home, ".config", "limes", privateKeyFilename)
	if !strings.Contains(output.String(), certificatePath) || !strings.Contains(output.String(), privateKeyPath) {
		t.Fatalf("init output = %q", output.String())
	}
	keyInfo, err := os.Stat(privateKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("private key permissions = %o", keyInfo.Mode().Perm())
	}
	if err := Run([]string{"init"}, getenv, io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second init error = %v", err)
	}

	authority, err := Load(getenv)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := authority.Certificate("api.github.test")
	if err != nil {
		t.Fatal(err)
	}
	leafCertificate, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(authority.certificate)
	if _, err := leafCertificate.Verify(x509.VerifyOptions{DNSName: "api.github.test", Roots: roots}); err != nil {
		t.Fatalf("verify leaf: %v", err)
	}
	if _, err := leafCertificate.Verify(x509.VerifyOptions{DNSName: "other.test", Roots: roots}); err == nil {
		t.Fatal("leaf certificate verified for a different host")
	}

	output.Reset()
	if err := Run([]string{"status"}, getenv, &output, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "fingerprint:") || strings.Contains(output.String(), "PRIVATE KEY") {
		t.Fatalf("status output = %q", output.String())
	}
	output.Reset()
	if err := Run([]string{"certificate"}, getenv, &output, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "BEGIN CERTIFICATE") || strings.Contains(output.String(), "PRIVATE KEY") {
		t.Fatalf("certificate output = %q", output.String())
	}
}

func TestCertificateRenewsCachedLeafBeforeExpiration(t *testing.T) {
	home := t.TempDir()
	getenv := func(name string) string {
		if name == "HOME" {
			return home
		}
		return ""
	}
	if err := Run([]string{"init"}, getenv, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	authority, err := Load(getenv)
	if err != nil {
		t.Fatal(err)
	}

	first, err := authority.Certificate("api.openai.com")
	if err != nil {
		t.Fatal(err)
	}
	cached, err := authority.Certificate("api.openai.com")
	if err != nil {
		t.Fatal(err)
	}
	if cached != first {
		t.Fatal("valid leaf certificate was not reused")
	}

	first.Leaf.NotAfter = time.Now().Add(leafRenewalMargin - time.Second)
	renewed, err := authority.Certificate("api.openai.com")
	if err != nil {
		t.Fatal(err)
	}
	if renewed == first {
		t.Fatal("leaf certificate near expiration was reused")
	}
	if !renewed.Leaf.NotAfter.After(first.Leaf.NotAfter) {
		t.Fatalf("renewed leaf expires at %s; previous leaf expires at %s", renewed.Leaf.NotAfter, first.Leaf.NotAfter)
	}
}

func TestRotateRequiresForceAndReplacesCA(t *testing.T) {
	home := t.TempDir()
	getenv := func(name string) string {
		if name == "HOME" {
			return home
		}
		return ""
	}
	if err := Run([]string{"init"}, getenv, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(home, ".config", "limes", certificateFilename))
	if err != nil {
		t.Fatal(err)
	}
	if err := Run([]string{"rotate"}, getenv, io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("rotate error = %v", err)
	}
	if err := Run([]string{"rotate", "--force"}, getenv, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(home, ".config", "limes", certificateFilename))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, after) {
		t.Fatal("rotation did not replace the certificate")
	}
}

func TestLoadRejectsInsecurePrivateKeyPermissions(t *testing.T) {
	home := t.TempDir()
	getenv := func(name string) string {
		if name == "HOME" {
			return home
		}
		return ""
	}
	if err := Run([]string{"init"}, getenv, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(home, ".config", "limes", privateKeyFilename)
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(getenv); err == nil || !strings.Contains(err.Error(), "inaccessible to group and others") {
		t.Fatalf("Load() error = %v", err)
	}
}
