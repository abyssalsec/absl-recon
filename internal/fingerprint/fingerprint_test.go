package fingerprint

import (
	"testing"

	"github.com/abyssalsec/absl-recon/internal/model"
)

func TestClassifyOpenSSH(t *testing.T) {
	svc := model.Service{
		Protocol: "tcp",
		Name:     "unknown",
	}

	raw :=
		[]byte(
			"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n",
		)

	if !classifyBanner(&svc, raw) {
		t.Fatal("OpenSSH banner was not detected")
	}

	if svc.Name != "ssh" {
		t.Fatalf(
			"expected ssh, got %q",
			svc.Name,
		)
	}

	if svc.Product != "OpenSSH" {
		t.Fatalf(
			"expected OpenSSH, got %q",
			svc.Product,
		)
	}

	if svc.Version != "9.6p1" {
		t.Fatalf(
			"expected 9.6p1, got %q",
			svc.Version,
		)
	}

	if svc.Confidence != 100 {
		t.Fatalf(
			"expected confidence 100, got %d",
			svc.Confidence,
		)
	}
}

func TestParseServerHeader(t *testing.T) {
	product, version :=
		parseServerHeader(
			"nginx/1.24.0",
		)

	if product != "nginx" {
		t.Fatalf(
			"expected nginx, got %q",
			product,
		)
	}

	if version != "1.24.0" {
		t.Fatalf(
			"expected 1.24.0, got %q",
			version,
		)
	}
}
