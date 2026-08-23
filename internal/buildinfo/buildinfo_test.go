package buildinfo_test

import (
	"strings"
	"testing"

	"github.com/crowl/limes/internal/buildinfo"
)

func TestString(t *testing.T) {
	got := buildinfo.String()
	if !strings.HasPrefix(got, "limes ") || !strings.Contains(got, " (") || !strings.HasSuffix(got, ")") {
		t.Fatalf("String() = %q", got)
	}
}
