package openapi

import (
	"strings"
	"testing"
	"time"

	"github.com/jaylordibe/application-security-framework/internal/model"
)

// A YAML alias bomb: a few hundred bytes that expand to hundreds of millions of
// nodes. The input size cap does not bound this, because expansion is
// exponential in the input.
func TestYAMLAliasBombIsRefused(t *testing.T) {
	var b strings.Builder
	b.WriteString("openapi: 3.0.0\ninfo:\n  title: t\n  version: '1'\npaths: {}\nx-bomb:\n")
	b.WriteString("  a: &a [x,x,x,x,x,x,x,x,x]\n")
	prev := "a"
	for i := 0; i < 9; i++ {
		name := string(rune('b' + i))
		b.WriteString("  " + name + ": &" + name + " [")
		for j := 0; j < 9; j++ {
			if j > 0 {
				b.WriteString(",")
			}
			b.WriteString("*" + prev)
		}
		b.WriteString("]\n")
		prev = name
	}
	doc := b.String()
	t.Logf("bomb is %d bytes", len(doc))

	done := make(chan error, 1)
	go func() {
		_, err := Parse([]byte(doc), "https://x.test", model.Source{})
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("alias bomb was accepted")
		}
		t.Logf("refused with: %v", err)
	case <-time.After(20 * time.Second):
		t.Fatal("alias bomb hung the parser")
	}
}
