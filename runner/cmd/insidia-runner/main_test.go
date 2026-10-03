package main

import (
	"os/exec"
	"strings"
	"testing"
)

func TestVersion(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal(err, string(out))
	}
	if !strings.Contains(string(out), "insidia-runner 0.1.0") {
		t.Fatalf("unexpected version output: %s", out)
	}
}
