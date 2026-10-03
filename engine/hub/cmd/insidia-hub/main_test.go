package main

import (
	"io"
	"net/http"
	"testing"
	"time"
)

func TestHealthz(t *testing.T) {
	go func() {
		_ = http.ListenAndServe("127.0.0.1:18081", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"status":"ok"}`)
		}))
	}()
	deadline := time.Now().Add(2 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://127.0.0.1:18081/healthz")
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Fatalf("status %d", resp.StatusCode)
			}
			return
		}
		last = err
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal(last)
}
