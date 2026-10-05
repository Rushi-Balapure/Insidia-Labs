package main

import (
	"fmt"
	"net/http"
	"os"
)

const version = "0.1.0"

func main() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Printf("insidia-hub %s\n", version)
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	addr := "127.0.0.1:8081"
	fmt.Fprintf(os.Stderr, "insidia-hub listening on %s\n", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
