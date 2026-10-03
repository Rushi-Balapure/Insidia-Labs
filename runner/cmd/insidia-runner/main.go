package main

import (
	"fmt"
	"os"
)

const version = "0.1.0"

func main() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Printf("insidia-runner %s\n", version)
		return
	}
	fmt.Fprintln(os.Stderr, "usage: insidia-runner version")
	os.Exit(2)
}
