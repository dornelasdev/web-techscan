package main

import (
	"os"

	"webscan/internal/cli"
)

// version can be set for release builds with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr, version))
}
