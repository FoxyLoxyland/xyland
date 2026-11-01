package main

import (
	"os"

	"github.com/FoxyLoxyland/xyland/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
