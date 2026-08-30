package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/crowl/limes/internal/app"
	"github.com/crowl/limes/internal/ca"
	"github.com/crowl/limes/internal/config"
)

func main() {
	var err error
	if len(os.Args) > 1 && os.Args[1] == "ca" {
		err = ca.Run(os.Args[2:], os.Getenv, os.Stdout, os.Stderr)
	} else {
		err = app.Run(context.Background(), os.Args[1:], os.Getenv, slog.Default(), os.Stdout, os.Stderr)
	}
	if err != nil {
		if config.IsHelp(err) {
			return
		}
		slog.Error("limes stopped", "error", err)
		os.Exit(1)
	}
}
