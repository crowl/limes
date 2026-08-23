package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/crowl/limes/internal/app"
	"github.com/crowl/limes/internal/config"
)

func main() {
	if err := app.Run(context.Background(), os.Args[1:], os.Getenv, slog.Default(), os.Stderr); err != nil {
		if config.IsHelp(err) {
			return
		}
		slog.Error("limes stopped", "error", err)
		os.Exit(1)
	}
}
