package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/crowl/limes/internal/buildinfo"
	"github.com/crowl/limes/internal/config"
)

const (
	shutdownTimeout    = 10 * time.Second
	requestReadTimeout = 5 * time.Minute
)

func Run(ctx context.Context, args []string, getenv func(string) string, logger *slog.Logger, output, flagOutput io.Writer) error {
	return runWithBind(ctx, args, getenv, logger, output, flagOutput, bindProviders)
}

func runWithBind(ctx context.Context, args []string, getenv func(string) string, logger *slog.Logger, output, flagOutput io.Writer, bind func([]provider) ([]runningProvider, error)) error {
	options, err := config.Parse(args, flagOutput)
	if err != nil {
		return err
	}
	if options.ShowVersion {
		_, err := fmt.Fprintln(output, buildinfo.String())
		return err
	}

	cfg, err := config.Load(options.Path)
	if err != nil {
		return err
	}
	providers := configureRuntimeProviders(cfg, getenv, logger)
	available := availableProviders(providers)
	if len(available) == 0 && cfg.Admin == nil {
		return errors.New("no configured listener has an available backend")
	}

	running, err := bind(available)
	if err != nil {
		return err
	}
	if cfg.Admin != nil {
		panel, err := newAdminPanel(cfg.Admin.Address, providers, logger)
		if err != nil {
			closeListeners(running)
			return err
		}
		admin, err := bindAdmin(panel)
		if err != nil {
			closeListeners(running)
			return err
		}
		running = append(running, admin)
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	return serveRunning(ctx, running, logger)
}

func serveRunning(ctx context.Context, running []runningProvider, logger *slog.Logger) error {
	serveErrors := make(chan error, len(running))
	for _, instance := range running {
		if instance.provider.authMode == "admin" {
			logger.Info("admin panel listening", "address", instance.listener.Addr().String())
		} else {
			logger.Info("provider proxy listening",
				"provider", instance.provider.name,
				"address", instance.listener.Addr().String(),
				"auth", instance.provider.authMode,
			)
			if !isLoopbackAddress(instance.provider.address) {
				logger.Warn("listener is reachable beyond loopback; Limes does not authenticate incoming clients, so do not expose it to untrusted networks",
					"provider", instance.provider.name,
					"address", instance.provider.address,
				)
			}
		}

		go func(instance runningProvider) {
			err := instance.server.Serve(instance.listener)
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				serveErrors <- fmt.Errorf("serve %s: %w", instance.provider.name, err)
			}
		}(instance)
	}

	select {
	case <-ctx.Done():
	case err := <-serveErrors:
		shutdownServers(running, shutdownTimeout, logger)
		return err
	}

	return shutdownServers(running, shutdownTimeout, logger)
}

func shutdownServers(running []runningProvider, timeout time.Duration, logger *slog.Logger) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	shutdownErrors := make(chan error, len(running))
	for _, instance := range running {
		go func(instance runningProvider) {
			if err := instance.server.Shutdown(ctx); err != nil {
				shutdownErr := fmt.Errorf("shut down %s: %w", instance.provider.name, err)
				if closeErr := instance.server.Close(); closeErr != nil {
					shutdownErr = errors.Join(shutdownErr, fmt.Errorf("close %s: %w", instance.provider.name, closeErr))
				}
				shutdownErrors <- shutdownErr
				return
			}
			if instance.provider.backends != nil {
				instance.provider.backends.setListening(false)
			}
			shutdownErrors <- nil
		}(instance)
	}

	var errs []error
	for range running {
		if err := <-shutdownErrors; err != nil {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		logger.Error("provider shutdown failed", "error", err)
		return err
	}
	return nil
}

func isLoopbackAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
