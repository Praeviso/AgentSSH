package remoteclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/Praeviso/AgentSSH/internal/executor"
	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/remote"
)

// WatchInterval is how often a running command re-checks the device's standing.
var WatchInterval = 30 * time.Second

// ErrRevokedDuringRun reports a command cancelled because the control plane
// revoked this device while it was running.
var ErrRevokedDuringRun = errors.New("the control plane revoked this device while the command was running; it was cancelled")

// WrapExecutor cancels in-flight commands once the control plane reports the
// device revoked. Only a definitive revocation cancels; a transient network
// failure does not, because signing and configuration already fail closed.
// This guards against the agent, not against a modified client binary.
func (s *Session) WrapExecutor(inner executor.Executor) executor.Executor {
	return &guardedExecutor{inner: inner, status: func(ctx context.Context) error {
		_, err := s.Client.Status(ctx)
		return err
	}}
}

type guardedExecutor struct {
	inner  executor.Executor
	status func(context.Context) error
}

func (g *guardedExecutor) watch(ctx context.Context) (context.Context, func() bool) {
	ctx, cancel := context.WithCancelCause(ctx)
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(WatchInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := g.status(ctx); remote.IsRevoked(err) {
					cancel(ErrRevokedDuringRun)
					return
				}
			}
		}
	}()
	return ctx, func() bool {
		close(done)
		<-stopped
		revoked := errors.Is(context.Cause(ctx), ErrRevokedDuringRun)
		cancel(nil)
		return revoked
	}
}

func revokedResult(result executor.Result) executor.Result {
	result.ExitCode = -1
	if result.Err == nil {
		result.Err = ErrRevokedDuringRun
	} else {
		result.Err = fmt.Errorf("%w: %w", ErrRevokedDuringRun, result.Err)
	}
	return result
}

func (g *guardedExecutor) Run(ctx context.Context, request executor.Request) executor.Result {
	ctx, stop := g.watch(ctx)
	result := g.inner.Run(ctx, request)
	if stop() {
		return revokedResult(result)
	}
	return result
}

func (g *guardedExecutor) RunStreaming(ctx context.Context, request executor.Request, stdout io.Writer, stderr io.Writer) executor.Result {
	streaming, ok := g.inner.(executor.StreamingExecutor)
	if !ok {
		return g.Run(ctx, request)
	}
	ctx, stop := g.watch(ctx)
	result := streaming.RunStreaming(ctx, request, stdout, stderr)
	if stop() {
		return revokedResult(result)
	}
	return result
}

// Probe forwards to the wrapped executor's probe when it has one.
func (g *guardedExecutor) Probe(ctx context.Context, target inventory.Target) executor.Result {
	if prober, ok := g.inner.(interface {
		Probe(context.Context, inventory.Target) executor.Result
	}); ok {
		return prober.Probe(ctx, target)
	}
	return g.Run(ctx, executor.Request{Target: target, Command: executor.OSProbeCommand})
}

func (g *guardedExecutor) Close() error {
	return g.inner.Close()
}
