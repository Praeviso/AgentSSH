package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/gateway"
	"github.com/Praeviso/AgentSSH/internal/remote"
	"github.com/spf13/cobra"
)

// newDeviceCommand is the shared device command plus activation: a gateway
// device is usable only inside a window an operator opens.
func newDeviceCommand(dir func() (string, error)) *cobra.Command {
	cmd := program.DeviceCommand(dir)
	cmd.Short = "Enroll, list, activate, and revoke devices."

	var window time.Duration
	var note string
	activate := &cobra.Command{
		Use:   "activate <device-id> --for <duration>",
		Short: "Let a device use the gateway for a chosen time, from 1m to 24h.",
		Long: "Let a device use the gateway for a chosen time, from 1m to 24h. It is inactive again when the time ends.\n" +
			"Activating an active device sets a new end. Unlike revoke, deactivate and expiry can be undone by activating again.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withStore(dir, func(d string, store *controlplane.Store) error {
				a, err := gateway.ActivateDevice(d, store, args[0], window, localOperator(), note, time.Now())
				switch {
				case errors.Is(err, gateway.ErrActivationDuration):
					return fmt.Errorf("--for: %w", err)
				case errors.Is(err, controlplane.ErrDeviceRevoked):
					return fmt.Errorf("activate %s: it is revoked; a revoked device cannot be activated again", args[0])
				case err != nil:
					return fmt.Errorf("activate %s: %w", args[0], err)
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Activated %s until %s (%s)\n", args[0], a.Until.Local().Format(time.RFC3339), gateway.Remaining(a.Until, a.SetAt))
				return nil
			})
		},
	}
	activate.Flags().DurationVar(&window, "for", 0, "how long the device may use the gateway, such as 30m or 4h (1m to 24h)")
	activate.Flags().StringVar(&note, "note", "", "why, recorded in the audit chain")
	_ = activate.MarkFlagRequired("for")

	deactivate := &cobra.Command{
		Use:   "deactivate <device-id>",
		Short: "Stop a device from using the gateway now; it can be activated again.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withStore(dir, func(d string, store *controlplane.Store) error {
				closed, err := gateway.DeactivateDevice(d, store, args[0], localOperator(), time.Now())
				if err != nil {
					return fmt.Errorf("deactivate %s: %w", args[0], err)
				}
				if closed {
					_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Deactivated %s\n", args[0])
				} else {
					_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s was not active\n", args[0])
				}
				return nil
			})
		},
	}
	cmd.AddCommand(activate, deactivate, newCreateTokenDeviceCommand(dir), newRotateTokenCommand(dir))
	return cmd
}

// newCreateTokenDeviceCommand adds a token device: one that authenticates with
// a bearer token, for agents that cannot run agentssh.
func newCreateTokenDeviceCommand(dir func() (string, error)) *cobra.Command {
	var name, kind string
	cmd := &cobra.Command{
		Use:   "create --name <name> --kind token",
		Short: "Add a token device, which authenticates with a bearer token instead of enrolling.",
		Long: "Add a token device for an agent that cannot run agentssh: it calls the gateway's API with a bearer token.\n" +
			"The token is printed once and only its hash is kept. The device starts inactive; activate it with device activate.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if kind != remote.DeviceKindToken {
				return errors.New("--kind token is required: signed devices enroll with agentssh remote enroll instead")
			}
			return withStore(dir, func(d string, store *controlplane.Store) error {
				issued, err := gateway.CreateTokenDevice(d, store, name, localOperator(), time.Now())
				if err != nil {
					return err
				}
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), issued.Token)
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Created token device %s (%s). The token above is shown once; send it as \"Authorization: Bearer <token>\".\n"+
					"The device is inactive until you run: agentssh-gateway device activate %s --for <duration>\n", issued.DeviceID, name, issued.DeviceID)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "device name (e.g. hosted-agent)")
	cmd.Flags().StringVar(&kind, "kind", "", "device kind; only token devices are created here")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("kind")
	return cmd
}

func newRotateTokenCommand(dir func() (string, error)) *cobra.Command {
	return &cobra.Command{
		Use:   "rotate <device-id>",
		Short: "Replace a token device's token; the old one is refused at once.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withStore(dir, func(d string, store *controlplane.Store) error {
				issued, err := gateway.RotateToken(d, store, args[0], localOperator(), time.Now())
				switch {
				case errors.Is(err, gateway.ErrNotTokenDevice):
					return fmt.Errorf("rotate %s: it is a signed device; only token devices have tokens", args[0])
				case errors.Is(err, controlplane.ErrDeviceRevoked):
					return fmt.Errorf("rotate %s: it is revoked", args[0])
				case err != nil:
					return fmt.Errorf("rotate %s: %w", args[0], err)
				}
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), issued.Token)
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Rotated the token of %s; the old one is refused from now on. The token above is shown once.\n", args[0])
				return nil
			})
		},
	}
}

// activationColumn is a device's window in device ls.
func activationColumn(store *controlplane.Store, device controlplane.Device, now time.Time) string {
	if device.Status == remote.DeviceRevoked {
		return "-"
	}
	a, err := gateway.DeviceActivation(store, device.ID)
	if err != nil {
		return "unknown"
	}
	if !a.Active(now) {
		return "inactive"
	}
	return fmt.Sprintf("until %s (%s left)", a.Until.Local().Format(time.RFC3339), gateway.Remaining(a.Until, now))
}

// checkStanding performs only state reads and cancellation. Audit-file I/O
// runs on an independent loop, so even a blocked audit lock cannot delay the
// next standing check.
func checkStanding(ctx context.Context, server *gateway.Server) {
	ticker := time.NewTicker(gateway.StandingCheckEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := server.CancelRunsWithoutStanding(); err != nil {
				log.Printf("agentssh-gateway: check running commands' standing: %v", err)
			}
		}
	}
}

// repairAudits collects expired windows and publishes pending lifecycle facts
// independently of enforcement, including events committed by another process.
func repairAudits(ctx context.Context, dir string, store *controlplane.Store) {
	ticker := time.NewTicker(gateway.StandingCheckEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if err := gateway.RecordDeviceRevocations(dir, store); err != nil {
				log.Printf("agentssh-gateway: record device revocations: %v", err)
			}
			if err := gateway.RecordEndedActivations(dir, store, now); err != nil {
				log.Printf("agentssh-gateway: record ended activations: %v", err)
			}
		}
	}
}
