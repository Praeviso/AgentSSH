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

// activationSweep is how often serve records windows that ended.
const activationSweep = 30 * time.Second

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
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Activated %s until %s (%s)\n", args[0], a.Until.Local().Format(time.RFC3339), remaining(a.Until, a.SetAt))
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
	cmd.AddCommand(activate, deactivate)
	return cmd
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
	return fmt.Sprintf("until %s (%s left)", a.Until.Local().Format(time.RFC3339), remaining(a.Until, now))
}

// remaining renders the time from now to until, to the minute.
func remaining(until, now time.Time) string {
	d := until.Sub(now).Round(time.Minute)
	if d < time.Minute {
		return "under 1m"
	}
	h, m := int(d.Hours()), int(d.Minutes())%60
	switch {
	case h == 0:
		return fmt.Sprintf("%dm", m)
	case m == 0:
		return fmt.Sprintf("%dh", h)
	}
	return fmt.Sprintf("%dh%dm", h, m)
}

// recordEndedActivations records ended windows until ctx ends, so an ended
// window is in the audit chain even if its device sends nothing more.
func recordEndedActivations(ctx context.Context, dir string, store *controlplane.Store) {
	ticker := time.NewTicker(activationSweep)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if err := gateway.RecordEndedActivations(dir, store, now); err != nil {
				log.Printf("agentssh-gateway: record ended activations: %v", err)
			}
		}
	}
}
