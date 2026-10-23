package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Praeviso/AgentSSH/internal/config"
	"github.com/Praeviso/AgentSSH/internal/managedmode"
	"github.com/Praeviso/AgentSSH/internal/policy"
	"github.com/Praeviso/AgentSSH/internal/remote"
	"github.com/Praeviso/AgentSSH/internal/remoteclient"
	"github.com/spf13/cobra"
)

func newRemoteCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remote",
		Short: "Enroll with and inspect a remote control plane.",
	}
	var token, mode string
	enrollCmd := &cobra.Command{
		Use:   "enroll <url> --token <token> [--mode managed|gateway]",
		Short: "Enroll this machine with an AgentSSH-compatible control plane.",
		Args:  exactArgs(1),
		PersistentPreRunE: func(*cobra.Command, []string) error {
			// The one-time token is the authorization; the TTY keeps an agent
			// from silently re-homing this machine onto another control plane.
			if !stdinIsTerminal() {
				return newUsageError("remote enroll requires an interactive TTY")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRemoteEnroll(cmd, args[0], token, mode)
		},
	}
	enrollCmd.Flags().StringVar(&token, "token", "", "one-time enrollment token from the control plane")
	enrollCmd.Flags().StringVar(&mode, "mode", remote.ModeManaged, "the control plane's mode: managed (agentssh-server) or gateway (agentssh-gateway)")
	_ = enrollCmd.MarkFlagRequired("token")

	var jsonOutput bool
	statusCmd := &cobra.Command{
		Use:   "status [--json]",
		Short: "Show enrollment, device standing, and the active configuration bundle.",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRemoteStatus(cmd, jsonOutput)
		},
	}
	statusCmd.Flags().BoolVar(&jsonOutput, "json", false, "emit machine-readable JSON")

	cmd.AddCommand(
		enrollCmd,
		statusCmd,
		&cobra.Command{
			Use:   "refresh",
			Short: "Fetch the configuration bundle now instead of waiting for the cache to age out.",
			Args:  noArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				return runRemoteRefresh(cmd)
			},
		},
		&cobra.Command{
			Use:               "leave",
			Short:             "Delete this device's credentials and return to local configuration.",
			Args:              noArgs,
			PersistentPreRunE: requireOperator,
			RunE: func(cmd *cobra.Command, _ []string) error {
				return runRemoteLeave(cmd)
			},
		},
	)
	return cmd
}

func remoteManagedHome() bool {
	home, err := config.ResolveHome()
	return err == nil && managedmode.Enrolled(home)
}

func requireEnrolledHome() (string, error) {
	home, err := config.ResolveHome()
	if err != nil {
		return "", err
	}
	if !managedmode.Enrolled(home) {
		return "", newUsageError("this machine is not enrolled with a control plane\n  enroll with: agentssh remote enroll <url> --token <token>")
	}
	return home, nil
}

func runRemoteEnroll(cmd *cobra.Command, serverURL, token, mode string) error {
	if mode != remote.ModeManaged && mode != remote.ModeGateway {
		return newUsageError("--mode must be managed or gateway")
	}
	home, err := config.ResolveHome()
	if err != nil {
		return err
	}
	if _, err := config.EnsureHome(home); err != nil {
		return classifyConfigError(err)
	}
	if managedmode.Enrolled(home) {
		return newUsageError("this machine is already enrolled\n  to switch control planes run: agentssh remote leave")
	}
	state, err := remoteclient.Enroll(cmd.Context(), home, serverURL, token, mode, time.Now())
	var mismatch *remoteclient.ModeMismatchError
	if errors.As(err, &mismatch) {
		return newUsageError("enroll: %v; the token was not used\n  enroll with: agentssh remote enroll %s --token <token> --mode %s", err, serverURL, mismatch.Got)
	}
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	out := cmd.OutOrStdout()
	if state.Gateway() {
		_, _ = fmt.Fprintf(out, "Enrolled as %s with gateway %s\n", state.DeviceID, state.ServerURL)
		_, _ = fmt.Fprintln(out, "The gateway runs, authorizes and audits every command; local inventory.yaml and policy.yaml are now ignored.")
		return nil
	}
	_, _ = fmt.Fprintf(out, "Enrolled as %s with %s\n", state.DeviceID, state.ServerURL)
	session, err := remoteclient.Open(cmd.Context(), home, remoteclient.OpenOptions{Refresh: true})
	var apiErr *remote.APIError
	switch {
	case errors.As(err, &apiErr) && apiErr.Code == remote.CodeNoConfig:
		_, _ = fmt.Fprintln(out, "No configuration assigned yet; ask the control-plane administrator to assign a configuration to "+state.DeviceID)
	case err != nil:
		_, _ = fmt.Fprintf(out, "Configuration not loaded yet: %v\n", err)
	default:
		_, _ = fmt.Fprintf(out, "Configuration v%d loaded: %d %s\n", session.Bundle.Version, len(session.Inventory.Hosts), plural(len(session.Inventory.Hosts), "host", "hosts"))
	}
	_, _ = fmt.Fprintln(out, "Local inventory.yaml is now ignored; deny rules in the local policy.yaml still apply.")
	return nil
}

type remoteStatusJSON struct {
	ServerURL      string `json:"server_url"`
	Mode           string `json:"mode"`
	DeviceID       string `json:"device_id"`
	Device         string `json:"device"`
	DeviceError    string `json:"device_error,omitempty"`
	BundleVersion  int64  `json:"bundle_version,omitempty"`
	BundleFetched  string `json:"bundle_fetched_at,omitempty"`
	BundleNotAfter string `json:"bundle_not_after,omitempty"`
	Hosts          int    `json:"hosts"`
	LocalDeny      int    `json:"local_deny_rules"`
	LocalIgnored   int    `json:"local_ignored_rules"`
}

func runRemoteStatus(cmd *cobra.Command, jsonOutput bool) error {
	home, err := requireEnrolledHome()
	if err != nil {
		return err
	}
	client, err := remoteclient.NewClient(home)
	if err != nil {
		return err
	}
	report := remoteStatusJSON{ServerURL: client.State.ServerURL, Mode: client.State.Mode, DeviceID: client.State.DeviceID}
	ctx, cancel := context.WithTimeout(cmd.Context(), remoteclient.RequestTimeout)
	defer cancel()
	healthy := true
	if status, err := client.Status(ctx); err != nil {
		healthy = false
		report.Device = "unknown"
		if remote.IsRevoked(err) {
			report.Device = remote.DeviceRevoked
		}
		report.DeviceError = err.Error()
	} else {
		report.Device = status.Status
	}
	if client.State.Gateway() {
		return printRemoteStatus(cmd, report, jsonOutput, healthy)
	}
	if bundle, fetched, err := remoteclient.CachedBundle(home); err == nil {
		report.BundleVersion = bundle.Version
		report.BundleFetched = fetched.Local().Format(time.RFC3339)
		report.BundleNotAfter = bundle.NotAfter.Local().Format(time.RFC3339)
		if inv, _, err := remote.ParseManaged(bundle.InventoryYAML, bundle.PolicyYAML, nil); err == nil {
			report.Hosts = len(inv.Hosts)
		}
	}
	local, err := policy.Load(config.NewPaths(home).PolicyFile)
	if err == nil {
		report.LocalIgnored = policy.IgnoredOverlayRules(local)
		report.LocalDeny = countDenyRules(local)
	}

	return printRemoteStatus(cmd, report, jsonOutput, healthy)
}

func printRemoteStatus(cmd *cobra.Command, report remoteStatusJSON, jsonOutput bool, healthy bool) error {
	gateway := report.Mode == remote.ModeGateway
	if jsonOutput {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(data))
	} else {
		out := cmd.OutOrStdout()
		_, _ = fmt.Fprintf(out, "server   %s\n", report.ServerURL)
		_, _ = fmt.Fprintf(out, "mode     %s\n", report.Mode)
		device := report.DeviceID + " (" + report.Device + ")"
		if report.DeviceError != "" && report.Device != remote.DeviceRevoked {
			device += " — " + report.DeviceError
		}
		_, _ = fmt.Fprintf(out, "device   %s\n", device)
		if gateway {
			_, _ = fmt.Fprintln(out, "config   kept on the gateway")
		} else if report.BundleVersion > 0 {
			_, _ = fmt.Fprintf(out, "config   v%d · %d %s · fetched %s · valid until %s\n", report.BundleVersion, report.Hosts, plural(report.Hosts, "host", "hosts"), report.BundleFetched, report.BundleNotAfter)
		} else {
			_, _ = fmt.Fprintln(out, "config   none cached")
		}
		if !gateway {
			local := fmt.Sprintf("%d deny %s", report.LocalDeny, plural(report.LocalDeny, "rule", "rules"))
			if report.LocalIgnored > 0 {
				local += fmt.Sprintf(" · %d non-deny %s ignored", report.LocalIgnored, plural(report.LocalIgnored, "rule", "rules"))
			}
			_, _ = fmt.Fprintf(out, "local    %s\n", local)
		}
	}
	if !healthy {
		return commandExitError{Code: exitRemoteFailed}
	}
	return nil
}

func countDenyRules(cfg policy.Config) int {
	count := 0
	for _, rule := range cfg.Rules {
		if rule.Action == policy.ActionDeny {
			count++
		}
	}
	for _, override := range cfg.HostOverrides {
		for _, rule := range override.Rules {
			if rule.Action == policy.ActionDeny {
				count++
			}
		}
	}
	return count
}

func runRemoteRefresh(cmd *cobra.Command) error {
	home, err := requireEnrolledHome()
	if err != nil {
		return err
	}
	if gatewayHome() {
		return newUsageError("a gateway device has no configuration to refresh: the gateway reads it on every command")
	}
	session, err := remoteclient.Open(cmd.Context(), home, remoteclient.OpenOptions{Refresh: true})
	if err != nil {
		return classifyConfigError(config.RemoteError{Err: err})
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Configuration v%d · %d %s · valid until %s\n",
		session.Bundle.Version, len(session.Inventory.Hosts), plural(len(session.Inventory.Hosts), "host", "hosts"),
		session.Bundle.NotAfter.Local().Format(time.RFC3339))
	return nil
}

func runRemoteLeave(cmd *cobra.Command) error {
	home, err := requireEnrolledHome()
	if err != nil {
		return err
	}
	gateway := gatewayHome()
	if err := remoteclient.Leave(home); err != nil {
		return fmt.Errorf("leave remote control: %w", err)
	}
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Left remote control. Device credentials were deleted; local inventory.yaml and policy.yaml are active again.")
	if gateway {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "The gateway keeps this device's audit; ask its administrator to revoke the device.")
	}
	return nil
}

func plural(n int, one string, many string) string {
	if n == 1 {
		return one
	}
	return many
}
