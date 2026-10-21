// Command agentssh-server is the AgentSSH remote control plane: it enrolls
// devices, distributes signed inventory/policy bundles, and signs SSH logins
// with identity keys that never leave the server.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/Praeviso/AgentSSH/internal/remote"
	"github.com/Praeviso/AgentSSH/internal/remoteserver"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const (
	envHome   = "AGENTSSH_SERVER_HOME"
	envMaster = "AGENTSSH_SERVER_MASTER_PASSWORD"
)

var version = "dev"

func main() {
	if err := newRootCommand().Execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	var dataDir string
	root := &cobra.Command{
		Use:           "agentssh-server",
		Short:         "AgentSSH remote control plane: device enrollment, config bundles, and remote SSH signing.",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&dataDir, "data", "", "data directory (default $"+envHome+" or ~/.agentssh-server)")
	dir := func() (string, error) {
		if dataDir != "" {
			return filepath.Clean(dataDir), nil
		}
		if env := os.Getenv(envHome); env != "" {
			return filepath.Clean(env), nil
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".agentssh-server"), nil
	}
	root.AddCommand(
		newInitCommand(dir),
		newServeCommand(dir),
		newDeviceCommand(dir),
		newIdentityCommand(dir),
		newConfigCommand(dir),
		newLogCommand(dir),
	)
	return root
}

func readMaster(confirm bool) (string, error) {
	if value := os.Getenv(envMaster); value != "" {
		return value, nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", fmt.Errorf("set %s or run from a terminal to enter the master password", envMaster)
	}
	_, _ = fmt.Fprint(os.Stderr, "Master password: ")
	first, err := term.ReadPassword(fd)
	_, _ = fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if confirm {
		_, _ = fmt.Fprint(os.Stderr, "Repeat master password: ")
		second, err := term.ReadPassword(fd)
		_, _ = fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		if string(first) != string(second) {
			return "", errors.New("passwords do not match")
		}
	}
	if len(first) == 0 {
		return "", errors.New("master password must not be empty")
	}
	return string(first), nil
}

func openStore(dir string) (*remoteserver.Store, error) {
	if !remoteserver.Initialized(dir) {
		return nil, fmt.Errorf("%s is not initialized; run agentssh-server init", dir)
	}
	return remoteserver.OpenStore(filepath.Join(dir, remoteserver.FileDatabase))
}

func newInitCommand(dir func() (string, error)) *cobra.Command {
	return &cobra.Command{Use: "init", Short: "Create encrypted signing keys and the database.", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			d, err := dir()
			if err != nil {
				return err
			}
			master, err := readMaster(true)
			if err != nil {
				return err
			}
			if err := remoteserver.Init(d, master); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Initialized %s\n", d)
			return nil
		}}
}

func newServeCommand(dir func() (string, error)) *cobra.Command {
	var listen string
	var publicURL string
	var bundleTTL time.Duration
	cmd := &cobra.Command{
		Use:   "serve --public-url <https-base> [--listen 127.0.0.1:8080]",
		Short: "Run the control plane API.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := remote.HTTPSBaseURL(publicURL); err != nil {
				return fmt.Errorf("--public-url: %w", err)
			}
			d, err := dir()
			if err != nil {
				return err
			}
			store, err := openStore(d)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close() }()
			master, err := readMaster(false)
			if err != nil {
				return err
			}
			keys, err := remoteserver.Unlock(d, master)
			if err != nil {
				return err
			}
			server := remoteserver.NewServer(store, keys)
			server.BundleTTL = bundleTTL
			handler, err := server.Handler(publicURL)
			if err != nil {
				return err
			}
			httpServer := &http.Server{
				Addr:              listen,
				Handler:           handler,
				ReadHeaderTimeout: 10 * time.Second,
				ReadTimeout:       30 * time.Second,
				WriteTimeout:      30 * time.Second,
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			errCh := make(chan error, 1)
			go func() { errCh <- httpServer.ListenAndServe() }()
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "agentssh-server origin %s for %s\n", listen, publicURL)
			select {
			case err := <-errCh:
				return err
			case <-ctx.Done():
				shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				return httpServer.Shutdown(shutdown)
			}
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "127.0.0.1:8080", "private HTTP origin listen address behind the public HTTPS ingress")
	cmd.Flags().StringVar(&publicURL, "public-url", "", "public HTTPS base (including path prefix)")
	cmd.Flags().DurationVar(&bundleTTL, "bundle-ttl", remoteserver.DefaultBundleTTL, "how long a device may use a bundle it cannot refresh")
	return cmd
}

func newDeviceCommand(dir func() (string, error)) *cobra.Command {
	cmd := &cobra.Command{Use: "device", Short: "Enroll, list, and revoke devices."}

	var name string
	var publicURL string
	var ttl time.Duration
	tokenCmd := &cobra.Command{Use: "token", Short: "Manage enrollment tokens."}
	createCmd := &cobra.Command{
		Use:   "create --name <name>",
		Short: "Create a one-time enrollment token.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(name) == "" {
				return errors.New("--name is required")
			}
			d, err := dir()
			if err != nil {
				return err
			}
			store, err := openStore(d)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close() }()
			pub, err := remoteserver.LoadBundlePublicKey(d)
			if err != nil {
				return err
			}
			token, err := store.CreateEnrollToken(name, publicURL, remote.PublicKeyFingerprint(pub), ttl, time.Now())
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), token.String())
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "One-time HTTPS token for %q, valid %s. On the device run:\n  agentssh remote enroll %s --token <token>\n", name, ttl, token.ServerURL)
			return nil
		},
	}
	createCmd.Flags().StringVar(&name, "name", "", "device name (e.g. alice-laptop)")
	createCmd.Flags().StringVar(&publicURL, "public-url", "", "public HTTPS base bound into the enrollment token")
	createCmd.Flags().DurationVar(&ttl, "ttl", 10*time.Minute, "token lifetime")
	_ = createCmd.MarkFlagRequired("public-url")
	tokenCmd.AddCommand(createCmd)

	lsCmd := &cobra.Command{
		Use:   "ls",
		Short: "List devices.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			d, err := dir()
			if err != nil {
				return err
			}
			store, err := openStore(d)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close() }()
			devices, err := store.Devices()
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintln(w, "ID\tNAME\tSTATUS\tCONFIG\tENROLLED")
			for _, device := range devices {
				cfgVersion := "-"
				if cfg, err := store.Config(device.ID); err == nil {
					cfgVersion = fmt.Sprintf("v%d", cfg.Version)
				}
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", device.ID, device.Name, device.Status, cfgVersion, device.CreatedAt.Local().Format(time.RFC3339))
			}
			return w.Flush()
		},
	}
	revokeCmd := &cobra.Command{
		Use:   "revoke <device-id>",
		Short: "Revoke a device; its next signature or bundle request is refused.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			d, err := dir()
			if err != nil {
				return err
			}
			store, err := openStore(d)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close() }()
			if err := store.RevokeDevice(args[0], time.Now()); err != nil {
				return fmt.Errorf("revoke %s: %w", args[0], err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Revoked %s\n", args[0])
			return nil
		},
	}
	cmd.AddCommand(tokenCmd, lsCmd, revokeCmd)
	return cmd
}

func newIdentityCommand(dir func() (string, error)) *cobra.Command {
	cmd := &cobra.Command{Use: "identity", Short: "Manage SSH identities held by the control plane."}
	createCmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Generate an ed25519 identity and print its authorized_keys line.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			d, err := dir()
			if err != nil {
				return err
			}
			store, err := openStore(d)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close() }()
			recipient, err := remoteserver.LoadRecipient(d)
			if err != nil {
				return err
			}
			identity, err := remoteserver.NewIdentity(args[0], recipient, time.Now())
			if err != nil {
				return err
			}
			if err := store.CreateIdentity(identity); err != nil {
				return fmt.Errorf("create identity %s: %w", args[0], err)
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), identity.PublicKey)
			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "Add this line to ~/.ssh/authorized_keys of the login user on each target host.")
			return nil
		},
	}
	lsCmd := &cobra.Command{
		Use:   "ls",
		Short: "List identities.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			d, err := dir()
			if err != nil {
				return err
			}
			store, err := openStore(d)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close() }()
			identities, err := store.Identities()
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintln(w, "NAME\tSTATUS\tPUBLIC KEY")
			for _, id := range identities {
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\n", id.Name, id.Status, id.PublicKey)
			}
			return w.Flush()
		},
	}
	disableCmd := &cobra.Command{
		Use:   "disable <name>",
		Short: "Stop signing with an identity.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			d, err := dir()
			if err != nil {
				return err
			}
			store, err := openStore(d)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close() }()
			if err := store.DisableIdentity(args[0], time.Now()); err != nil {
				return fmt.Errorf("disable %s: %w", args[0], err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Disabled %s\n", args[0])
			return nil
		},
	}
	cmd.AddCommand(createCmd, lsCmd, disableCmd)
	return cmd
}

func newConfigCommand(dir func() (string, error)) *cobra.Command {
	cmd := &cobra.Command{Use: "config", Short: "Assign inventory and policy to devices."}
	var device, inventoryPath, policyPath string
	pushCmd := &cobra.Command{
		Use:   "push --device <id> --inventory <file> --policy <file>",
		Short: "Validate and assign a device's inventory and policy.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if device == "" || inventoryPath == "" || policyPath == "" {
				return errors.New("--device, --inventory, and --policy are required")
			}
			inv, err := os.ReadFile(inventoryPath)
			if err != nil {
				return err
			}
			pol, err := os.ReadFile(policyPath)
			if err != nil {
				return err
			}
			d, err := dir()
			if err != nil {
				return err
			}
			store, err := openStore(d)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close() }()
			version, err := remoteserver.PushConfig(store, device, string(inv), string(pol), time.Now())
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Pushed configuration v%d to %s\n", version, device)
			return nil
		},
	}
	pushCmd.Flags().StringVar(&device, "device", "", "device id")
	pushCmd.Flags().StringVar(&inventoryPath, "inventory", "", "inventory.yaml to assign")
	pushCmd.Flags().StringVar(&policyPath, "policy", "", "policy.yaml to assign")
	cmd.AddCommand(pushCmd)
	return cmd
}

func newLogCommand(dir func() (string, error)) *cobra.Command {
	var device, host string
	var limit int
	cmd := &cobra.Command{
		Use:   "log [--device <id>] [--host <name>] [--limit N]",
		Short: "Show the signing log.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			d, err := dir()
			if err != nil {
				return err
			}
			store, err := openStore(d)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close() }()
			entries, err := store.SignLog(remoteserver.SignLogFilter{DeviceID: device, Host: host, Limit: limit})
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintln(w, "TIME\tSIGN ID\tDEVICE\tHOST\tIDENTITY\tUSER\tRESULT\tREASON")
			for _, e := range entries {
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", e.TS.Local().Format(time.RFC3339), e.SignID, e.DeviceID, e.Host, dash(e.Identity), dash(e.User), e.Result, dash(e.Reason))
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&device, "device", "", "filter by device id")
	cmd.Flags().StringVar(&host, "host", "", "filter by host")
	cmd.Flags().IntVar(&limit, "limit", 50, "maximum entries")
	return cmd
}

func dash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}
