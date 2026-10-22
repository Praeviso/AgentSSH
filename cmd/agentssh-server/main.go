// Command agentssh-server is the AgentSSH remote control plane: it enrolls
// devices, distributes signed inventory/policy bundles, and signs SSH logins
// with identity keys that never leave the server.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/controlplane/admin"
	"github.com/Praeviso/AgentSSH/internal/remote"
	"github.com/Praeviso/AgentSSH/internal/remoteserver"
	"github.com/spf13/cobra"
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

var program = &admin.Program{
	Name:      "agentssh-server",
	Mode:      remote.ModeManaged,
	EnvHome:   envHome,
	EnvMaster: envMaster,
	Init:      remoteserver.Init,
	OpenStore: func(dir string) (*controlplane.Store, error) {
		store, err := remoteserver.OpenStore(filepath.Join(dir, remoteserver.FileDatabase))
		if err != nil {
			return nil, err
		}
		return store.Store, nil
	},
	EnrollHint:   "agentssh remote enroll %s --token <token>",
	RevokeShort:  "Revoke a device; its next signature or bundle request is refused.",
	DisableShort: "Stop signing with an identity.",
}

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "agentssh-server",
		Short:         "AgentSSH remote control plane: device enrollment, config bundles, and remote SSH signing.",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	dir := program.DataDir(root)
	root.AddCommand(
		program.InitCommand(dir),
		newServeCommand(dir),
		program.DeviceCommand(dir),
		program.IdentityCommand(dir),
		program.ConfigCommand(dir),
		newLogCommand(dir),
	)
	return root
}

// openStore opens the managed store, including the signing log.
func openStore(dir string) (*remoteserver.Store, error) {
	if err := program.CheckDir(dir); err != nil {
		return nil, err
	}
	return remoteserver.OpenStore(filepath.Join(dir, remoteserver.FileDatabase))
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
			master, err := program.ReadMaster(false)
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
			return program.Serve(cmd.Context(), cmd.OutOrStdout(), listen, publicURL, handler)
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "127.0.0.1:8080", "private HTTP origin listen address behind the public HTTPS ingress")
	cmd.Flags().StringVar(&publicURL, "public-url", "", "public HTTPS base (including path prefix)")
	cmd.Flags().DurationVar(&bundleTTL, "bundle-ttl", remoteserver.DefaultBundleTTL, "how long a device may use a bundle it cannot refresh")
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
