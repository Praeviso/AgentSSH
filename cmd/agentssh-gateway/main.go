// Command agentssh-gateway is the AgentSSH gateway control plane: it enrolls
// devices and holds their inventory, policy and SSH identities. Unlike
// agentssh-server it never hands a device a signature or a configuration
// bundle; devices forward commands and the gateway authorizes, executes and
// audits them.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/controlplane/admin"
	"github.com/Praeviso/AgentSSH/internal/gateway"
	"github.com/Praeviso/AgentSSH/internal/remote"
	"github.com/spf13/cobra"
)

const (
	envHome   = "AGENTSSH_GATEWAY_HOME"
	envMaster = "AGENTSSH_GATEWAY_MASTER_PASSWORD"
)

var version = "dev"

var program = &admin.Program{
	Name:      "agentssh-gateway",
	Mode:      remote.ModeGateway,
	EnvHome:   envHome,
	EnvMaster: envMaster,
	Init:      gateway.Init,
	OpenStore: func(dir string) (*controlplane.Store, error) {
		return gateway.OpenStore(filepath.Join(dir, gateway.FileDatabase))
	},
	EnrollHint:   "agentssh remote enroll %s --mode gateway --token <token>",
	RevokeShort:  "Revoke a device; its next request is refused.",
	DisableShort: "Stop connecting with an identity.",
}

func main() {
	if err := newRootCommand().Execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "agentssh-gateway",
		Short:         "AgentSSH gateway control plane: device enrollment, server-side inventory, policy and SSH identities.",
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
		newAuditCommand(dir),
	)
	return root
}

func newServeCommand(dir func() (string, error)) *cobra.Command {
	var listen string
	var publicURL string
	var execTimeout time.Duration
	var maxConcurrent int
	var runRetention time.Duration
	var runMaxBytes int64
	var runQuotaBytes int64
	cmd := &cobra.Command{
		Use:   "serve --public-url <https-base> [--listen 127.0.0.1:8080]",
		Short: "Run the gateway API.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := remote.HTTPSBaseURL(publicURL); err != nil {
				return fmt.Errorf("--public-url: %w", err)
			}
			d, err := dir()
			if err != nil {
				return err
			}
			store, err := program.Open(d)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close() }()
			master, err := program.ReadMaster(false)
			if err != nil {
				return err
			}
			keys, err := controlplane.Unlock(d, master)
			if err != nil {
				return err
			}
			server := gateway.NewServer(d, store, keys)
			server.ExecTimeout = execTimeout
			server.MaxConcurrentPerDevice = maxConcurrent
			server.RunRetention = runRetention
			server.RunMaxBytes = runMaxBytes
			server.RunQuotaBytes = runQuotaBytes
			handler, err := server.Handler(publicURL)
			if err != nil {
				return err
			}
			return program.Serve(cmd.Context(), cmd.OutOrStdout(), listen, publicURL, handler)
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "127.0.0.1:8080", "private HTTP origin listen address behind the public HTTPS ingress")
	cmd.Flags().StringVar(&publicURL, "public-url", "", "public HTTPS base (including path prefix)")
	cmd.Flags().DurationVar(&execTimeout, "exec-timeout", gateway.DefaultExecTimeout, "longest a single execution may run")
	cmd.Flags().IntVar(&maxConcurrent, "max-concurrent", gateway.DefaultMaxConcurrentPerDevice, "executions one device may run at once")
	cmd.Flags().DurationVar(&runRetention, "run-retention", gateway.DefaultRunRetention, "how long a finished run's output stays reattachable")
	cmd.Flags().Int64Var(&runMaxBytes, "run-max-bytes", gateway.DefaultRunMaxBytes, "spooled output kept per run; beyond it the result is marked truncated")
	cmd.Flags().Int64Var(&runQuotaBytes, "run-quota-bytes", gateway.DefaultRunQuotaBytes, "finished-run output kept per device; the oldest runs are evicted first")
	return cmd
}

func newAuditCommand(dir func() (string, error)) *cobra.Command {
	cmd := &cobra.Command{Use: "audit", Short: "Inspect the gateway's audit chain."}
	cmd.AddCommand(&cobra.Command{
		Use:   "verify",
		Short: "Recompute the audit hash chain.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			d, err := dir()
			if err != nil {
				return err
			}
			if err := program.CheckDir(d); err != nil {
				return err
			}
			result, err := audit.NewStore(filepath.Join(d, gateway.FileAudit)).Verify()
			if err != nil {
				return err
			}
			if !result.OK {
				return fmt.Errorf("audit chain broken · seq=%d · reason=%s", result.BrokenSeq, result.Reason)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "audit chain ok · records=%d\n", result.Count)
			return nil
		},
	})
	return cmd
}
