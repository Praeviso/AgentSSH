// Package admin is the operator command scaffolding shared by the control-plane
// binaries: data-directory and master-password handling, init, device,
// identity and configuration commands, and the serve loop.
package admin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/remote"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// Program describes one control-plane binary.
type Program struct {
	// Name is the binary name, used for the default data directory and hints.
	Name string
	// Mode is the control-plane mode the binary runs (remote.Mode*).
	Mode string
	// EnvHome and EnvMaster name the data-directory and master-password
	// environment variables.
	EnvHome, EnvMaster string
	// Init initializes a data directory for this mode.
	Init func(dir, master string) error
	// OpenStore opens this mode's database in an initialized data directory.
	OpenStore func(dir string) (*controlplane.Store, error)
	// EnrollHint is printed after a token is created; %s is the public URL.
	EnrollHint string
	// RevokeShort and DisableShort describe what revoking a device and
	// disabling an identity stop in this mode.
	RevokeShort, DisableShort string
	// DeviceColumn, if set, adds a column headed DeviceColumnHeader to
	// device ls, with a mode's own standing for each device.
	DeviceColumnHeader string
	DeviceColumn       func(store *controlplane.Store, device controlplane.Device, now time.Time) string
}

// DataDir registers --data on root and returns its resolver.
func (p *Program) DataDir(root *cobra.Command) func() (string, error) {
	var dataDir string
	root.PersistentFlags().StringVar(&dataDir, "data", "", "data directory (default $"+p.EnvHome+" or ~/."+p.Name+")")
	return func() (string, error) {
		if dataDir != "" {
			return filepath.Clean(dataDir), nil
		}
		if env := os.Getenv(p.EnvHome); env != "" {
			return filepath.Clean(env), nil
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, "."+p.Name), nil
	}
}

// ReadMaster reads the master password from the environment or the terminal.
func (p *Program) ReadMaster(confirm bool) (string, error) {
	if value := os.Getenv(p.EnvMaster); value != "" {
		return value, nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", fmt.Errorf("set %s or run from a terminal to enter the master password", p.EnvMaster)
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

// CheckDir refuses a data directory that is uninitialized or belongs to the
// other mode: one data directory serves exactly one mode.
func (p *Program) CheckDir(dir string) error {
	if !controlplane.Initialized(dir) {
		return fmt.Errorf("%s is not initialized; run %s init", dir, p.Name)
	}
	mode, err := controlplane.Mode(dir)
	if err != nil {
		return err
	}
	if mode != p.Mode {
		return fmt.Errorf("%s holds a %s control plane; %s serves only %s mode", dir, mode, p.Name, p.Mode)
	}
	return nil
}

// Open checks dir and opens its store.
func (p *Program) Open(dir string) (*controlplane.Store, error) {
	if err := p.CheckDir(dir); err != nil {
		return nil, err
	}
	return p.OpenStore(dir)
}

func (p *Program) withStore(dir func() (string, error), run func(d string, store *controlplane.Store) error) error {
	d, err := dir()
	if err != nil {
		return err
	}
	store, err := p.Open(d)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()
	return run(d, store)
}

// InitCommand creates the encrypted keys and the database.
func (p *Program) InitCommand(dir func() (string, error)) *cobra.Command {
	return &cobra.Command{Use: "init", Short: "Create encrypted signing keys and the database.", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			d, err := dir()
			if err != nil {
				return err
			}
			master, err := p.ReadMaster(true)
			if err != nil {
				return err
			}
			if err := p.Init(d, master); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Initialized %s\n", d)
			return nil
		}}
}

// DeviceCommand manages enrollment tokens and devices.
func (p *Program) DeviceCommand(dir func() (string, error)) *cobra.Command {
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
			return p.withStore(dir, func(d string, store *controlplane.Store) error {
				pub, err := controlplane.LoadBundlePublicKey(d)
				if err != nil {
					return err
				}
				token, err := store.CreateEnrollToken(name, publicURL, remote.PublicKeyFingerprint(pub), ttl, time.Now())
				if err != nil {
					return err
				}
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), token.String())
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "One-time HTTPS token for %q, valid %s. On the device run:\n  "+p.EnrollHint+"\n", name, ttl, token.ServerURL)
				return nil
			})
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
			return p.withStore(dir, func(_ string, store *controlplane.Store) error {
				devices, err := store.Devices()
				if err != nil {
					return err
				}
				w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
				header := "ID\tNAME\tSTATUS\tCONFIG\tENROLLED"
				if p.DeviceColumn != nil {
					header += "\t" + p.DeviceColumnHeader
				}
				_, _ = fmt.Fprintln(w, header)
				now := time.Now()
				for _, device := range devices {
					cfgVersion := "-"
					if cfg, err := store.Config(device.ID); err == nil {
						cfgVersion = fmt.Sprintf("v%d", cfg.Version)
					}
					row := fmt.Sprintf("%s\t%s\t%s\t%s\t%s", device.ID, device.Name, device.Status, cfgVersion, device.CreatedAt.Local().Format(time.RFC3339))
					if p.DeviceColumn != nil {
						row += "\t" + p.DeviceColumn(store, device, now)
					}
					_, _ = fmt.Fprintln(w, row)
				}
				return w.Flush()
			})
		},
	}
	revokeCmd := &cobra.Command{
		Use:   "revoke <device-id>",
		Short: p.RevokeShort,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return p.withStore(dir, func(_ string, store *controlplane.Store) error {
				if err := store.RevokeDevice(args[0], time.Now()); err != nil {
					return fmt.Errorf("revoke %s: %w", args[0], err)
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Revoked %s\n", args[0])
				return nil
			})
		},
	}
	cmd.AddCommand(tokenCmd, lsCmd, revokeCmd)
	return cmd
}

// IdentityCommand manages the control plane's SSH identities.
func (p *Program) IdentityCommand(dir func() (string, error)) *cobra.Command {
	cmd := &cobra.Command{Use: "identity", Short: "Manage SSH identities held by the control plane."}
	createCmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Generate an ed25519 identity and print its authorized_keys line.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return p.withStore(dir, func(d string, store *controlplane.Store) error {
				recipient, err := controlplane.LoadRecipient(d)
				if err != nil {
					return err
				}
				identity, err := controlplane.NewIdentity(args[0], recipient, time.Now())
				if err != nil {
					return err
				}
				if err := store.CreateIdentity(identity); err != nil {
					return fmt.Errorf("create identity %s: %w", args[0], err)
				}
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), identity.PublicKey)
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "Add this line to ~/.ssh/authorized_keys of the login user on each target host.")
				return nil
			})
		},
	}
	lsCmd := &cobra.Command{
		Use:   "ls",
		Short: "List identities.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return p.withStore(dir, func(_ string, store *controlplane.Store) error {
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
			})
		},
	}
	disableCmd := &cobra.Command{
		Use:   "disable <name>",
		Short: p.DisableShort,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return p.withStore(dir, func(_ string, store *controlplane.Store) error {
				if err := store.DisableIdentity(args[0], time.Now()); err != nil {
					return fmt.Errorf("disable %s: %w", args[0], err)
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Disabled %s\n", args[0])
				return nil
			})
		},
	}
	cmd.AddCommand(createCmd, lsCmd, disableCmd)
	return cmd
}

// ConfigCommand assigns per-device inventory and policy.
func (p *Program) ConfigCommand(dir func() (string, error)) *cobra.Command {
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
			return p.withStore(dir, func(_ string, store *controlplane.Store) error {
				version, err := controlplane.PushConfig(store, device, string(inv), string(pol), time.Now())
				if err != nil {
					return err
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Pushed configuration v%d to %s\n", version, device)
				return nil
			})
		},
	}
	pushCmd.Flags().StringVar(&device, "device", "", "device id")
	pushCmd.Flags().StringVar(&inventoryPath, "inventory", "", "inventory.yaml to assign")
	pushCmd.Flags().StringVar(&policyPath, "policy", "", "policy.yaml to assign")
	cmd.AddCommand(pushCmd)
	return cmd
}

// Serve runs handler on the private HTTP origin until ctx ends or the server
// fails.
func (p *Program) Serve(ctx context.Context, out io.Writer, listen, publicURL string, handler http.Handler) error {
	httpServer := &http.Server{
		Addr:              listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)
	go func() { errCh <- httpServer.ListenAndServe() }()
	_, _ = fmt.Fprintf(out, "%s origin %s for %s\n", p.Name, listen, publicURL)
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return httpServer.Shutdown(shutdown)
	}
}
