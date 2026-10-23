package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"text/tabwriter"
	"time"

	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/gateway"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const envOperatorPassword = "AGENTSSH_GATEWAY_OPERATOR_PASSWORD"

// readOperatorPassword reads a new operator's password twice from the
// terminal, or from envOperatorPassword for scripts.
func readOperatorPassword() (string, error) {
	if value := os.Getenv(envOperatorPassword); value != "" {
		return value, nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", fmt.Errorf("set %s or run from a terminal to enter the operator's password", envOperatorPassword)
	}
	_, _ = fmt.Fprint(os.Stderr, "Operator password: ")
	first, err := term.ReadPassword(fd)
	_, _ = fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	_, _ = fmt.Fprint(os.Stderr, "Repeat operator password: ")
	second, err := term.ReadPassword(fd)
	_, _ = fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if string(first) != string(second) {
		return "", errors.New("passwords do not match")
	}
	return string(first), nil
}

func newOperatorCommand(dir func() (string, error)) *cobra.Command {
	cmd := &cobra.Command{Use: "operator", Short: "Manage the Web UI's operator accounts."}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "add <name>",
			Short: "Create an operator; they set up two-factor sign-in at first login.",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				password, err := readOperatorPassword()
				if err != nil {
					return err
				}
				return withStore(dir, func(_ string, store *controlplane.Store) error {
					if err := gateway.AddOperator(store, args[0], password, time.Now()); err != nil {
						return err
					}
					_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Added operator %s; they set up two-factor sign-in at their first Web UI login.\n", args[0])
					return nil
				})
			},
		},
		&cobra.Command{
			Use:   "ls",
			Short: "List operators.",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				return withStore(dir, func(_ string, store *controlplane.Store) error {
					operators, err := gateway.Operators(store)
					if err != nil {
						return err
					}
					w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
					_, _ = fmt.Fprintln(w, "NAME\tSTATUS\tTWO-FACTOR\tCREATED")
					for _, op := range operators {
						twoFactor := "not set up"
						if op.TOTPEnrolled {
							twoFactor = "set up"
						}
						_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", op.Name, op.Status, twoFactor, op.CreatedAt.Local().Format(time.RFC3339))
					}
					return w.Flush()
				})
			},
		},
		&cobra.Command{
			Use:   "revoke <name>",
			Short: "Disable an operator and end all their sessions now.",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				return withStore(dir, func(_ string, store *controlplane.Store) error {
					if err := gateway.RevokeOperator(store, args[0], time.Now()); err != nil {
						return err
					}
					_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Revoked operator %s; their sessions have ended.\n", args[0])
					return nil
				})
			},
		},
	)
	return cmd
}

// serveWeb starts the Web UI on its own listener, which serves until ctx
// ends: over TLS with the given certificate, or plain HTTP behind a
// TLS-terminating proxy. Binding and the certificate are checked before it
// returns.
func serveWeb(ctx context.Context, out io.Writer, listen, certFile, keyFile string, handler http.Handler) error {
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	if certFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return fmt.Errorf("--web-cert: %w", err)
		}
		server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("--web-listen: %w", err)
	}
	go func() {
		var err error
		if certFile != "" {
			err = server.ServeTLS(listener, "", "")
		} else {
			err = server.Serve(listener)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("agentssh-gateway: web UI stopped: %v", err)
		}
	}()
	scheme := "https"
	if certFile == "" {
		scheme = "plain http, for a TLS-terminating proxy"
	}
	_, _ = fmt.Fprintf(out, "agentssh-gateway web UI %s (%s)\n", listener.Addr(), scheme)
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	return nil
}
