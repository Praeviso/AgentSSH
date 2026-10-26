package main

import (
	"errors"
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/gateway"
	"github.com/spf13/cobra"
)

// newOAuthCommand lists and revokes OAuth grants: an operator's consent that
// lets an MCP client act as a token device.
func newOAuthCommand(dir func() (string, error)) *cobra.Command {
	cmd := &cobra.Command{Use: "oauth", Short: "List and revoke the OAuth grants that let MCP clients act as token devices."}
	var all bool
	ls := &cobra.Command{
		Use:   "ls",
		Short: "List OAuth grants that are in force (--all for revoked ones too).",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withStore(dir, func(_ string, store *controlplane.Store) error {
				grants, err := gateway.Grants(store)
				if err != nil {
					return err
				}
				tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
				_, _ = fmt.Fprintln(tw, "GRANT\tCLIENT\tDEVICE\tAUTHORIZED\tBY\tSTATUS")
				for _, g := range grants {
					status := "active"
					if !g.RevokedAt.IsZero() {
						if !all {
							continue
						}
						status = "revoked " + g.RevokedAt.Local().Format(time.RFC3339)
					}
					_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", g.ID, g.ClientName, g.DeviceID, g.CreatedAt.Local().Format(time.RFC3339), g.CreatedBy, status)
				}
				return tw.Flush()
			})
		},
	}
	ls.Flags().BoolVar(&all, "all", false, "include revoked grants")
	revoke := &cobra.Command{
		Use:   "revoke <grant-id>",
		Short: "Revoke an OAuth grant: its client's tokens are refused from its next request.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withStore(dir, func(d string, store *controlplane.Store) error {
				revoked, err := gateway.RevokeGrant(d, store, args[0], localOperator(), time.Now())
				switch {
				case errors.Is(err, controlplane.ErrNotFound):
					return fmt.Errorf("revoke %s: no such grant", args[0])
				case err != nil:
					return fmt.Errorf("revoke %s: %w", args[0], err)
				}
				if revoked {
					_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Revoked %s\n", args[0])
				} else {
					_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s was already revoked\n", args[0])
				}
				return nil
			})
		},
	}
	cmd.AddCommand(ls, revoke)
	return cmd
}
