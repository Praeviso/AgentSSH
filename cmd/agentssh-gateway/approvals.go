package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"

	"github.com/Praeviso/AgentSSH/internal/approval"
	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/gateway"
	"github.com/spf13/cobra"
)

// localOperator names a decision made on the gateway host in the audit.
func localOperator() string {
	name := os.Getenv("USER")
	if u, err := user.Current(); err == nil {
		name = u.Username
	}
	return "local:" + name
}

// withStore checks the data directory and opens its store for run.
func withStore(dir func() (string, error), run func(d string, store *controlplane.Store) error) error {
	d, err := dir()
	if err != nil {
		return err
	}
	store, err := program.Open(d)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()
	return run(d, store)
}

func writeJSON(out io.Writer, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(data))
	return err
}

// grantScope reads exactly one of the scope flags.
func grantScope(once, session, task bool, host ...bool) (approval.Scope, error) {
	var scopes []approval.Scope
	if len(host) > 0 && host[0] {
		scopes = append(scopes, approval.ScopeHost)
	}
	if once {
		scopes = append(scopes, approval.ScopeOnce)
	}
	if session {
		scopes = append(scopes, approval.ScopeSession)
	}
	if task {
		scopes = append(scopes, approval.ScopeTask)
	}
	if len(scopes) != 1 {
		return "", errors.New("grant requires exactly one scope flag")
	}
	return scopes[0], nil
}

func addScopeFlags(cmd *cobra.Command, once, session, task *bool, what string) {
	cmd.Flags().BoolVar(once, "once", false, "approve "+what+" once")
	cmd.Flags().BoolVar(session, "session", false, "approve "+what+" for the requesting session")
	cmd.Flags().BoolVar(task, "task", false, "approve "+what+"'s bounded task profile for the session")
}

// addDeviceFlag lets the operator name the device an ID belongs to; a lookup
// that more than one device answers is refused without it.
func addDeviceFlag(cmd *cobra.Command, deviceID *string) {
	cmd.Flags().StringVar(deviceID, "device", "", "the device the ID belongs to (agentssh-gateway device ls)")
}

func newApprovalCommand(dir func() (string, error)) *cobra.Command {
	cmd := &cobra.Command{Use: "approval", Short: "Review and decide devices' approval requests."}
	var deviceID string

	var jsonOutput bool
	lsCmd := &cobra.Command{
		Use:   "ls [--json]",
		Short: "List pending approval requests of every device.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withStore(dir, func(d string, _ *controlplane.Store) error {
				requests, err := gateway.ListApprovals(d)
				if err != nil {
					return err
				}
				if jsonOutput {
					if requests == nil {
						requests = []gateway.DeviceApproval{}
					}
					return writeJSON(cmd.OutOrStdout(), requests)
				}
				out := cmd.OutOrStdout()
				if len(requests) == 0 {
					_, _ = fmt.Fprintln(out, "(none)")
				}
				for _, req := range requests {
					line := fmt.Sprintf("%s device=%s host=%s session=%s cmd=%s matcher=%s", req.ID, req.DeviceID, req.Host, req.SessionID, strconv.Quote(req.Cmd), strconv.Quote(req.Candidate.Regex))
					if req.StdinSHA256 != "" {
						line += fmt.Sprintf(" stdin=%s:%d", req.StdinSHA256, req.StdinBytes)
					}
					if req.PlanID != "" {
						line += fmt.Sprintf(" plan=%s (%d/%d)", req.PlanID, req.PlanSeq, req.PlanTotal)
					}
					_, _ = fmt.Fprintln(out, line)
				}
				return nil
			})
		},
	}
	lsCmd.Flags().BoolVar(&jsonOutput, "json", false, "emit machine-readable JSON")

	showCmd := &cobra.Command{
		Use:   "show <approval-id>",
		Short: "Show one approval request and its status as JSON.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withStore(dir, func(d string, _ *controlplane.Store) error {
				owner, status, err := gateway.ApprovalStatus(d, deviceID, args[0])
				if err != nil {
					return err
				}
				return writeJSON(cmd.OutOrStdout(), struct {
					DeviceID string `json:"device_id"`
					approval.StatusResult
				}{owner, status})
			})
		},
	}

	var once, session, task, host bool
	grantCmd := &cobra.Command{
		Use:   "grant <approval-id> --once|--session|--task|--host",
		Short: "Approve a request; the device's rerun then runs.",
		Long:  "Approve a request. --host adds an allow rule for the command's matcher to the device's policy and pushes it as a new configuration version; the policy is re-rendered, so comments and formatting in it are not kept.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			scope, err := grantScope(once, session, task, host)
			if err != nil {
				return err
			}
			return withStore(dir, func(d string, store *controlplane.Store) error {
				decided, _, err := gateway.DecideApproval(d, store, gateway.Decider{Operator: localOperator(), DeviceID: deviceID}, args[0], approval.VerdictApproved, scope)
				if err != nil {
					return err
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "approved %s for %s scope=%s\n", args[0], decided, scope)
				return nil
			})
		},
	}
	addScopeFlags(grantCmd, &once, &session, &task, "the command")
	grantCmd.Flags().BoolVar(&host, "host", false, "approve the command's matcher on this host permanently, as a rule in the device's policy")

	denyCmd := &cobra.Command{
		Use:   "deny <approval-id>",
		Short: "Deny a request.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withStore(dir, func(d string, store *controlplane.Store) error {
				decided, _, err := gateway.DecideApproval(d, store, gateway.Decider{Operator: localOperator(), DeviceID: deviceID}, args[0], approval.VerdictDenied, "")
				if err != nil {
					return err
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "denied %s for %s\n", args[0], decided)
				return nil
			})
		},
	}
	for _, sub := range []*cobra.Command{showCmd, grantCmd, denyCmd} {
		addDeviceFlag(sub, &deviceID)
	}
	cmd.AddCommand(lsCmd, showCmd, grantCmd, denyCmd)
	return cmd
}

func newPlanCommand(dir func() (string, error)) *cobra.Command {
	cmd := &cobra.Command{Use: "plan", Short: "Review and decide devices' submitted plans."}
	var deviceID string

	var jsonOutput bool
	showCmd := &cobra.Command{
		Use:   "show <plan-id> [--json]",
		Short: "Show a plan's review and the commands awaiting a decision.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withStore(dir, func(d string, _ *controlplane.Store) error {
				owner, status, err := gateway.PlanStatus(d, deviceID, args[0])
				if err != nil {
					return err
				}
				if jsonOutput {
					return writeJSON(cmd.OutOrStdout(), struct {
						DeviceID string `json:"device_id"`
						approval.PlanStatus
					}{owner, status})
				}
				printPlan(cmd.OutOrStdout(), owner, status)
				return nil
			})
		},
	}
	showCmd.Flags().BoolVar(&jsonOutput, "json", false, "emit machine-readable JSON")

	var once, session, task bool
	grantCmd := &cobra.Command{
		Use:   "grant <plan-id> --once|--session|--task",
		Short: "Approve every pending command of a plan.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			scope, err := grantScope(once, session, task)
			if err != nil {
				return err
			}
			return withStore(dir, func(d string, store *controlplane.Store) error {
				decided, results, err := gateway.DecidePlan(d, store, gateway.Decider{Operator: localOperator(), DeviceID: deviceID}, args[0], approval.VerdictApproved, scope)
				if err != nil {
					return err
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "plan %s for %s: approved scope=%s %d command(s)\n", args[0], decided, scope, len(results))
				return nil
			})
		},
	}
	addScopeFlags(grantCmd, &once, &session, &task, "each command")

	denyCmd := &cobra.Command{
		Use:   "deny <plan-id>",
		Short: "Deny every pending command of a plan.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withStore(dir, func(d string, store *controlplane.Store) error {
				decided, results, err := gateway.DecidePlan(d, store, gateway.Decider{Operator: localOperator(), DeviceID: deviceID}, args[0], approval.VerdictDenied, "")
				if err != nil {
					return err
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "plan %s for %s: denied %d command(s)\n", args[0], decided, len(results))
				return nil
			})
		},
	}
	for _, sub := range []*cobra.Command{showCmd, grantCmd, denyCmd} {
		addDeviceFlag(sub, &deviceID)
	}
	cmd.AddCommand(showCmd, grantCmd, denyCmd)
	return cmd
}

// printPlan shows what the operator decides on: the commands of the plan's
// requests, which are what a grant authorizes, then the device's review.
// Device-supplied text is quoted, so it cannot write to the terminal.
func printPlan(out io.Writer, deviceID string, status approval.PlanStatus) {
	_, _ = fmt.Fprintf(out, "plan %s · %s · device %s · host %s · session %s\n", status.ID, status.Status, deviceID, status.Host, status.SessionID)
	meta := status.Metadata
	for _, field := range []struct{ name, value string }{
		{"title", meta.Title}, {"version", meta.Version}, {"revision", meta.Revision},
		{"description", meta.Description}, {"impact", meta.Impact}, {"recovery", meta.Recovery},
	} {
		if field.value != "" {
			_, _ = fmt.Fprintf(out, "%-12s %s\n", field.name, strconv.Quote(field.value))
		}
	}
	_, _ = fmt.Fprintf(out, "approved %d · denied %d · pending %d\n", status.Approved, status.Denied, status.Pending)
	for _, member := range status.Members {
		line := "  " + member.ApprovalID + " " + member.Status
		if member.Request != nil {
			line += " · " + strconv.Quote(member.Request.Cmd)
			if member.Request.StdinSHA256 != "" {
				line += fmt.Sprintf(" · stdin %s:%d", member.Request.StdinSHA256, member.Request.StdinBytes)
			}
		}
		_, _ = fmt.Fprintln(out, line)
	}
	if status.Review != nil && len(status.Review.Steps) > 0 {
		_, _ = fmt.Fprintln(out, "steps (as the device described them):")
		for _, step := range status.Review.Steps {
			_, _ = fmt.Fprintf(out, "  %d. %s · %s\n", step.Seq, strconv.Quote(step.Status), strconv.Quote(step.Cmd))
		}
	}
}
