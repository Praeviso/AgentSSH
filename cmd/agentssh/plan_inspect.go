package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Praeviso/AgentSSH/internal/approval"
	"github.com/Praeviso/AgentSSH/internal/config"
	"github.com/Praeviso/AgentSSH/internal/payload"
	"github.com/spf13/cobra"
)

func newPlanInspectCommand() *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "inspect <plan_id> [--json]",
		Short: "Inspect the immutable full-plan review snapshot.",
		Args:  exactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return classifyConfigError(err)
			}
			manifest, err := approvalStore(cfg.Paths).GetPlan(args[0])
			if err != nil {
				return mapPlanError(err)
			}
			if jsonOutput {
				return writeJSON(cmd, manifest)
			}
			printPlanReview(cmd, cfg.Paths, manifest)
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "emit machine-readable JSON")
	return cmd
}

func printPlanReview(cmd *cobra.Command, paths config.Paths, manifest approval.PlanManifest) {
	out := cmd.OutOrStdout()
	title := manifest.Metadata.Title
	if title == "" {
		title = manifest.ID
	}
	_, _ = fmt.Fprintf(out, "plan %s · %s\n", manifest.ID, printable(title, 160))
	if manifest.ExecutionID != "" {
		_, _ = fmt.Fprintf(out, "execution %s\n", manifest.ExecutionID)
	}
	if manifest.ReviewSHA256 != "" {
		_, _ = fmt.Fprintf(out, "review sha256=%s\n", manifest.ReviewSHA256)
	}
	_, _ = fmt.Fprintln(out, "submitter descriptions (unverified):")
	printMetadataLine(out, "version", manifest.Metadata.Version)
	printMetadataLine(out, "revision", manifest.Metadata.Revision)
	printMetadataLine(out, "description", manifest.Metadata.Description)
	printMetadataLine(out, "impact", manifest.Metadata.Impact)
	printMetadataLine(out, "recovery", manifest.Metadata.Recovery)
	if manifest.Review == nil {
		_, _ = fmt.Fprintln(out, "legacy plan: no immutable review snapshot")
		return
	}
	_, _ = fmt.Fprintln(out, "recorded facts from parsed command and payload identity:")
	store := planPayloadStore(paths)
	for _, step := range manifest.Review.Steps {
		_, _ = fmt.Fprintf(out, "%d. %s %s\n", step.Seq, printable(step.ID, 80), printable(step.Status, 40))
		_, _ = fmt.Fprintf(out, "   cmd: %s\n", printableLiteral(step.Cmd, 0))
		if step.Name != "" {
			_, _ = fmt.Fprintf(out, "   submitter step name (unverified): %s\n", printable(step.Name, 80))
		}
		if step.Phase != "" || step.OnFailure != "" {
			_, _ = fmt.Fprintf(out, "   phase/on_failure: %s %s\n", printable(step.Phase, 40), printable(step.OnFailure, 40))
		}
		if step.ApprovalID != "" {
			_, _ = fmt.Fprintf(out, "   approval %s\n", step.ApprovalID)
		}
		if step.StdinSHA256 != "" {
			_, _ = fmt.Fprintf(out, "   stdin %d B sha256=%s\n", step.StdinBytes, step.StdinSHA256)
		}
		if step.PayloadRef != "" {
			state := "retained"
			ref, err := payload.ParseRef(step.PayloadRef)
			if err != nil {
				state = "invalid-ref"
			} else if _, err := store.Get(ref); err != nil {
				state = "missing-or-corrupt"
			}
			_, _ = fmt.Fprintf(out, "   payload %s %s\n", printable(step.PayloadRef, 120), state)
		} else if step.StdinSHA256 != "" {
			_, _ = fmt.Fprintln(out, "   payload not retained")
		}
	}
}

func printMetadataLine(out interface{ Write([]byte) (int, error) }, label string, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	_, _ = fmt.Fprintf(out, "%s: %s\n", label, printable(value, 1000))
}

func printable(value string, limit int) string {
	value = cleanPrintable(value)
	value = strings.Join(strings.Fields(value), " ")
	runes := []rune(value)
	if limit > 0 && len(runes) > limit {
		return string(runes[:limit]) + "..."
	}
	return value
}

func printableLiteral(value string, limit int) string {
	value = strconv.QuoteToGraphic(stripPrintableEscapes(value))
	runes := []rune(value)
	if limit > 0 && len(runes) > limit {
		return string(runes[:limit]) + "..."
	}
	return value
}

func cleanPrintable(value string) string {
	value = stripPrintableEscapes(value)
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t' || r == '\r':
			return ' '
		case r < 0x20 || r == 0x7f:
			return -1
		default:
			return r
		}
	}, value)
}

func stripPrintableEscapes(value string) string {
	var b strings.Builder
	escapeState := 0
	for _, r := range value {
		switch escapeState {
		case 1:
			if r == '[' {
				escapeState = 2
				continue
			}
			escapeState = 0
		case 2:
			if r >= '@' && r <= '~' {
				escapeState = 0
			}
			continue
		}
		if r == 0x1b {
			escapeState = 1
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
