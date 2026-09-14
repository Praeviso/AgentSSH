package main

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Praeviso/AgentSSH/internal/approval"
	"github.com/Praeviso/AgentSSH/internal/config"
	"github.com/Praeviso/AgentSSH/internal/payload"
	"github.com/spf13/cobra"
)

func newPlanPayloadCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "payload",
		Short: "Inspect explicitly retained local plan payloads.",
	}
	var jsonOutput bool
	listCmd := &cobra.Command{
		Use:   "list [--json]",
		Short: "List retained payload metadata.",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load()
			if err != nil {
				return classifyConfigError(err)
			}
			items, err := planPayloadStore(cfg.Paths).List()
			if err != nil {
				return err
			}
			if jsonOutput {
				return writeJSON(cmd, items)
			}
			for _, item := range items {
				state := "retained"
				if !item.Retained {
					state = "missing"
				}
				ttl := ""
				if !item.ExpireAt.IsZero() {
					ttl = " expires=" + item.ExpireAt.Format(time.RFC3339)
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s %d B %s%s\n", item.Ref.String(), item.Ref.Bytes, state, ttl)
			}
			return nil
		},
	}
	listCmd.Flags().BoolVar(&jsonOutput, "json", false, "emit machine-readable JSON")

	var showJSON bool
	showCmd := &cobra.Command{
		Use:   "show <sha256:hash:bytes> [--json]",
		Short: "Show a bounded text preview and archive inventory for one payload.",
		Args:  exactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return classifyConfigError(err)
			}
			ref, err := payload.ParseRef(args[0])
			if err != nil {
				return mapPayloadError(err)
			}
			result, err := planPayloadStore(cfg.Paths).Show(ref, payload.ShowOptions{})
			if err != nil {
				return mapPayloadError(err)
			}
			if showJSON {
				return writeJSON(cmd, result)
			}
			printPayloadShow(cmd, result)
			return nil
		},
	}
	showCmd.Flags().BoolVar(&showJSON, "json", false, "emit machine-readable JSON")

	var diffJSON bool
	diffCmd := &cobra.Command{
		Use:   "diff <from-ref> <to-ref> [--json]",
		Short: "Diff two retained text payload previews by content hash.",
		Args:  exactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return classifyConfigError(err)
			}
			from, err := payload.ParseRef(args[0])
			if err != nil {
				return mapPayloadError(err)
			}
			to, err := payload.ParseRef(args[1])
			if err != nil {
				return mapPayloadError(err)
			}
			result, err := planPayloadStore(cfg.Paths).Diff(from, to)
			if err != nil {
				return mapPayloadError(err)
			}
			if diffJSON {
				return writeJSON(cmd, result)
			}
			if result.Binary {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), "binary payloads differ by hash; text diff unavailable")
			} else if strings.TrimSpace(result.Text) == "" {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), "no text differences in retained preview")
			} else {
				_, _ = fmt.Fprint(cmd.OutOrStdout(), result.Text)
			}
			if result.Truncated {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), "[diff truncated]")
			}
			return nil
		},
	}
	diffCmd.Flags().BoolVar(&diffJSON, "json", false, "emit machine-readable JSON")

	var removeForce bool
	removeCmd := &cobra.Command{
		Use:   "remove <sha256:hash:bytes> [--force]",
		Short: "Remove one retained payload unless it has active references.",
		Args:  exactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return classifyConfigError(err)
			}
			ref, err := payload.ParseRef(args[0])
			if err != nil {
				return mapPayloadError(err)
			}
			if err := planPayloadStore(cfg.Paths).Remove(ref, removeForce); err != nil {
				return mapPayloadError(err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "removed %s\n", ref.String())
			return nil
		},
	}
	removeCmd.Flags().BoolVar(&removeForce, "force", false, "remove even when active references exist")

	var gcJSON bool
	gcCmd := &cobra.Command{
		Use:   "gc [--json]",
		Short: "Remove expired payloads that have no active references.",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load()
			if err != nil {
				return classifyConfigError(err)
			}
			if err := releaseTerminalPlanPayloadPins(cfg.Paths); err != nil {
				return mapPayloadError(err)
			}
			removed, err := planPayloadStore(cfg.Paths).GC()
			if err != nil {
				return mapPayloadError(err)
			}
			if gcJSON {
				return writeJSON(cmd, removed)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "removed %d expired payload(s)\n", len(removed))
			return nil
		},
	}
	gcCmd.Flags().BoolVar(&gcJSON, "json", false, "emit machine-readable JSON")

	cmd.AddCommand(listCmd, showCmd, diffCmd, removeCmd, gcCmd)
	return cmd
}

func planPayloadStore(paths config.Paths) payload.Store {
	return payload.Store{Dir: paths.PayloadsDir}
}

func resolvePayloadRefs(cfg *config.Config, commands []planCommand) error {
	store := planPayloadStore(cfg.Paths)
	for i := range commands {
		if commands[i].PayloadRef == "" {
			continue
		}
		ref, err := payload.ParseRef(commands[i].PayloadRef)
		if err != nil {
			return mapPayloadError(err)
		}
		data, err := store.Get(ref)
		if err != nil {
			return mapPayloadError(err)
		}
		commands[i].stdin = stdinSpec{sha256: ref.SHA256, bytes: ref.Bytes}
		if len(data) != int(ref.Bytes) {
			return mapPayloadError(payload.ErrCorrupt)
		}
	}
	return nil
}

func saveCommandPayloads(cfg *config.Config, commands []planCommand, retainFor time.Duration, owner string) ([]payload.Ref, error) {
	store := planPayloadStore(cfg.Paths)
	var refs []payload.Ref
	for i := range commands {
		if commands[i].PayloadRef != "" {
			continue
		}
		if commands[i].stdin.sha256 == "" {
			continue
		}
		ref, err := store.PutAndPin(commands[i].stdin.data, payload.PutOptions{
			Name:      commands[i].ID,
			RetainFor: retainFor,
		}, owner)
		if err != nil {
			return refs, mapPayloadError(err)
		}
		commands[i].PayloadRef = ref.String()
		refs = append(refs, ref)
	}
	return refs, nil
}

func pinCommandPayloadRefs(cfg *config.Config, commands []planCommand, owner string) ([]payload.Ref, error) {
	store := planPayloadStore(cfg.Paths)
	seen := map[payload.Ref]bool{}
	var refs []payload.Ref
	for _, command := range commands {
		if command.PayloadRef == "" {
			continue
		}
		ref, err := payload.ParseRef(command.PayloadRef)
		if err != nil {
			return refs, mapPayloadError(err)
		}
		if seen[ref] {
			continue
		}
		if err := store.Pin(ref, owner); err != nil {
			return refs, mapPayloadError(err)
		}
		seen[ref] = true
		refs = append(refs, ref)
	}
	return refs, nil
}

func releasePayloadPins(paths config.Paths, owner string, refs []payload.Ref) {
	if owner == "" {
		return
	}
	store := planPayloadStore(paths)
	seen := map[payload.Ref]bool{}
	for _, ref := range refs {
		if seen[ref] {
			continue
		}
		_ = store.Unpin(ref, owner)
		seen[ref] = true
	}
}

func releasePlanPayloadPins(paths config.Paths, manifest approval.PlanManifest) {
	if manifest.ID == "" || manifest.Review == nil {
		return
	}
	var refs []payload.Ref
	for _, step := range manifest.Review.Steps {
		if step.PayloadRef == "" {
			continue
		}
		ref, err := payload.ParseRef(step.PayloadRef)
		if err == nil {
			refs = append(refs, ref)
		}
	}
	releasePayloadPins(paths, manifest.ID, refs)
}

func releasePlanStatusPayloadPins(paths config.Paths, status approval.PlanStatus) {
	if status.ID == "" || status.Review == nil {
		return
	}
	var refs []payload.Ref
	for _, step := range status.Review.Steps {
		if step.PayloadRef == "" {
			continue
		}
		ref, err := payload.ParseRef(step.PayloadRef)
		if err == nil {
			refs = append(refs, ref)
		}
	}
	releasePayloadPins(paths, status.ID, refs)
}

func releaseTerminalPlanPayloadPins(paths config.Paths) error {
	store := planPayloadStore(paths)
	items, err := store.List()
	if err != nil {
		return err
	}
	seenOwners := map[string]bool{}
	for _, item := range items {
		for _, owner := range item.Pins {
			if !strings.HasPrefix(owner, "pl_") || seenOwners[owner] {
				continue
			}
			seenOwners[owner] = true
			status, err := approvalStore(paths).PlanStatus(owner)
			if err != nil || status.Status == "pending" {
				continue
			}
			releasePlanStatusPayloadPins(paths, status)
		}
	}
	return nil
}

func printPayloadShow(cmd *cobra.Command, result payload.ShowResult) {
	if result.Binary {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "binary payload; text preview unavailable")
	} else {
		_, _ = fmt.Fprint(cmd.OutOrStdout(), result.Text)
		if result.Text != "" && !strings.HasSuffix(result.Text, "\n") {
			_, _ = fmt.Fprintln(cmd.OutOrStdout())
		}
	}
	if result.Truncated {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "[preview truncated]")
	}
	for _, member := range result.Archives {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s member %s %d B %s\n", member.Archive, member.Name, member.Size, member.Mode)
	}
}

func mapPayloadError(err error) error {
	switch {
	case errors.Is(err, payload.ErrInvalidRef),
		errors.Is(err, payload.ErrNotFound),
		errors.Is(err, payload.ErrTooLarge),
		errors.Is(err, payload.ErrTotalTooLarge),
		errors.Is(err, payload.ErrCorrupt),
		errors.Is(err, payload.ErrActiveRef),
		errors.Is(err, payload.ErrUnretained),
		errors.Is(err, payload.ErrUnsupportedTTL):
		return newUsageError("%v", err)
	default:
		return err
	}
}
