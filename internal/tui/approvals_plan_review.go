package tui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Praeviso/AgentSSH/internal/approval"
	"github.com/Praeviso/AgentSSH/internal/payload"
	"github.com/charmbracelet/lipgloss"
)

func (s approvalsSection) planReviewView(width int) string {
	req, ok := s.selected()
	if !ok || req.PlanID == "" {
		return s.chooserLine()
	}
	status, err := s.pendingStore().PlanStatus(req.PlanID)
	if err != nil {
		return s.styles.err.Render(cleanReviewText(err.Error(), width)) + "\n" + s.chooserLine()
	}
	lines := s.planReviewLines(status, width)
	count := maxInt(1, s.h-8)
	start := minInt(s.previewOffset, maxInt(0, len(lines)-count))
	end := minInt(len(lines), start+count)
	return s.styles.header.Render("Review plan "+shortPlanID(req.PlanID)) + "\n" +
		strings.Join(lines[start:end], "\n") + "\n" +
		s.styles.dim.Render(fmt.Sprintf("%d-%d of %d lines · j/k scroll · v preview · n/p payload · CLI: plan inspect %s", start+1, end, len(lines), req.PlanID)) + "\n" +
		s.chooserLine()
}

func (s approvalsSection) planReviewLines(status approval.PlanStatus, width int) []string {
	var lines []string
	if status.ReviewSHA256 != "" {
		lines = append(lines, s.styles.dim.Render(cleanReviewText("review sha256="+status.ReviewSHA256, width)))
	}
	lines = append(lines, s.styles.dim.Render(cleanReviewText("single-row decisions use the original pending request context; returned plan ids can be reviewed with plan inspect/grant", width)))
	if status.Review == nil {
		lines = append(lines, s.styles.dim.Render(cleanReviewText("legacy plan: no immutable review snapshot", width)))
		for _, member := range status.Members {
			if member.Request == nil {
				continue
			}
			lines = append(lines, cleanReviewText(member.Request.Cmd, width))
		}
		return lines
	}
	meta := status.Review.Metadata
	var metaLines []string
	for _, line := range []string{
		meta.Title,
		"version: " + meta.Version,
		"revision: " + meta.Revision,
		"description: " + meta.Description,
		"impact: " + meta.Impact,
		"recovery: " + meta.Recovery,
	} {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasSuffix(line, ":") {
			continue
		}
		metaLines = append(metaLines, s.styles.dim.Render(cleanReviewText(line, width)))
	}
	if len(metaLines) > 0 {
		lines = append(lines, s.styles.dim.Render(cleanReviewText("submitter descriptions (unverified):", width)))
		lines = append(lines, metaLines...)
	}
	if s.payloadPreview {
		lines = append(lines, s.payloadPreviewText...)
	}
	lines = append(lines, s.styles.dim.Render(cleanReviewText("recorded facts from parsed command and payload identity:", width)))
	for i, step := range status.Review.Steps {
		if i >= 200 {
			lines = append(lines, s.styles.dim.Render(cleanReviewText("review truncated after 200 steps", width)))
			break
		}
		head := fmt.Sprintf("%d. %s · %s", step.Seq, step.ID, step.Status)
		lines = append(lines, cleanReviewText(head, width))
		if step.Name != "" {
			lines = append(lines, s.styles.dim.Render(cleanReviewText("  submitter step name (unverified): "+step.Name, width)))
		}
		for _, line := range wrapReviewText("  cmd: "+literalReviewText(step.Cmd), width) {
			lines = append(lines, s.styles.dim.Render(line))
		}
		if step.StdinSHA256 != "" {
			lines = append(lines, s.styles.dim.Render(cleanReviewText(fmt.Sprintf("  stdin %d B sha256=%s", step.StdinBytes, step.StdinSHA256), width)))
		}
		if step.PayloadRef != "" {
			state := "payload retained by reference; press v for bounded preview"
			if !step.PayloadRetained {
				state = "payload reference recorded but not marked retained"
			}
			lines = append(lines, s.styles.dim.Render(cleanReviewText("  payload "+step.PayloadRef+" · "+state, width)))
		} else if step.StdinSHA256 != "" {
			lines = append(lines, s.styles.dim.Render(cleanReviewText("  payload not retained", width)))
		}
		if step.ApprovalID != "" {
			lines = append(lines, s.styles.dim.Render(cleanReviewText("  approval "+step.ApprovalID, width)))
		}
	}
	if len(lines) == 0 {
		lines = append(lines, s.styles.dim.Render("empty review"))
	}
	return lines
}

type payloadPreviewTarget struct {
	step approval.PlanReviewStep
	ref  payload.Ref
}

func (s approvalsSection) loadPayloadPreview() approvalsSection {
	width := s.w
	if width <= 0 {
		width = 80
	}
	s.payloadPreviewText = nil
	req, ok := s.selected()
	if !ok || req.PlanID == "" {
		s.payloadPreviewText = []string{s.styles.dim.Render(cleanReviewText("payload preview: no selected plan", width))}
		return s
	}
	status, err := s.pendingStore().PlanStatus(req.PlanID)
	if err != nil {
		s.payloadPreviewText = []string{s.styles.err.Render(cleanReviewText("payload preview: "+err.Error(), width))}
		return s
	}
	if status.Review == nil {
		s.payloadPreviewText = []string{s.styles.dim.Render(cleanReviewText("payload preview: legacy plan has no immutable review snapshot", width))}
		return s
	}
	targets := payloadPreviewTargets(status)
	if len(targets) == 0 {
		s.payloadPreviewIndex = 0
		s.payloadPreviewText = []string{s.styles.dim.Render(cleanReviewText("payload preview: no retained payload references in this review", width))}
		return s
	}
	if s.payloadPreviewIndex < 0 {
		s.payloadPreviewIndex = len(targets) - 1
	}
	if s.payloadPreviewIndex >= len(targets) {
		s.payloadPreviewIndex = 0
	}
	target := targets[s.payloadPreviewIndex]
	store := payload.Store{Dir: s.paths.PayloadsDir}
	result, err := store.Show(target.ref, payload.ShowOptions{PreviewBytes: 4096})
	if err != nil {
		s.payloadPreviewText = []string{s.styles.err.Render(cleanReviewText("payload preview: "+err.Error(), width))}
		return s
	}
	lines := []string{s.styles.dim.Render(cleanReviewText(fmt.Sprintf("payload preview %d/%d for %s %s", s.payloadPreviewIndex+1, len(targets), target.step.ID, target.step.PayloadRef), width))}
	if result.Binary {
		lines = append(lines, s.styles.dim.Render(cleanReviewText("binary payload; text preview unavailable", width)))
	} else {
		for _, line := range wrapReviewText(literalReviewText(result.Text), width) {
			lines = append(lines, s.styles.dim.Render(line))
		}
	}
	if result.Truncated {
		lines = append(lines, s.styles.dim.Render(cleanReviewText("payload preview truncated at 4 KiB in TUI; CLI plan payload show gives a 64 KiB preview and archive inventory", width)))
	}
	s.payloadPreviewText = lines
	return s
}

func payloadPreviewTargets(status approval.PlanStatus) []payloadPreviewTarget {
	if status.Review == nil {
		return nil
	}
	var out []payloadPreviewTarget
	for _, step := range status.Review.Steps {
		if step.PayloadRef == "" {
			continue
		}
		ref, err := payload.ParseRef(step.PayloadRef)
		if err != nil {
			continue
		}
		out = append(out, payloadPreviewTarget{step: step, ref: ref})
	}
	return out
}

func (s approvalsSection) releasePlanPayloadPins(status approval.PlanStatus) {
	if status.ID == "" || status.Review == nil {
		return
	}
	store := payload.Store{Dir: s.paths.PayloadsDir}
	seen := map[payload.Ref]bool{}
	for _, step := range status.Review.Steps {
		if step.PayloadRef == "" {
			continue
		}
		ref, err := payload.ParseRef(step.PayloadRef)
		if err != nil || seen[ref] {
			continue
		}
		_ = store.Unpin(ref, status.ID)
		seen[ref] = true
	}
}

func cleanReviewText(value string, width int) string {
	value = cleanReviewString(value)
	value = strings.Join(strings.Fields(value), " ")
	if width <= 0 {
		width = 80
	}
	if width < 4 {
		width = 4
	}
	runes := []rune(value)
	if len(runes) > width {
		return string(runes[:width-3]) + "..."
	}
	return value
}

func cleanReviewString(value string) string {
	value = stripReviewEscapes(value)
	var b strings.Builder
	for _, r := range value {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteByte(' ')
		case r < 0x20 || r == 0x7f:
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func stripReviewEscapes(value string) string {
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

func literalReviewText(value string) string {
	return strconv.QuoteToGraphic(stripReviewEscapes(value))
}

func wrapReviewText(value string, width int) []string {
	if width <= 0 {
		width = 80
	}
	if width < 8 {
		width = 8
	}
	if value == "" {
		return []string{""}
	}
	var lines []string
	var b strings.Builder
	for _, r := range value {
		next := b.String() + string(r)
		if b.Len() > 0 && lipgloss.Width(next) > width {
			lines = append(lines, b.String())
			b.Reset()
			if len(lines) >= 80 {
				lines = append(lines, "[wrapped text truncated; use CLI inspect/show]")
				return lines
			}
		}
		b.WriteRune(r)
	}
	if b.Len() > 0 {
		lines = append(lines, b.String())
	}
	return lines
}
