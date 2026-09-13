package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/Praeviso/AgentSSH/internal/approval"
	tea "github.com/charmbracelet/bubbletea"
)

func (s approvalsSection) taskTTL() time.Duration {
	if s.runtime.TaskTTL > 0 {
		return s.runtime.TaskTTL
	}
	return approval.DefaultTaskTTL
}

func (s approvalsSection) taskMembers() []approval.PendingRequest {
	req, ok := s.selected()
	if !ok {
		return nil
	}
	if req.PlanID == "" || (!s.planMode && s.expandedPlans[req.PlanID]) {
		return []approval.PendingRequest{req}
	}
	var members []approval.PendingRequest
	for _, member := range s.pending {
		if member.PlanID == req.PlanID {
			members = append(members, member)
		}
	}
	return members
}

func (s approvalsSection) hasTaskChoice() bool {
	for _, req := range s.taskMembers() {
		if approval.TaskCandidate(req.Cmd, req.StdinSHA256) != nil {
			return true
		}
	}
	return false
}

func (s approvalsSection) openTaskChooser() (tea.Model, tea.Cmd) {
	if !s.runtime.Enabled || !s.hasTaskChoice() {
		return s, nil
	}
	req, _ := s.selected()
	s.choosing = true
	s.previewOffset = 0
	s.choiceID = req.ID
	s.planMode = req.PlanID != "" && !s.expandedPlans[req.PlanID]
	for i, choice := range s.choices() {
		if choice.scope == approval.ScopeTask {
			s.choiceIdx = i
			break
		}
	}
	return s, nil
}

func (s approvalsSection) taskPreview() string {
	lines := []string{fmt.Sprintf("Task scope · host/session bound · expires %s after approval · session end revokes", s.taskTTL())}
	if req, ok := s.selected(); ok {
		lines = append(lines, fmt.Sprintf("Host: %q · Session: %q", req.Host, req.SessionID))
	}
	seen := map[string]bool{}
	exact := 0
	for _, req := range s.taskMembers() {
		p := approval.TaskCandidate(req.Cmd, req.StdinSHA256)
		if p == nil {
			exact++
			continue
		}
		line := p.Summary()
		if !seen[line] {
			lines = append(lines, line)
			seen[line] = true
		}
	}
	if exact > 0 {
		lines = append(lines, fmt.Sprintf("%d other command(s): exact command + stdin only, same expiry", exact))
		for _, req := range s.taskMembers() {
			if approval.TaskCandidate(req.Cmd, req.StdinSHA256) == nil {
				line := fmt.Sprintf("  exact: %q", req.Cmd)
				if req.StdinSHA256 != "" {
					line += fmt.Sprintf(" · stdin %d B sha256=%s", req.StdinBytes, req.StdinSHA256)
				}
				lines = append(lines, line)
			}
		}
	}
	return strings.Join(lines, "\n")
}

func (s approvalsSection) taskReviewView(width int) string {
	wrapped := s.styles.dim.Width(width).Render(s.taskPreview())
	lines := strings.Split(wrapped, "\n")
	count := maxInt(1, s.h-3)
	start := minInt(s.previewOffset, maxInt(0, len(lines)-count))
	end := minInt(len(lines), start+count)
	return s.styles.header.Render("Review task permissions") + "\n" + strings.Join(lines[start:end], "\n") + "\n" +
		s.styles.dim.Render(fmt.Sprintf("%d-%d of %d lines · j/k scroll · esc cancel", start+1, end, len(lines))) + "\n" + s.chooserLine()
}
