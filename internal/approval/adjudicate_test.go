package approval

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/policy"
)

func TestApplyDecisionAtomicClaimBeforeHostSideEffects(t *testing.T) {
	root := t.TempDir()
	pending := PendingStore{PendingDir: filepath.Join(root, "pending"), ResponsesDir: filepath.Join(root, "responses")}
	matcher, err := Generalize("ls /var", HostGrantSafePrefix)
	if err != nil {
		t.Fatal(err)
	}
	req, err := pending.Create(PendingRequest{
		ReqID:     "r1",
		SessionID: "s1",
		Host:      "web-1",
		Cmd:       "ls /var",
		Candidate: matcher,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	var mu sync.Mutex
	var saved []policy.Config
	opts := ApplyOptions{
		Pending: pending,
		Bundle: policy.Bundle{
			Inventory: inventory.Inventory{Hosts: map[string]inventory.Host{"web-1": {}}},
		},
		SavePolicy: func(next policy.Config) error {
			mu.Lock()
			defer mu.Unlock()
			saved = append(saved, next)
			return nil
		},
	}

	type outcome struct {
		result ApplyResult
		err    error
	}
	results := make(chan outcome, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		result, err := ApplyDecision(opts, req.ID, VerdictApproved, ScopeHost)
		results <- outcome{result: result, err: err}
	}()
	go func() {
		defer wg.Done()
		result, err := ApplyDecision(opts, req.ID, VerdictDenied, "")
		results <- outcome{result: result, err: err}
	}()
	wg.Wait()
	close(results)

	var wins []ApplyResult
	var alreadyResolved int
	for out := range results {
		if out.err == nil {
			wins = append(wins, out.result)
			continue
		}
		if errors.Is(out.err, ErrAlreadyResolved) {
			alreadyResolved++
			continue
		}
		t.Fatalf("unexpected ApplyDecision error: %v", out.err)
	}
	if len(wins) != 1 || alreadyResolved != 1 {
		t.Fatalf("wins=%d alreadyResolved=%d", len(wins), alreadyResolved)
	}
	status, err := pending.Status(req.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	switch status.Verdict {
	case VerdictApproved:
		if len(saved) != 1 {
			t.Fatalf("approved resolution saved policies = %d, want 1", len(saved))
		}
		rules := saved[0].HostOverrides[policy.HostRulesKey("web-1")].Rules
		if len(rules) != 1 || rules[0].Group != policy.ApprovalGroup || rules[0].Action != policy.ActionAllow {
			t.Fatalf("saved host rules = %#v", rules)
		}
	case VerdictDenied:
		if len(saved) != 0 {
			t.Fatalf("denied resolution saved policies = %d, want 0", len(saved))
		}
	default:
		t.Fatalf("status = %#v", status)
	}
}
