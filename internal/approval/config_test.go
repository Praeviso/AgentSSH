package approval

import (
	"testing"

	"github.com/Praeviso/AgentSSH/internal/policy"
)

func TestRuntimeConfigApprovalEnvCanOnlyEnable(t *testing.T) {
	cfg, err := RuntimeConfigFromPolicy(policy.Approval{Enabled: true}, "false")
	if err != nil {
		t.Fatalf("RuntimeConfigFromPolicy enabled+false env: %v", err)
	}
	if !cfg.Enabled {
		t.Fatal("AGENTSSH_APPROVAL=false disabled policy-file approval")
	}

	cfg, err = RuntimeConfigFromPolicy(policy.Approval{}, "true")
	if err != nil {
		t.Fatalf("RuntimeConfigFromPolicy disabled+true env: %v", err)
	}
	if !cfg.Enabled {
		t.Fatal("AGENTSSH_APPROVAL=true did not enable approval")
	}

	cfg, err = RuntimeConfigFromPolicy(policy.Approval{}, "false")
	if err != nil {
		t.Fatalf("RuntimeConfigFromPolicy disabled+false env: %v", err)
	}
	if cfg.Enabled {
		t.Fatal("AGENTSSH_APPROVAL=false enabled approval")
	}
}
