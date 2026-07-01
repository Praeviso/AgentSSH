package approval

import (
	"fmt"
	"strings"
	"time"

	"github.com/Praeviso/AgentSSH/internal/policy"
)

const (
	DefaultSessionTTL  = 12 * time.Hour
	DefaultWaitTimeout = 10 * time.Minute
)

type RuntimeConfig struct {
	Enabled       bool
	HostGrantMode HostGrantMode
	SessionTTL    time.Duration
	WaitTimeout   time.Duration
}

func RuntimeConfigFromPolicy(cfg policy.Approval, envValue string) (RuntimeConfig, error) {
	out := RuntimeConfig{
		Enabled:       cfg.Enabled,
		HostGrantMode: HostGrantSafePrefix,
		SessionTTL:    DefaultSessionTTL,
		WaitTimeout:   DefaultWaitTimeout,
	}
	if cfg.HostGrantMode != "" {
		switch HostGrantMode(cfg.HostGrantMode) {
		case HostGrantExact, HostGrantSafePrefix, HostGrantPrefix:
			out.HostGrantMode = HostGrantMode(cfg.HostGrantMode)
		default:
			return out, fmt.Errorf("invalid approval.host_grant_mode %q; expected exact, safe-prefix, or prefix", cfg.HostGrantMode)
		}
	}
	if cfg.SessionTTL != "" {
		duration, err := time.ParseDuration(cfg.SessionTTL)
		if err != nil || duration <= 0 {
			return out, fmt.Errorf("invalid approval.session_ttl %q", cfg.SessionTTL)
		}
		out.SessionTTL = duration
	}
	if cfg.WaitTimeout != "" {
		duration, err := time.ParseDuration(cfg.WaitTimeout)
		if err != nil || duration <= 0 {
			return out, fmt.Errorf("invalid approval.wait_timeout %q", cfg.WaitTimeout)
		}
		out.WaitTimeout = duration
	}
	if envValue != "" {
		enabled, err := parseBoolEnv(envValue)
		if err != nil {
			return out, err
		}
		out.Enabled = enabled
	}
	return out, nil
}

func parseBoolEnv(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on", "enabled":
		return true, nil
	case "0", "false", "no", "off", "disabled":
		return false, nil
	default:
		return false, fmt.Errorf("invalid AGENTSSH_APPROVAL value %q; expected true/false", value)
	}
}
