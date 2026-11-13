package auth

import (
	"context"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// soonestResetProbeInterval bounds how often a credential without reset data is
// picked ahead of known credentials so its quota windows can be learned.
const soonestResetProbeInterval = 10 * time.Minute

// SoonestResetSelector prefers the credential whose Claude 7-day quota window resets
// soonest, so quota that would otherwise expire unused at reset is spent first. Ties
// fall back to the earlier 5-hour reset and then to round-robin order.
//
// Reset data comes from the passive Anthropic unified rate-limit snapshot kept in
// Quota.Signals. A credential whose 5h or 7d window is known to be exhausted is
// skipped until that window resets. Credentials without data rank after known ones,
// so they act as a same-tier fallback. Subscription credentials without data are also
// probed at most once per soonestResetProbeInterval so their windows are learned; API
// keys never carry unified rate-limit headers and are not probed.
type SoonestResetSelector struct {
	mu         sync.Mutex
	lastPicked map[string]string
	probedAt   map[string]time.Time
}

// claudeResetRank orders credentials for SoonestResetSelector. Zero reset times mean
// unknown or already passed and sort after any known reset.
type claudeResetRank struct {
	exhausted bool
	reset7d   time.Time
	reset5h   time.Time
}

func (r claudeResetRank) known() bool {
	return !r.reset7d.IsZero() || !r.reset5h.IsZero()
}

// claudeResetRankForAuth reads the 5h and 7d windows from the latest quota snapshot.
// A window whose reset has passed carries no information about the current window.
func claudeResetRankForAuth(auth *Auth, now time.Time) claudeResetRank {
	var rank claudeResetRank
	if auth == nil {
		return rank
	}
	signals := latestQuotaSignals(auth)
	for _, window := range []string{"5h", "7d"} {
		reset, ok := parseQuotaSignalUnixTime(signals[claudeUnifiedWindowHeader(window, "Reset")])
		if !ok || !reset.After(now) {
			continue
		}
		if window == "5h" {
			rank.reset5h = reset
		} else {
			rank.reset7d = reset
		}
		status := strings.TrimSpace(signals[claudeUnifiedWindowHeader(window, "Status")])
		utilization, errParse := strconv.ParseFloat(strings.TrimSpace(signals[claudeUnifiedWindowHeader(window, "Utilization")]), 64)
		if strings.EqualFold(status, "rejected") || (errParse == nil && utilization >= 1.0) {
			rank.exhausted = true
		}
	}
	return rank
}

// latestQuotaSignals returns the newest passive quota snapshot recorded for auth. The
// 5h and 7d windows are credential-wide, so a newer per-model snapshot is as valid as
// the credential-level one.
func latestQuotaSignals(auth *Auth) map[string]string {
	latest := auth.Quota
	for _, state := range auth.ModelStates {
		if state != nil && state.Quota.ObservedAt.After(latest.ObservedAt) {
			latest = state.Quota
		}
	}
	return latest.Signals
}

func parseQuotaSignalUnixTime(raw string) (time.Time, bool) {
	seconds, errParse := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if errParse != nil || seconds <= 0 || math.IsInf(seconds, 0) || math.IsNaN(seconds) {
		return time.Time{}, false
	}
	return time.Unix(int64(seconds), 0), true
}

// resetBefore reports whether reset a sorts before b, treating zero as infinitely late.
func resetBefore(a, b time.Time) bool {
	if a.IsZero() || b.IsZero() {
		return !a.IsZero() && b.IsZero()
	}
	return a.Before(b)
}

// compareClaudeResetRank returns -1, 0, or 1 as a sorts before, with, or after b.
func compareClaudeResetRank(a, b claudeResetRank) int {
	switch {
	case a.exhausted != b.exhausted:
		if b.exhausted {
			return -1
		}
		return 1
	case resetBefore(a.reset7d, b.reset7d):
		return -1
	case resetBefore(b.reset7d, a.reset7d):
		return 1
	case resetBefore(a.reset5h, b.reset5h):
		return -1
	case resetBefore(b.reset5h, a.reset5h):
		return 1
	default:
		return 0
	}
}

// Pick selects the available auth whose quota resets soonest.
func (s *SoonestResetSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	_ = opts
	now := time.Now()
	available, err := getSelectorAvailableAuths(ctx, auths, provider, model, now)
	if err != nil {
		return nil, err
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)

	ranks := make([]claudeResetRank, len(available))
	for i, auth := range available {
		ranks[i] = claudeResetRankForAuth(auth, now)
	}

	key := provider + ":" + canonicalModelLookupKey(model)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastPicked == nil || (len(s.lastPicked) >= 4096 && s.lastPicked[key] == "") {
		s.lastPicked = make(map[string]string)
	}
	if s.probedAt == nil || len(s.probedAt) >= 4096 {
		s.probedAt = make(map[string]time.Time)
	}
	for i, auth := range available {
		if ranks[i].known() || auth.AuthKind() == AuthKindAPIKey {
			continue
		}
		if last, ok := s.probedAt[auth.ID]; !ok || now.Sub(last) >= soonestResetProbeInterval {
			s.probedAt[auth.ID] = now
			s.lastPicked[key] = auth.ID
			return auth, nil
		}
	}

	// Keep only the best-ranked candidates; available is ID-sorted, so the round-robin
	// successor among them resumes after the previous pick.
	best := make([]*Auth, 0, len(available))
	bestRank := ranks[0]
	for i, auth := range available {
		switch compareClaudeResetRank(ranks[i], bestRank) {
		case -1:
			bestRank = ranks[i]
			best = append(best[:0], auth)
		case 0:
			best = append(best, auth)
		}
	}
	picked := best[successorIndex(best, s.lastPicked[key])]
	s.lastPicked[key] = picked.ID
	return picked, nil
}
