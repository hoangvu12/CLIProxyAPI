package auth

import (
	"context"
	"net/http"
	"strconv"
	"testing"
	"time"

	internallogging "github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

type claudeWindowSignal struct {
	reset       time.Duration
	status      string
	utilization string
}

// soonestResetAuth builds a Claude credential whose quota snapshot carries the given windows.
func soonestResetAuth(id string, now time.Time, fiveHour, sevenDay *claudeWindowSignal) *Auth {
	signals := map[string]string{}
	for window, signal := range map[string]*claudeWindowSignal{"5h": fiveHour, "7d": sevenDay} {
		if signal == nil {
			continue
		}
		signals[claudeUnifiedWindowHeader(window, "Reset")] = strconv.FormatInt(now.Add(signal.reset).Unix(), 10)
		status := signal.status
		if status == "" {
			status = "allowed"
		}
		signals[claudeUnifiedWindowHeader(window, "Status")] = status
		if signal.utilization != "" {
			signals[claudeUnifiedWindowHeader(window, "Utilization")] = signal.utilization
		}
	}
	return &Auth{ID: id, Provider: "claude", Quota: QuotaState{ObservedAt: now, Signals: signals}}
}

func pickSoonestResetIDs(t *testing.T, selector Selector, opts cliproxyexecutor.Options, auths []*Auth, n int) []string {
	t.Helper()
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		got, errPick := selector.Pick(context.Background(), "claude", "claude-test", opts, auths)
		if errPick != nil {
			t.Fatalf("Pick() #%d error = %v", i, errPick)
		}
		ids = append(ids, got.ID)
	}
	return ids
}

func assertPicks(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("picks = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("picks = %v, want %v", got, want)
		}
	}
}

func TestSoonestResetSelectorPrefersEarliestSevenDayReset(t *testing.T) {
	t.Parallel()

	now := time.Now()
	auths := []*Auth{
		soonestResetAuth("a", now, &claudeWindowSignal{reset: time.Hour}, &claudeWindowSignal{reset: 96 * time.Hour}),
		soonestResetAuth("b", now, &claudeWindowSignal{reset: 4 * time.Hour}, &claudeWindowSignal{reset: 24 * time.Hour}),
		soonestResetAuth("c", now, &claudeWindowSignal{reset: 2 * time.Hour}, &claudeWindowSignal{reset: 48 * time.Hour}),
	}

	got := pickSoonestResetIDs(t, &SoonestResetSelector{}, cliproxyexecutor.Options{}, auths, 4)
	assertPicks(t, got, "b", "b", "b", "b")
}

func TestSoonestResetSelectorSkipsExhaustedWindows(t *testing.T) {
	t.Parallel()

	now := time.Now()
	tests := []struct {
		name string
		soon *Auth
		want string
	}{
		{
			name: "seven day utilization full",
			soon: soonestResetAuth("a", now, &claudeWindowSignal{reset: time.Hour}, &claudeWindowSignal{reset: 24 * time.Hour, utilization: "1.0"}),
			want: "b",
		},
		{
			name: "five hour rejected",
			soon: soonestResetAuth("a", now, &claudeWindowSignal{reset: time.Hour, status: "rejected"}, &claudeWindowSignal{reset: 24 * time.Hour}),
			want: "b",
		},
		{
			name: "five hour utilization full",
			soon: soonestResetAuth("a", now, &claudeWindowSignal{reset: time.Hour, utilization: "1.02"}, &claudeWindowSignal{reset: 24 * time.Hour, utilization: "0.4"}),
			want: "b",
		},
		{
			name: "rejected window already reset",
			soon: soonestResetAuth("a", now, &claudeWindowSignal{reset: -time.Minute, status: "rejected", utilization: "1.0"}, &claudeWindowSignal{reset: 24 * time.Hour}),
			want: "a",
		},
		{
			name: "high but not full utilization",
			soon: soonestResetAuth("a", now, &claudeWindowSignal{reset: time.Hour, status: "allowed_warning", utilization: "0.97"}, &claudeWindowSignal{reset: 24 * time.Hour}),
			want: "a",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			later := soonestResetAuth("b", now, &claudeWindowSignal{reset: 2 * time.Hour}, &claudeWindowSignal{reset: 72 * time.Hour})
			got := pickSoonestResetIDs(t, &SoonestResetSelector{}, cliproxyexecutor.Options{}, []*Auth{test.soon, later}, 3)
			assertPicks(t, got, test.want, test.want, test.want)
		})
	}
}

func TestSoonestResetSelectorAllExhaustedStillPicks(t *testing.T) {
	t.Parallel()

	now := time.Now()
	auths := []*Auth{
		soonestResetAuth("a", now, nil, &claudeWindowSignal{reset: 48 * time.Hour, status: "rejected"}),
		soonestResetAuth("b", now, nil, &claudeWindowSignal{reset: 24 * time.Hour, status: "rejected"}),
	}

	got := pickSoonestResetIDs(t, &SoonestResetSelector{}, cliproxyexecutor.Options{}, auths, 2)
	assertPicks(t, got, "b", "b")
}

func TestSoonestResetSelectorProbesUnknownThenRanksItLast(t *testing.T) {
	t.Parallel()

	now := time.Now()
	auths := []*Auth{
		soonestResetAuth("a", now, nil, &claudeWindowSignal{reset: 96 * time.Hour}),
		{ID: "b", Provider: "claude"},
		soonestResetAuth("c", now, nil, &claudeWindowSignal{reset: 48 * time.Hour}),
	}
	selector := &SoonestResetSelector{}

	// The unknown credential is probed once, then ranks after every known one.
	got := pickSoonestResetIDs(t, selector, cliproxyexecutor.Options{}, auths, 4)
	assertPicks(t, got, "b", "c", "c", "c")

	// It is probed again once the probe interval has passed without data arriving.
	selector.mu.Lock()
	selector.probedAt["b"] = now.Add(-soonestResetProbeInterval)
	selector.mu.Unlock()
	got = pickSoonestResetIDs(t, selector, cliproxyexecutor.Options{}, auths, 2)
	assertPicks(t, got, "b", "c")
}

func TestSoonestResetSelectorUnknownCredentialsStillServeWhenAlone(t *testing.T) {
	t.Parallel()

	auths := []*Auth{{ID: "b"}, {ID: "a"}, {ID: "c"}}

	// Each unknown credential is probed once, then they share traffic round-robin.
	got := pickSoonestResetIDs(t, &SoonestResetSelector{}, cliproxyexecutor.Options{}, auths, 6)
	assertPicks(t, got, "a", "b", "c", "a", "b", "c")
}

func TestSoonestResetSelectorSameTierAPIKeyIsFallbackOnly(t *testing.T) {
	t.Parallel()

	now := time.Now()
	gateway := &Auth{ID: "a-gateway", Provider: "claude", Attributes: map[string]string{AttributeAPIKey: "test-key"}}
	oauthA := soonestResetAuth("oauth-a", now, nil, &claudeWindowSignal{reset: 48 * time.Hour})
	oauthB := soonestResetAuth("oauth-b", now, nil, &claudeWindowSignal{reset: 24 * time.Hour})
	selector := &SoonestResetSelector{}

	// The API key reports no reset data and is never probed, so known credentials win.
	got := pickSoonestResetIDs(t, selector, cliproxyexecutor.Options{}, []*Auth{gateway, oauthA, oauthB}, 3)
	assertPicks(t, got, "oauth-b", "oauth-b", "oauth-b")

	// It is preferred over credentials whose windows are known to be exhausted.
	oauthA = soonestResetAuth("oauth-a", now, nil, &claudeWindowSignal{reset: 48 * time.Hour, status: "rejected"})
	oauthB = soonestResetAuth("oauth-b", now, nil, &claudeWindowSignal{reset: 24 * time.Hour, utilization: "1.0"})
	got = pickSoonestResetIDs(t, selector, cliproxyexecutor.Options{}, []*Auth{gateway, oauthA, oauthB}, 2)
	assertPicks(t, got, "a-gateway", "a-gateway")
}

func TestSoonestResetSelectorTieBreaks(t *testing.T) {
	t.Parallel()

	now := time.Now()
	sevenDay := &claudeWindowSignal{reset: 24 * time.Hour}

	// Equal 7d resets fall back to the earlier 5h reset.
	auths := []*Auth{
		soonestResetAuth("a", now, &claudeWindowSignal{reset: 3 * time.Hour}, sevenDay),
		soonestResetAuth("b", now, &claudeWindowSignal{reset: time.Hour}, sevenDay),
		soonestResetAuth("c", now, nil, sevenDay),
	}
	got := pickSoonestResetIDs(t, &SoonestResetSelector{}, cliproxyexecutor.Options{}, auths, 2)
	assertPicks(t, got, "b", "b")

	// Fully equal resets rotate round-robin among the tied credentials only.
	fiveHour := &claudeWindowSignal{reset: time.Hour}
	auths = []*Auth{
		soonestResetAuth("a", now, fiveHour, sevenDay),
		soonestResetAuth("b", now, fiveHour, sevenDay),
		soonestResetAuth("c", now, fiveHour, &claudeWindowSignal{reset: 48 * time.Hour}),
	}
	got = pickSoonestResetIDs(t, &SoonestResetSelector{}, cliproxyexecutor.Options{}, auths, 4)
	assertPicks(t, got, "a", "b", "a", "b")
}

func TestSoonestResetSelectorRespectsPriorityAndCooldown(t *testing.T) {
	t.Parallel()

	now := time.Now()
	model := "claude-test"
	lowSoon := soonestResetAuth("low-soon", now, nil, &claudeWindowSignal{reset: time.Hour})
	lowSoon.Attributes = map[string]string{"priority": "0"}
	highLate := soonestResetAuth("high-late", now, nil, &claudeWindowSignal{reset: 96 * time.Hour})
	highLate.Attributes = map[string]string{"priority": "10"}
	highCooling := soonestResetAuth("high-cooling", now, nil, &claudeWindowSignal{reset: 2 * time.Hour})
	highCooling.Attributes = map[string]string{"priority": "10"}
	highCooling.ModelStates = map[string]*ModelState{
		model: {Status: StatusActive, Unavailable: true, NextRetryAfter: now.Add(30 * time.Minute), Quota: QuotaState{Exceeded: true}},
	}

	got := pickSoonestResetIDs(t, &SoonestResetSelector{}, cliproxyexecutor.Options{}, []*Auth{lowSoon, highLate, highCooling}, 2)
	assertPicks(t, got, "high-late", "high-late")
}

func TestSoonestResetSelectorLowerTierUnknownCredentialIsNotProbed(t *testing.T) {
	t.Parallel()

	now := time.Now()
	model := "claude-test"
	oauthA := soonestResetAuth("oauth-a", now, nil, &claudeWindowSignal{reset: 48 * time.Hour})
	oauthB := soonestResetAuth("oauth-b", now, nil, &claudeWindowSignal{reset: 24 * time.Hour, status: "rejected"})
	// An API-key gateway in a lower tier never reports quota headers.
	gateway := &Auth{ID: "gateway", Provider: "claude", Attributes: map[string]string{"priority": "-10"}}
	selector := &SoonestResetSelector{}

	got := pickSoonestResetIDs(t, selector, cliproxyexecutor.Options{}, []*Auth{gateway, oauthA, oauthB}, 3)
	assertPicks(t, got, "oauth-a", "oauth-a", "oauth-a")

	// It serves only once every higher-tier credential is cooling down.
	for _, auth := range []*Auth{oauthA, oauthB} {
		auth.ModelStates = map[string]*ModelState{
			model: {Status: StatusActive, Unavailable: true, NextRetryAfter: now.Add(time.Hour), Quota: QuotaState{Exceeded: true}},
		}
	}
	got = pickSoonestResetIDs(t, selector, cliproxyexecutor.Options{}, []*Auth{gateway, oauthA, oauthB}, 2)
	assertPicks(t, got, "gateway", "gateway")
}

func TestSoonestResetSelectorUsesNewestModelSnapshot(t *testing.T) {
	t.Parallel()

	now := time.Now()
	// The credential-level snapshot is stale; a newer per-model snapshot reports a sooner reset.
	stale := soonestResetAuth("a", now.Add(-time.Hour), nil, &claudeWindowSignal{reset: 96 * time.Hour})
	fresh := soonestResetAuth("a", now, nil, &claudeWindowSignal{reset: 12 * time.Hour})
	stale.ModelStates = map[string]*ModelState{"claude-other": {Status: StatusActive, Quota: fresh.Quota}}
	other := soonestResetAuth("b", now, nil, &claudeWindowSignal{reset: 24 * time.Hour})

	got := pickSoonestResetIDs(t, &SoonestResetSelector{}, cliproxyexecutor.Options{}, []*Auth{stale, other}, 2)
	assertPicks(t, got, "a", "a")
}

func TestSoonestResetSelectorSessionAffinityKeepsExistingBinding(t *testing.T) {
	t.Parallel()

	now := time.Now()
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: &SoonestResetSelector{},
		TTL:      time.Minute,
	})
	defer selector.Stop()

	sessionA := cliproxyexecutor.Options{OriginalRequest: []byte(`{"metadata":{"user_id":"user_xxx_account__session_soonest-reset-a"}}`)}
	sessionB := cliproxyexecutor.Options{OriginalRequest: []byte(`{"metadata":{"user_id":"user_xxx_account__session_soonest-reset-b"}}`)}

	auths := []*Auth{
		soonestResetAuth("early", now, nil, &claudeWindowSignal{reset: 96 * time.Hour}),
		soonestResetAuth("late", now, nil, &claudeWindowSignal{reset: 24 * time.Hour}),
	}
	assertPicks(t, pickSoonestResetIDs(t, selector, sessionA, auths, 1), "late")

	// "early" now resets sooner: the cold session follows it, the bound one stays put.
	auths = []*Auth{
		soonestResetAuth("early", now, nil, &claudeWindowSignal{reset: 12 * time.Hour}),
		soonestResetAuth("late", now, nil, &claudeWindowSignal{reset: 24 * time.Hour}),
	}
	assertPicks(t, pickSoonestResetIDs(t, selector, sessionA, auths, 3), "late", "late", "late")
	assertPicks(t, pickSoonestResetIDs(t, selector, sessionB, auths, 1), "early")

	// Failover rebinding uses soonest-reset ordering among the remaining credentials.
	third := soonestResetAuth("third", now, nil, &claudeWindowSignal{reset: 48 * time.Hour})
	remaining := []*Auth{auths[0], third}
	assertPicks(t, pickSoonestResetIDs(t, selector, sessionA, remaining, 2), "early", "early")
}

func TestManagerSoonestResetLearnsFromClaudeResponseHeaders(t *testing.T) {
	ctx := context.Background()
	model := "claude-soonest-reset-manager-model"
	manager := NewManager(nil, &SoonestResetSelector{}, nil)
	manager.RegisterExecutor(schedulerProviderTestExecutor{provider: "claude"})
	if manager.useSchedulerFastPath() {
		t.Fatal("soonest-reset must not use the scheduler fast path")
	}
	registerSchedulerModels(t, "claude", model, "sr-mgr-a", "sr-mgr-b", "sr-mgr-c")
	for _, id := range []string{"sr-mgr-a", "sr-mgr-b", "sr-mgr-c"} {
		if _, errRegister := manager.Register(ctx, &Auth{ID: id, Provider: "claude", Status: StatusActive}); errRegister != nil {
			t.Fatalf("Register(%s) error = %v", id, errRegister)
		}
	}

	now := time.Now()
	observe := func(id string, sevenDayReset time.Duration, sevenDayStatus string) {
		resultCtx := internallogging.WithResponseHeadersHolder(ctx)
		internallogging.SetResponseHeaders(resultCtx, http.Header{
			"Anthropic-Ratelimit-Unified-Status":               []string{"allowed"},
			"Anthropic-Ratelimit-Unified-5h-Status":            []string{"allowed"},
			"Anthropic-Ratelimit-Unified-5h-Reset":             []string{strconv.FormatInt(now.Add(2*time.Hour).Unix(), 10)},
			"Anthropic-Ratelimit-Unified-5h-Utilization":       []string{"0.1"},
			"Anthropic-Ratelimit-Unified-7d-Status":            []string{sevenDayStatus},
			"Anthropic-Ratelimit-Unified-7d-Reset":             []string{strconv.FormatInt(now.Add(sevenDayReset).Unix(), 10)},
			"Anthropic-Ratelimit-Unified-7d-Utilization":       []string{"0.5"},
			"Anthropic-Ratelimit-Unified-Representative-Claim": []string{"five_hour"},
		})
		manager.MarkResult(resultCtx, Result{AuthID: id, Provider: "claude", Model: model, Success: true, CompletedResponse: true})
	}
	observe("sr-mgr-a", 96*time.Hour, "allowed")
	observe("sr-mgr-b", 24*time.Hour, "allowed")
	observe("sr-mgr-c", 48*time.Hour, "allowed")

	pick := func() string {
		t.Helper()
		got, _, errPick := manager.pickNext(ctx, "claude", model, cliproxyexecutor.Options{}, nil)
		if errPick != nil {
			t.Fatalf("pickNext() error = %v", errPick)
		}
		return got.ID
	}
	for i := 0; i < 3; i++ {
		if got := pick(); got != "sr-mgr-b" {
			t.Fatalf("pickNext() #%d = %q, want sr-mgr-b", i, got)
		}
	}

	// Once b's latest response reports its 7d window as fully used, c resets next.
	observe("sr-mgr-b", 24*time.Hour, "rejected")
	if got := pick(); got != "sr-mgr-c" {
		t.Fatalf("pickNext() after b exhausted = %q, want sr-mgr-c", got)
	}
}
