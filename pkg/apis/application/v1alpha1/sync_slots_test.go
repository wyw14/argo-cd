package v1alpha1

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func utcTime(y int, month time.Month, d, h, minute, sec int) time.Time {
	return time.Date(y, month, d, h, minute, sec, 0, time.UTC)
}

// justAfter is the first instant at which a window is active after its
// firing second: isActiveAt uses a strict Before and is inactive at the firing
// instant itself.
func justAfter(t time.Time) time.Time {
	return t.Add(time.Nanosecond)
}

func newSlotWindow(kind, schedule, duration, timeZone string) *InlineSyncWindow {
	return &InlineSyncWindow{
		Kind:         kind,
		Schedule:     schedule,
		Duration:     duration,
		TimeZone:     timeZone,
		Applications: []string{"*"},
	}
}

// syncOracle answers admission questions through the exact partition +
// canSyncFrom path that backs CanSync, at caller-chosen instants. Partitions
// are cached per exact instant; canSyncFrom itself is still invoked
// independently for every candidate start and operation instant, so the
// reference never shares state with the code under test.
type syncOracle struct {
	t       *testing.T
	windows SyncWindows
	manual  bool
	cache   map[time.Time]oraclePartition
}

type oraclePartition struct {
	active         *SyncWindows
	inactiveAllows *SyncWindows
}

func newSyncOracle(t *testing.T, windows SyncWindows, manual bool) *syncOracle {
	t.Helper()
	return &syncOracle{t: t, windows: windows, manual: manual, cache: map[time.Time]oraclePartition{}}
}

func (o *syncOracle) partition(at time.Time) oraclePartition {
	o.t.Helper()
	key := at.UTC().Truncate(time.Nanosecond)
	if cached, ok := o.cache[key]; ok {
		return cached
	}
	active, inactiveAllows, err := o.windows.partition(at.UTC())
	require.NoError(o.t, err)
	part := oraclePartition{active: active, inactiveAllows: inactiveAllows}
	o.cache[key] = part
	return part
}

// canSync asks the real CanSync decision code at one instant. In overrun mode
// operationStartTime is bound to the candidate start, exactly as the
// production semantics require; strict mode leaves it unset.
func (o *syncOracle) canSync(mode SyncSlotMode, start, at time.Time) bool {
	o.t.Helper()
	part := o.partition(at)
	var operationStartTime *time.Time
	if mode == SyncSlotModeOverrun {
		operationStartTime = &start
	}
	allowed, err := o.windows.canSyncFrom(o.manual, operationStartTime, part.active, part.inactiveAllows)
	require.NoError(o.t, err)
	return allowed
}

// admissible walks every second of [start, start+duration) independently, and
// additionally evaluates every collected boundary instant (including the
// one-nanosecond companions) the interval contains, so no sub-second boundary
// is sampled away.
func (o *syncOracle) admissible(mode SyncSlotMode, start time.Time, duration time.Duration, bounds []time.Time) bool {
	o.t.Helper()
	instants := map[time.Time]struct{}{}
	for tick := start; tick.Before(start.Add(duration)); tick = tick.Add(time.Second) {
		instants[tick] = struct{}{}
	}
	end := start.Add(duration)
	for _, bound := range bounds {
		if !bound.Before(start) && bound.Before(end) {
			instants[bound] = struct{}{}
		}
	}
	for tick := range instants {
		if !o.canSync(mode, start, tick) {
			return false
		}
	}
	return true
}

func containsSlot(slots []SyncSlot, at time.Time) bool {
	for _, slot := range slots {
		if !at.Before(slot.Start) && at.Before(slot.End) {
			return true
		}
	}
	return false
}

// assertSlotsMatchOracle compares every whole-second candidate start in the
// domain against the independent oracle, then re-verifies each interval
// endpoint separately, and checks the slots are maximal, sorted and disjoint.
func assertSlotsMatchOracle(t *testing.T, windows SyncWindows, req FindSyncSlotsRequest) *FindSyncSlotsResponse {
	t.Helper()
	resp, err := windows.FindSyncSlots(req)
	require.NoError(t, err)
	require.Equal(t, SyncSlotSearchComplete, resp.Status, resp.Reason)

	from := req.DomainStart.UTC()
	lastStart := req.DomainEnd.UTC().Add(-req.OperationDuration)
	oracle := newSyncOracle(t, windows, req.Manual)

	collector := &slotBoundaryCollector{
		from:       from,
		to:         req.DomainEnd.UTC(),
		bounds:     map[time.Time]struct{}{from: {}, req.DomainEnd.UTC(): {}},
		eventLimit: defaultSyncSlotCronEventLimit,
	}
	require.NoError(t, collector.collect(&windows))
	bounds := collector.sortedBounds()

	for start := from; start.Before(lastStart); start = start.Add(time.Second) {
		expected := oracle.admissible(req.Mode, start, req.OperationDuration, bounds)
		assert.Equalf(t, expected, containsSlot(resp.Slots, start),
			"admission mismatch at candidate start %s (mode %s, manual %t)", start, req.Mode, req.Manual)
	}

	var previousEnd time.Time
	for i, slot := range resp.Slots {
		assert.True(t, slot.End.After(slot.Start), "slot %d must be non-empty", i)
		if i > 0 {
			assert.True(t, slot.Start.After(previousEnd), "slots must be sorted and disjoint")
			assert.False(t, slot.Start.Equal(previousEnd), "adjacent admissible slots must be merged")
		}
		previousEnd = slot.End

		// Half-open endpoints, verified independently against the oracle.
		assert.True(t, oracle.admissible(req.Mode, slot.Start, req.OperationDuration, bounds),
			"inclusive slot start %s must be admissible", slot.Start)
		assert.True(t, oracle.admissible(req.Mode, slot.End.Add(-time.Second), req.OperationDuration, bounds),
			"second before exclusive slot end %s must be admissible", slot.End)
		if slot.Start.After(from) {
			assert.False(t, oracle.admissible(req.Mode, slot.Start.Add(-time.Second), req.OperationDuration, bounds),
				"second before slot start %s must not be admissible", slot.Start)
		}
		if slot.End.Before(lastStart) {
			assert.False(t, oracle.admissible(req.Mode, slot.End, req.OperationDuration, bounds),
				"exclusive slot end %s must not be admissible", slot.End)
		}
	}
	return resp
}

func TestFindSyncSlots_NoWindows(t *testing.T) {
	windows := SyncWindows{}
	from := utcTime(2026, 5, 1, 8, 0, 0)
	to := utcTime(2026, 5, 1, 10, 0, 0)
	duration := 30 * time.Minute

	resp := assertSlotsMatchOracle(t, windows, FindSyncSlotsRequest{
		Mode: SyncSlotModeStrict, OperationDuration: duration, DomainStart: from, DomainEnd: to,
	})
	require.Len(t, resp.Slots, 1)
	assert.Equal(t, from, resp.Slots[0].Start)
	assert.Equal(t, to.Add(-duration), resp.Slots[0].End)
	assert.NotEmpty(t, resp.WindowDigest)
}

func TestFindSyncSlots_SingleAllowWindow(t *testing.T) {
	windows := SyncWindows{newSlotWindow("allow", "0 10 * * *", "1h", "UTC")}
	from := utcTime(2026, 5, 1, 8, 0, 0)
	to := utcTime(2026, 5, 1, 13, 0, 0)
	duration := 30 * time.Minute

	for _, mode := range []SyncSlotMode{SyncSlotModeStrict, SyncSlotModeOverrun} {
		resp := assertSlotsMatchOracle(t, windows, FindSyncSlotsRequest{
			Mode: mode, OperationDuration: duration, DomainStart: from, DomainEnd: to,
		})
		require.Len(t, resp.Slots, 1)
		assert.Equal(t, justAfter(utcTime(2026, 5, 1, 10, 0, 0)), resp.Slots[0].Start)
		assert.Equal(t, justAfter(utcTime(2026, 5, 1, 10, 30, 0)), resp.Slots[0].End)
	}
}

func TestFindSyncSlots_NestedAllowAndDeny(t *testing.T) {
	windows := SyncWindows{
		newSlotWindow("allow", "0 10 * * *", "2h", "UTC"),  // 10:00-12:00
		newSlotWindow("deny", "30 10 * * *", "30m", "UTC"), // 10:30-11:00
	}
	from := utcTime(2026, 5, 1, 9, 0, 0)
	to := utcTime(2026, 5, 1, 13, 0, 0)
	duration := 15 * time.Minute

	resp := assertSlotsMatchOracle(t, windows, FindSyncSlotsRequest{
		Mode: SyncSlotModeStrict, OperationDuration: duration, DomainStart: from, DomainEnd: to,
	})
	require.Len(t, resp.Slots, 2)
	assert.Equal(t, SyncSlot{
		Start: justAfter(utcTime(2026, 5, 1, 10, 0, 0)),
		End:   utcTime(2026, 5, 1, 10, 15, 0).Add(2 * time.Nanosecond),
	}, resp.Slots[0])
	assert.Equal(t, SyncSlot{
		Start: utcTime(2026, 5, 1, 11, 0, 0),
		End:   justAfter(utcTime(2026, 5, 1, 11, 45, 0)),
	}, resp.Slots[1])
}

func TestFindSyncSlots_MultipleDenyWindows(t *testing.T) {
	windows := SyncWindows{
		newSlotWindow("deny", "15 10 * * *", "15m", "UTC"), // 10:15-10:30
		newSlotWindow("deny", "45 10 * * *", "15m", "UTC"), // 10:45-11:00
	}
	from := utcTime(2026, 5, 1, 9, 30, 0)
	to := utcTime(2026, 5, 1, 12, 0, 0)
	duration := 10 * time.Minute

	// Deny-only configuration: every instant outside the deny windows is
	// admissible, and overlapping deny intervals are just one blocked union.
	assertSlotsMatchOracle(t, windows, FindSyncSlotsRequest{
		Mode: SyncSlotModeStrict, OperationDuration: duration, DomainStart: from, DomainEnd: to,
	})
}

func TestFindSyncSlots_ManualDenyWindow(t *testing.T) {
	deny := newSlotWindow("deny", "0 10 * * *", "1h", "UTC")
	deny.ManualSync = true
	windows := SyncWindows{deny}
	from := utcTime(2026, 5, 1, 9, 0, 0)
	to := utcTime(2026, 5, 1, 12, 0, 0)
	duration := 20 * time.Minute

	t.Run("auto sync is blocked while the manual deny is active", func(t *testing.T) {
		req := FindSyncSlotsRequest{
			Manual: false, Mode: SyncSlotModeStrict,
			OperationDuration: duration, DomainStart: from, DomainEnd: to,
		}
		resp := assertSlotsMatchOracle(t, windows, req)
		for _, slot := range resp.Slots {
			assert.True(t, slot.End.Before(utcTime(2026, 5, 1, 10, 0, 0)) ||
				!slot.Start.Before(utcTime(2026, 5, 1, 11, 0, 0)))
		}
	})

	t.Run("manual sync bypasses the manual deny", func(t *testing.T) {
		req := FindSyncSlotsRequest{
			Manual: true, Mode: SyncSlotModeStrict,
			OperationDuration: duration, DomainStart: from, DomainEnd: to,
		}
		resp := assertSlotsMatchOracle(t, windows, req)
		require.Len(t, resp.Slots, 1)
		assert.Equal(t, from, resp.Slots[0].Start)
		assert.Equal(t, to.Add(-duration), resp.Slots[0].End)
	})
}

func TestFindSyncSlots_InactiveAllowManual(t *testing.T) {
	allow := newSlotWindow("allow", "0 10 * * *", "1h", "UTC")
	allow.ManualSync = true
	windows := SyncWindows{allow}
	from := utcTime(2026, 5, 1, 9, 0, 0)
	to := utcTime(2026, 5, 1, 12, 0, 0)
	duration := 15 * time.Minute

	// Manual syncs are admitted even while the allow window is inactive.
	resp := assertSlotsMatchOracle(t, windows, FindSyncSlotsRequest{
		Manual: true, Mode: SyncSlotModeStrict,
		OperationDuration: duration, DomainStart: from, DomainEnd: to,
	})
	require.Len(t, resp.Slots, 1)
	assert.Equal(t, from, resp.Slots[0].Start)
}

func TestFindSyncSlots_DenyOverrunStrictVsOverrun(t *testing.T) {
	deny := newSlotWindow("deny", "30 10 * * *", "30m", "UTC") // 10:30-11:00
	deny.SyncOverrun = true
	windows := SyncWindows{deny}
	from := utcTime(2026, 5, 1, 9, 0, 0)
	to := utcTime(2026, 5, 1, 12, 0, 0)
	duration := time.Hour

	strict := assertSlotsMatchOracle(t, windows, FindSyncSlotsRequest{
		Manual: false, Mode: SyncSlotModeStrict,
		OperationDuration: duration, DomainStart: from, DomainEnd: to,
	})
	// Strict: the whole operation must avoid the deny window, so an operation
	// starting after 09:30 reaches the deny boundary.
	require.Len(t, strict.Slots, 1)
	assert.Equal(t, utcTime(2026, 5, 1, 9, 0, 0), strict.Slots[0].Start)
	assert.Equal(t, utcTime(2026, 5, 1, 9, 30, 0).Add(2*time.Nanosecond), strict.Slots[0].End)

	overrun := assertSlotsMatchOracle(t, windows, FindSyncSlotsRequest{
		Manual: false, Mode: SyncSlotModeOverrun,
		OperationDuration: duration, DomainStart: from, DomainEnd: to,
	})
	// Overrun: an operation that started while sync was allowed may continue
	// into the overrun-enabled deny, so starts up to the deny boundary work;
	// starting inside the deny still fails because it was not allowed at start.
	require.Len(t, overrun.Slots, 1)
	assert.Equal(t, utcTime(2026, 5, 1, 9, 0, 0), overrun.Slots[0].Start)
	assert.Equal(t, justAfter(utcTime(2026, 5, 1, 10, 30, 0)), overrun.Slots[0].End)
}

func TestFindSyncSlots_AllowOverrunStrictVsOverrun(t *testing.T) {
	allow := newSlotWindow("allow", "0 9 * * *", "1h", "UTC") // 09:00-10:00
	allow.SyncOverrun = true
	windows := SyncWindows{allow}
	from := utcTime(2026, 5, 1, 8, 0, 0)
	to := utcTime(2026, 5, 1, 12, 0, 0)
	duration := 90 * time.Minute

	strict, err := windows.FindSyncSlots(FindSyncSlotsRequest{
		Manual: false, Mode: SyncSlotModeStrict,
		OperationDuration: duration, DomainStart: from, DomainEnd: to,
	})
	require.NoError(t, err)
	// A 90 minute operation cannot fit inside a 60 minute allow window.
	assert.Empty(t, strict.Slots)
	assert.Equal(t, SyncSlotSearchComplete, strict.Status)

	overrun := assertSlotsMatchOracle(t, windows, FindSyncSlotsRequest{
		Manual: false, Mode: SyncSlotModeOverrun,
		OperationDuration: duration, DomainStart: from, DomainEnd: to,
	})
	// Starts inside the allow window may finish after it thanks to overrun;
	// starts outside it cannot claim the window at all.
	require.Len(t, overrun.Slots, 1)
	assert.Equal(t, justAfter(utcTime(2026, 5, 1, 9, 0, 0)), overrun.Slots[0].Start)
	assert.Equal(t, utcTime(2026, 5, 1, 10, 0, 0), overrun.Slots[0].End)
}

func TestFindSyncSlots_CrossMidnight(t *testing.T) {
	windows := SyncWindows{newSlotWindow("allow", "0 23 * * *", "2h", "UTC")} // 23:00-01:00
	from := utcTime(2026, 5, 1, 21, 0, 0)
	to := utcTime(2026, 5, 2, 2, 0, 0)
	duration := 45 * time.Minute

	resp := assertSlotsMatchOracle(t, windows, FindSyncSlotsRequest{
		Mode: SyncSlotModeStrict, OperationDuration: duration, DomainStart: from, DomainEnd: to,
	})
	require.Len(t, resp.Slots, 1)
	assert.Equal(t, justAfter(utcTime(2026, 5, 1, 23, 0, 0)), resp.Slots[0].Start)
	assert.Equal(t, justAfter(utcTime(2026, 5, 2, 0, 15, 0)), resp.Slots[0].End)
}

func TestFindSyncSlots_DSTFallBackRepeatedHour(t *testing.T) {
	// America/New_York falls back from EDT (-04) to EST (-05) on 2026-11-01
	// at 06:00 UTC. A 01:00 local window open for two wall-clock hours covers
	// the repeated hour and is active 05:00-08:00 UTC: four real hours, not
	// three.
	windows := SyncWindows{newSlotWindow("allow", "0 1 * * *", "2h", "America/New_York")}
	from := utcTime(2026, 11, 1, 4, 0, 0)
	to := utcTime(2026, 11, 1, 9, 0, 0)
	duration := 30 * time.Minute

	resp := assertSlotsMatchOracle(t, windows, FindSyncSlotsRequest{
		Mode: SyncSlotModeStrict, OperationDuration: duration, DomainStart: from, DomainEnd: to,
	})
	// The repeated 01:00 wall instant is inactive at exactly 06:00:00 UTC, so
	// an operation that would contain that instant splits the answer in two.
	require.Len(t, resp.Slots, 2)
	assert.Equal(t, SyncSlot{
		Start: justAfter(utcTime(2026, 11, 1, 5, 0, 0)),
		End:   justAfter(utcTime(2026, 11, 1, 5, 30, 0)),
	}, resp.Slots[0])
	assert.Equal(t, SyncSlot{
		Start: justAfter(utcTime(2026, 11, 1, 6, 0, 0)),
		End:   justAfter(utcTime(2026, 11, 1, 7, 30, 0)),
	}, resp.Slots[1])
}

func TestFindSyncSlots_DSTSpringForwardMissingHour(t *testing.T) {
	// America/New_York springs forward on 2026-03-08 at 07:00 UTC: wall time
	// 02:00-03:00 does not exist.
	t.Run("window inside the gap is shortened to the post-gap remainder", func(t *testing.T) {
		// Wall 02:30-03:30 does not exist as scheduled: isActiveAt re-reads the
		// offset after the jump, so the window is really active 07:00-07:30 UTC.
		windows := SyncWindows{newSlotWindow("allow", "30 2 * * *", "1h", "America/New_York")}
		from := utcTime(2026, 3, 8, 6, 0, 0)
		to := utcTime(2026, 3, 8, 10, 0, 0)
		duration := 10 * time.Minute

		for _, mode := range []SyncSlotMode{SyncSlotModeStrict, SyncSlotModeOverrun} {
			resp := assertSlotsMatchOracle(t, windows, FindSyncSlotsRequest{
				Mode: mode, OperationDuration: duration, DomainStart: from, DomainEnd: to,
			})
			require.Len(t, resp.Slots, 1)
			assert.Equal(t, utcTime(2026, 3, 8, 7, 0, 0), resp.Slots[0].Start)
			assert.Equal(t, justAfter(utcTime(2026, 3, 8, 7, 20, 0)), resp.Slots[0].End)
		}
	})

	t.Run("window crossing the gap is shortened by one hour", func(t *testing.T) {
		// Wall 02:00-04:00 maps to UTC 07:00-08:00: the missing hour shrinks
		// the active interval.
		windows := SyncWindows{newSlotWindow("allow", "0 2 * * *", "2h", "America/New_York")}
		from := utcTime(2026, 3, 8, 6, 0, 0)
		to := utcTime(2026, 3, 8, 9, 0, 0)
		duration := 15 * time.Minute

		resp := assertSlotsMatchOracle(t, windows, FindSyncSlotsRequest{
			Mode: SyncSlotModeStrict, OperationDuration: duration, DomainStart: from, DomainEnd: to,
		})
		require.Len(t, resp.Slots, 1)
		// The gap makes the firing strictly precede the first active instant,
		// so the window is already active at 07:00:00 exactly.
		assert.Equal(t, utcTime(2026, 3, 8, 7, 0, 0), resp.Slots[0].Start)
		assert.Equal(t, justAfter(utcTime(2026, 3, 8, 7, 45, 0)), resp.Slots[0].End)
	})
}

func TestFindSyncSlots_MixedTimeZones(t *testing.T) {
	windows := SyncWindows{
		newSlotWindow("allow", "0 12 * * *", "2h", "UTC"),            // 12:00-14:00 UTC
		newSlotWindow("deny", "0 9 * * *", "1h", "America/New_York"), // 14:00-15:00 UTC (EDT, -04)
	}
	from := utcTime(2026, 7, 1, 11, 0, 0)
	to := utcTime(2026, 7, 1, 16, 0, 0)
	duration := 20 * time.Minute

	assertSlotsMatchOracle(t, windows, FindSyncSlotsRequest{
		Mode: SyncSlotModeStrict, OperationDuration: duration, DomainStart: from, DomainEnd: to,
	})
}

func TestFindSyncSlots_InvalidConfiguration(t *testing.T) {
	from := utcTime(2026, 5, 1, 8, 0, 0)
	to := utcTime(2026, 5, 1, 10, 0, 0)
	base := func() FindSyncSlotsRequest {
		return FindSyncSlotsRequest{
			Mode: SyncSlotModeStrict, OperationDuration: time.Minute,
			DomainStart: from, DomainEnd: to,
		}
	}

	t.Run("invalid cron", func(t *testing.T) {
		windows := SyncWindows{newSlotWindow("allow", "not a cron", "1h", "UTC")}
		_, err := windows.FindSyncSlots(base())
		require.ErrorContains(t, err, "cannot parse schedule")
	})
	t.Run("invalid time zone", func(t *testing.T) {
		windows := SyncWindows{newSlotWindow("allow", "0 10 * * *", "1h", "Mars/Olympus")}
		_, err := windows.FindSyncSlots(base())
		require.ErrorContains(t, err, "invalid sync window time zone")
	})
	t.Run("invalid duration", func(t *testing.T) {
		windows := SyncWindows{newSlotWindow("allow", "0 10 * * *", "soon", "UTC")}
		_, err := windows.FindSyncSlots(base())
		require.ErrorContains(t, err, "cannot parse sync window duration")
	})
	t.Run("invalid kind", func(t *testing.T) {
		window := newSlotWindow("maybe", "0 10 * * *", "1h", "UTC")
		windows := SyncWindows{window}
		_, err := windows.FindSyncSlots(base())
		require.ErrorContains(t, err, "can only be allow or deny")
	})
}

func TestFindSyncSlots_InvalidRequest(t *testing.T) {
	windows := SyncWindows{newSlotWindow("allow", "0 10 * * *", "1h", "UTC")}
	from := utcTime(2026, 5, 1, 8, 0, 0)
	to := utcTime(2026, 5, 1, 10, 0, 0)

	_, err := windows.FindSyncSlots(FindSyncSlotsRequest{
		Mode: SyncSlotModeStrict, OperationDuration: 0, DomainStart: from, DomainEnd: to,
	})
	require.ErrorContains(t, err, "operationDuration")

	_, err = windows.FindSyncSlots(FindSyncSlotsRequest{
		Mode: SyncSlotModeStrict, OperationDuration: time.Minute, DomainStart: to, DomainEnd: from,
	})
	require.ErrorContains(t, err, "domainEnd must be after domainStart")

	_, err = windows.FindSyncSlots(FindSyncSlotsRequest{
		Mode: "Sideways", OperationDuration: time.Minute, DomainStart: from, DomainEnd: to,
	})
	require.ErrorContains(t, err, "unknown sync slot mode")

	_, err = windows.FindSyncSlots(FindSyncSlotsRequest{
		Mode: SyncSlotModeStrict, OperationDuration: time.Minute,
		DomainStart: from, DomainEnd: to.Add(maxSyncSlotDomain + time.Hour),
	})
	require.ErrorContains(t, err, "must not exceed")

	req := FindSyncSlotsRequest{
		Mode: SyncSlotModeStrict, OperationDuration: 3 * time.Hour, DomainStart: from, DomainEnd: to,
	}
	resp, err := windows.FindSyncSlots(req)
	require.NoError(t, err)
	assert.Equal(t, SyncSlotSearchComplete, resp.Status)
	assert.Empty(t, resp.Slots, "an operation longer than the domain yields no slots")
}

func TestFindSyncSlots_IncompleteOnCronEventLimit(t *testing.T) {
	// A per-minute schedule over six hours produces 360 firings.
	windows := SyncWindows{newSlotWindow("deny", "* * * * *", "1m", "UTC")}
	from := utcTime(2026, 5, 1, 8, 0, 0)
	to := utcTime(2026, 5, 1, 14, 0, 0)

	resp, err := windows.FindSyncSlots(FindSyncSlotsRequest{
		Mode: SyncSlotModeStrict, OperationDuration: 5 * time.Minute,
		DomainStart: from, DomainEnd: to, MaxCronEvents: 10,
	})
	require.NoError(t, err)
	assert.Equal(t, SyncSlotSearchIncomplete, resp.Status)
	assert.NotEmpty(t, resp.Reason)
}

func TestFindSyncSlots_IncompleteOnSlotLimit(t *testing.T) {
	// Alternating 10 minute allow windows create many disjoint slots.
	windows := SyncWindows{newSlotWindow("allow", "0,20,40 * * * *", "10m", "UTC")}
	from := utcTime(2026, 5, 1, 8, 0, 0)
	to := utcTime(2026, 5, 1, 12, 0, 0)

	resp, err := windows.FindSyncSlots(FindSyncSlotsRequest{
		Mode: SyncSlotModeStrict, OperationDuration: time.Minute,
		DomainStart: from, DomainEnd: to, MaxSlots: 3,
	})
	require.NoError(t, err)
	assert.Equal(t, SyncSlotSearchIncomplete, resp.Status)
	assert.Len(t, resp.Slots, 3)
}

func TestFindSyncSlots_DigestAndGenerationBinding(t *testing.T) {
	windows := SyncWindows{newSlotWindow("allow", "0 10 * * *", "1h", "UTC")}
	from := utcTime(2026, 5, 1, 8, 0, 0)
	to := utcTime(2026, 5, 1, 12, 0, 0)

	resp, err := windows.FindSyncSlots(FindSyncSlotsRequest{
		Mode: SyncSlotModeStrict, OperationDuration: 15 * time.Minute,
		DomainStart: from, DomainEnd: to,
		ProjectGeneration: 7, ApplicationGeneration: 9,
		ProjectName: "proj", ApplicationName: "app",
	})
	require.NoError(t, err)
	assert.Equal(t, int64(7), resp.ProjectGeneration)
	assert.Equal(t, int64(9), resp.ApplicationGeneration)

	valid, err := resp.ValidFor(7, 9, &windows)
	require.NoError(t, err)
	assert.True(t, valid)

	stale, err := resp.ValidFor(8, 9, &windows)
	require.NoError(t, err)
	assert.False(t, stale, "a new project generation invalidates the result")

	changed := SyncWindows{newSlotWindow("allow", "0 11 * * *", "1h", "UTC")}
	differentDigest, err := resp.ValidFor(7, 9, &changed)
	require.NoError(t, err)
	assert.False(t, differentDigest, "a changed window digest invalidates the result")

	behaviorChanged := SyncWindows{newSlotWindow("allow", "0 10 * * *", "1h", "UTC")}
	behaviorChanged[0].SyncOverrun = true
	overrunDigest, err := resp.ValidFor(7, 9, &behaviorChanged)
	require.NoError(t, err)
	assert.False(t, overrunDigest, "the digest covers behavioral fields such as syncOverrun")
}

func TestCheckedTimeAdd(t *testing.T) {
	extreme := time.Unix(math.MaxInt64, 0).UTC()
	_, err := checkedTimeAdd(extreme, time.Hour)
	require.ErrorIs(t, err, errTimeOverflow)

	minimum := time.Unix(math.MinInt64, 0).UTC()
	_, err = checkedTimeAdd(minimum, -time.Hour)
	require.ErrorIs(t, err, errTimeOverflow)

	safe, err := checkedTimeAdd(utcTime(2026, 1, 1, 0, 0, 0), 90*time.Minute)
	require.NoError(t, err)
	assert.Equal(t, utcTime(2026, 1, 1, 1, 30, 0), safe)
}

func TestDSTTransitions(t *testing.T) {
	loc, err := time.LoadLocation("America/New_York")
	require.NoError(t, err)

	transitions := dstTransitions(loc, utcTime(2026, 1, 1, 0, 0, 0), utcTime(2027, 1, 1, 0, 0, 0))
	assert.Equal(t, []time.Time{
		utcTime(2026, 3, 8, 7, 0, 0),  // spring forward, EST -> EDT
		utcTime(2026, 11, 1, 6, 0, 0), // fall back, EDT -> EST
	}, transitions)
}
