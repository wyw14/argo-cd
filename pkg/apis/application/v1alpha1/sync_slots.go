package v1alpha1

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"time"

	"github.com/argoproj/argo-cd/v3/util/hash"
)

// SyncSlotMode selects how a candidate operation start time is admitted.
type SyncSlotMode string

const (
	// SyncSlotModeStrict requires the operation to be allowed at every instant
	// of its duration. CanSync is evaluated without an operation start time, so
	// sync overrun is never relied upon.
	SyncSlotModeStrict SyncSlotMode = "Strict"
	// SyncSlotModeOverrun binds operationStartTime to every candidate start
	// time, exactly as CanSync does for a running operation: a window with
	// syncOverrun may carry the operation past the window end or into an
	// overrun-enabled deny window. The operation still has to be admissible at
	// every instant of its duration.
	SyncSlotModeOverrun SyncSlotMode = "Overrun"
)

// SyncSlotSearchStatus reports whether the search covered the whole domain.
type SyncSlotSearchStatus string

const (
	// SyncSlotSearchComplete means the slots cover every admissible start time
	// in the domain.
	SyncSlotSearchComplete SyncSlotSearchStatus = "Complete"
	// SyncSlotSearchIncomplete means a configured limit was hit and the
	// returned slots are a partial result: an absent slot must not be read as
	// "no admissible time".
	SyncSlotSearchIncomplete SyncSlotSearchStatus = "Incomplete"
)

const (
	// maxSyncSlotDomain bounds the UTC span of a single search. A bounded
	// domain keeps cron enumeration and the interval arithmetic proportional to
	// a planning horizon rather than an unbounded request.
	maxSyncSlotDomain = 366 * 24 * time.Hour
	// defaultSyncSlotCronEventLimit caps the number of cron firings enumerated
	// across all windows before the result is marked incomplete.
	defaultSyncSlotCronEventLimit = 10000
	maxSyncSlotCronEventLimit     = 100000
	// defaultSyncSlotLimit caps the number of slots returned in one response.
	defaultSyncSlotLimit = 1000
	maxSyncSlotLimit     = 10000
	// maxTimeZoneOffsetAbs bounds the UTC offset of every supported IANA zone
	// (the widest modern offset is UTC+14). It only widens the cron scan range
	// so a firing near a domain edge cannot be missed; window offsets themselves
	// always come from the real time zone data.
	maxTimeZoneOffsetAbs = 15 * time.Hour
)

// FindSyncSlotsRequest describes a sync slot search for one application.
type FindSyncSlotsRequest struct {
	// Manual is passed through as CanSync's isManual argument: it selects the
	// manual-sync exceptions configured on deny and allow windows.
	Manual bool
	// Mode selects strict (fully allowed throughout) or overrun-aware
	// admission. See SyncSlotMode.
	Mode SyncSlotMode
	// OperationDuration is the expected full duration of the operation. It must
	// be positive; an operation [start, start+OperationDuration) has to fit
	// entirely inside the domain.
	OperationDuration time.Duration
	// DomainStart and DomainEnd define the half-open UTC search domain. Both
	// are converted to UTC; the operation end must not exceed DomainEnd.
	DomainStart time.Time
	DomainEnd   time.Time
	// ProjectGeneration and ApplicationGeneration bind the result to the
	// configuration it was computed from. They are echoed back and checked by
	// FindSyncSlotsResponse.ValidFor.
	ProjectGeneration     int64
	ApplicationGeneration int64
	// ProjectName and ApplicationName are recorded for diagnostics; they do not
	// influence the computation.
	ProjectName     string
	ApplicationName string
	// MaxCronEvents overrides the cron firing limit (zero keeps the default).
	// It is clamped to maxSyncSlotCronEventLimit.
	MaxCronEvents int
	// MaxSlots overrides the returned slot limit (zero keeps the default). It
	// is clamped to maxSyncSlotLimit.
	MaxSlots int
}

// SyncSlot is a maximal half-open UTC interval [Start, End) of admissible
// operation start times.
type SyncSlot struct {
	// Start is inclusive.
	Start time.Time
	// End is exclusive.
	End time.Time
}

// FindSyncSlotsResponse is the result of a sync slot search. It never starts or
// queues a sync: it only reports when one could be admitted.
type FindSyncSlotsResponse struct {
	// Status is Complete only when the whole domain was covered within the
	// configured limits.
	Status SyncSlotSearchStatus
	// Slots are the maximal admissible start-time intervals, sorted, disjoint
	// and half-open. When Status is Incomplete they are a partial result.
	Slots []SyncSlot
	// WindowDigest identifies the exact SyncWindows the slots were computed
	// from, including ManualSync and SyncOverrun. Any window change produces a
	// different digest.
	WindowDigest string
	// ProjectGeneration and ApplicationGeneration echo the request, so a result
	// computed against an older generation cannot be reused as a current
	// admission decision.
	ProjectGeneration     int64
	ApplicationGeneration int64
	ProjectName           string
	ApplicationName       string
	// Reason explains why Status is Incomplete; empty when Complete.
	Reason string
}

// FindSyncSlots returns the maximal half-open UTC start-time intervals in which
// an operation of the requested duration can run to completion under the
// receiver's sync window semantics.
//
// The windows passed as receiver must already be matched to the target
// application (see SyncWindows.Matches). The computation reuses the real cron
// parser, time zone data and the CanSync decision code; it collects window
// start/end, DST and duration-offset boundaries and derives the answer with
// interval arithmetic, so no second-level boundary is sampled away and DST days
// are never assumed to be 24 hours. It is a pure calculation and never queues
// or starts a sync.
//
// Invalid cron specs, time zones or durations, and invalid requests, return an
// error. Hitting a configured limit is not an error: the response is returned
// with Status Incomplete instead of claiming that no slot exists.
func (w *SyncWindows) FindSyncSlots(req FindSyncSlotsRequest) (*FindSyncSlotsResponse, error) {
	if err := req.validate(); err != nil {
		return nil, err
	}
	eventLimit, slotLimit := req.limits()

	// Truncate at nanosecond precision only to strip monotonic clock readings,
	// which would otherwise make equal instants distinct map keys.
	from := req.DomainStart.UTC().Truncate(time.Nanosecond)
	to := req.DomainEnd.UTC().Truncate(time.Nanosecond)

	resp := &FindSyncSlotsResponse{
		Status:                SyncSlotSearchComplete,
		ProjectGeneration:     req.ProjectGeneration,
		ApplicationGeneration: req.ApplicationGeneration,
		ProjectName:           req.ProjectName,
		ApplicationName:       req.ApplicationName,
	}
	digest, err := syncWindowsDigest(w)
	if err != nil {
		return nil, err
	}
	resp.WindowDigest = digest

	lastStart, err := checkedTimeAdd(to, -req.OperationDuration)
	if err != nil {
		return nil, fmt.Errorf("cannot bound operation start times: %w", err)
	}
	if !lastStart.After(from) {
		// The operation cannot finish inside the domain at all.
		return resp, nil
	}

	if !w.HasWindows() {
		// No matched windows: CanSync admits at every instant.
		resp.Slots = []SyncSlot{{Start: from, End: lastStart}}
		return resp, nil
	}

	for _, window := range *w {
		if err := validateSlotWindow(window); err != nil {
			return nil, err
		}
	}

	collector := &slotBoundaryCollector{
		from:       from,
		to:         to,
		bounds:     map[time.Time]struct{}{from: {}, to: {}},
		eventLimit: eventLimit,
	}
	if err := collector.collect(w); err != nil {
		return nil, err
	}

	partitioned, err := buildSlotSegments(w, req.Manual, collector.sortedBounds())
	if err != nil {
		return nil, err
	}

	slots, slotLimitHit, err := partitioned.findSlots(req.Mode, req.OperationDuration, from, lastStart, slotLimit)
	if err != nil {
		return nil, err
	}
	resp.Slots = slots

	if collector.incomplete {
		resp.Status = SyncSlotSearchIncomplete
		resp.Reason = collector.reason
	} else if slotLimitHit {
		resp.Status = SyncSlotSearchIncomplete
		resp.Reason = fmt.Sprintf("sync slot limit (%d) exceeded; the search domain was not fully covered", slotLimit)
	}
	return resp, nil
}

func (r *FindSyncSlotsRequest) validate() error {
	if r.OperationDuration <= 0 {
		return errors.New("operationDuration must be greater than zero")
	}
	if r.DomainStart.IsZero() || r.DomainEnd.IsZero() {
		return errors.New("domainStart and domainEnd are required")
	}
	from := r.DomainStart.UTC()
	to := r.DomainEnd.UTC()
	if !to.After(from) {
		return errors.New("domainEnd must be after domainStart")
	}
	if to.Sub(from) > maxSyncSlotDomain {
		return fmt.Errorf("sync slot search domain must not exceed %s", maxSyncSlotDomain)
	}
	switch r.Mode {
	case SyncSlotModeStrict, SyncSlotModeOverrun:
	default:
		return fmt.Errorf("unknown sync slot mode %q", r.Mode)
	}
	if r.MaxCronEvents < 0 || r.MaxSlots < 0 {
		return errors.New("sync slot limits must not be negative")
	}
	return nil
}

func (r *FindSyncSlotsRequest) limits() (eventLimit, slotLimit int) {
	eventLimit = defaultSyncSlotCronEventLimit
	if r.MaxCronEvents > 0 {
		eventLimit = min(r.MaxCronEvents, maxSyncSlotCronEventLimit)
	}
	slotLimit = defaultSyncSlotLimit
	if r.MaxSlots > 0 {
		slotLimit = min(r.MaxSlots, maxSyncSlotLimit)
	}
	return eventLimit, slotLimit
}

// validateSlotWindow fails closed on configuration the interval computation
// cannot resolve. Unlike window evaluation, an unknown time zone is an error
// here rather than a silent UTC fallback: slot planning must not quietly shift
// every boundary.
func validateSlotWindow(window *InlineSyncWindow) error {
	if window.Kind != "allow" && window.Kind != "deny" {
		return fmt.Errorf("sync window kind %q can only be allow or deny", window.Kind)
	}
	if _, err := time.LoadLocation(window.TimeZone); err != nil {
		return fmt.Errorf("invalid sync window time zone %q: %w", window.TimeZone, err)
	}
	if _, err := syncWindowSchedule(window.Schedule); err != nil {
		return err
	}
	duration, err := time.ParseDuration(window.Duration)
	if err != nil {
		return fmt.Errorf("cannot parse sync window duration %q: %w", window.Duration, err)
	}
	if duration <= 0 {
		return fmt.Errorf("sync window duration %q must be greater than zero", window.Duration)
	}
	return nil
}

func syncWindowsDigest(w *SyncWindows) (string, error) {
	sum, err := hash.GobObjectHash(w)
	if err != nil {
		return "", fmt.Errorf("failed to hash sync windows: %w", err)
	}
	return strconv.FormatUint(sum, 16), nil
}

// ValidFor reports whether the result still describes the given project and
// application generations and window configuration. A result computed against
// an older generation or a changed window digest must never be treated as a
// current admission authorization.
func (r *FindSyncSlotsResponse) ValidFor(projectGeneration, applicationGeneration int64, windows *SyncWindows) (bool, error) {
	digest, err := syncWindowsDigest(windows)
	if err != nil {
		return false, err
	}
	return r.ProjectGeneration == projectGeneration &&
		r.ApplicationGeneration == applicationGeneration &&
		r.WindowDigest == digest, nil
}

// errTimeOverflow marks time arithmetic that would wrap the underlying int64
// representation.
var errTimeOverflow = errors.New("time arithmetic overflow")

// checkedTimeAdd adds d to t and rejects an overflowing result instead of
// silently wrapping.
func checkedTimeAdd(t time.Time, d time.Duration) (time.Time, error) {
	secs := int64(d / time.Second)
	if d >= 0 && t.Unix() > math.MaxInt64-secs {
		return time.Time{}, errTimeOverflow
	}
	if d < 0 && t.Unix() < math.MinInt64-secs {
		return time.Time{}, errTimeOverflow
	}
	return t.Add(d), nil
}

// slotBoundaryCollector gathers every UTC instant at which the admission
// decision can change: window starts and ends, DST transitions of the window
// time zones, and the domain edges.
type slotBoundaryCollector struct {
	from       time.Time
	to         time.Time
	bounds     map[time.Time]struct{}
	eventLimit int
	eventCount int
	incomplete bool
	reason     string
}

func (c *slotBoundaryCollector) collect(w *SyncWindows) error {
	locations := map[string]*time.Location{}
	offsets := map[string][]int{}
	for _, window := range *w {
		loc, ok := locations[window.TimeZone]
		if !ok {
			// validateSlotWindow already proved the location loads.
			loaded, err := time.LoadLocation(window.TimeZone)
			if err != nil {
				return fmt.Errorf("invalid sync window time zone %q: %w", window.TimeZone, err)
			}
			loc = loaded
			locations[window.TimeZone] = loaded
			transitions, zoneOffsets := zoneTransitionInfo(loaded, c.from.Add(-maxTimeZoneOffsetAbs), c.to.Add(maxTimeZoneOffsetAbs))
			offsets[window.TimeZone] = zoneOffsets
			for _, transition := range transitions {
				c.addBound(transition)
			}
		}
		if err := c.collectWindow(window, loc, offsets[window.TimeZone]); err != nil {
			return err
		}
		if c.incomplete {
			return nil
		}
	}
	return nil
}

func (c *slotBoundaryCollector) collectWindow(window *InlineSyncWindow, loc *time.Location, zoneOffsets []int) error {
	schedule, err := syncWindowSchedule(window.Schedule)
	if err != nil {
		return err
	}
	duration, err := time.ParseDuration(window.Duration)
	if err != nil {
		return fmt.Errorf("cannot parse sync window duration %q: %w", window.Duration, err)
	}

	// Firings are naive wall-clock times. Scan from the earliest wall time that
	// could map to a UTC instant at or after the domain start, accounting for
	// the widest zone offset and the whole window duration.
	wallLower, err := checkedTimeAdd(c.from, -maxTimeZoneOffsetAbs)
	if err != nil {
		return fmt.Errorf("sync window schedule scan overflowed: %w", err)
	}
	wallLower, err = checkedTimeAdd(wallLower, -duration)
	if err != nil {
		return fmt.Errorf("sync window schedule scan overflowed: %w", err)
	}
	wallUpper, err := checkedTimeAdd(c.to, maxTimeZoneOffsetAbs)
	if err != nil {
		return fmt.Errorf("sync window schedule scan overflowed: %w", err)
	}

	firing := schedule.Next(wallLower)
	for firing.Before(wallUpper) {
		if firing.IsZero() {
			// The cron spec has no future firing (e.g. February 31st).
			break
		}
		if c.eventCount >= c.eventLimit {
			c.incomplete = true
			c.reason = fmt.Sprintf("cron event limit (%d) exceeded; the search domain was not fully covered", c.eventLimit)
			return nil
		}
		c.eventCount++

		endWall, err := checkedTimeAdd(firing, duration)
		if err != nil {
			return fmt.Errorf("sync window duration overflowed: %w", err)
		}
		// isActiveAt works on the wall clock w(t) = t + offset(t): a window is
		// active while its firing and end wall times bracket w(t). Invert that
		// relation for every offset the location actually uses, then keep only
		// candidates whose UTC instant really renders that wall time. The
		// equality check is what resolves DST gaps (no candidate survives) and
		// repeated hours (both occurrences survive).
		for _, wall := range []time.Time{firing, endWall} {
			for _, offset := range zoneOffsets {
				candidate := wall.Add(-time.Duration(offset) * time.Second)
				if wallTimeMatches(candidate, loc, wall) {
					c.addBound(candidate)
				}
			}
		}

		firing = schedule.Next(firing)
	}
	return nil
}

// wallTimeMatches reports whether t, rendered in loc, has the same wall-clock
// fields as the UTC-labeled naive wall time.
func wallTimeMatches(t time.Time, loc *time.Location, wall time.Time) bool {
	local := t.In(loc)
	return local.Year() == wall.Year() &&
		local.Month() == wall.Month() &&
		local.Day() == wall.Day() &&
		local.Hour() == wall.Hour() &&
		local.Minute() == wall.Minute() &&
		local.Second() == wall.Second() &&
		local.Nanosecond() == wall.Nanosecond()
}

func (c *slotBoundaryCollector) addBound(t time.Time) {
	// No rounding: sub-second window durations produce sub-second boundaries,
	// and every source (cron firings, time.Date and time.Add) is already
	// monotonic-free.
	t = t.UTC()
	if t.After(c.from) && t.Before(c.to) {
		c.bounds[t] = struct{}{}
	}
}

// sortedBounds returns the collected boundaries, each paired with a companion
// one nanosecond later. isActiveAt decides with a strict Before, so a window is
// inactive at its own firing instant and becomes active just after it: the
// admission truth at the boundary instant differs from the segment interior.
// The companion turns that instant into its own segment, whose midpoint is the
// boundary instant itself. Durations are shifted by whole nanosecond arithmetic,
// so companions move correctly under every operation duration.
func (c *slotBoundaryCollector) sortedBounds() []time.Time {
	expanded := make(map[time.Time]struct{}, len(c.bounds)*2)
	for bound := range c.bounds {
		expanded[bound] = struct{}{}
		// A companion at the domain start captures a window that fires exactly
		// when the search begins; companions past the domain end are irrelevant.
		if !bound.Before(c.from) {
			if companion := bound.Add(time.Nanosecond); companion.Before(c.to) {
				expanded[companion] = struct{}{}
			}
		}
	}
	bounds := make([]time.Time, 0, len(expanded))
	for bound := range expanded {
		bounds = append(bounds, bound)
	}
	slices.SortFunc(bounds, func(a, b time.Time) int { return a.Compare(b) })
	return bounds
}

// dstTransitions returns the UTC instants at which loc's offset changes inside
// [from, to). Days are stepped with AddDate (a calendar step, not a fixed 24
// hour span) and each change is refined against the real zone data down to the
// second, so neither spring-forward gaps nor fall-back repeats are assumed away.
func dstTransitions(loc *time.Location, from, to time.Time) []time.Time {
	transitions, _ := zoneTransitionInfo(loc, from, to)
	return transitions
}

// zoneTransitionInfo returns the UTC offset-change instants inside [from, to)
// and every distinct UTC offset (in seconds) the location uses across the
// range. The offsets let callers invert wall-clock instants without assuming a
// day is 24 hours; the transitions are themselves admission boundaries because
// isActiveAt reads the offset at the evaluated instant.
func zoneTransitionInfo(loc *time.Location, from, to time.Time) ([]time.Time, []int) {
	var transitions []time.Time
	offsetSet := map[int]struct{}{}
	recordOffset := func(t time.Time) {
		_, offset := t.In(loc).Zone()
		offsetSet[offset] = struct{}{}
	}

	day := time.Date(from.Year(), from.Month(), from.Day(), 0, 0, 0, 0, time.UTC)
	recordOffset(day)
	for day.Before(to) {
		nextDay := day.AddDate(0, 0, 1)
		probe := nextDay
		if probe.After(to) {
			probe = to
		}
		_, startOffset := day.In(loc).Zone()
		_, endOffset := probe.In(loc).Zone()
		if startOffset != endOffset {
			// The caller guarantees probe already carries the new offset.
			transition := refineOffsetChange(loc, day, probe, startOffset).UTC()
			recordOffset(transition.Add(time.Second))
			if transition.After(from) && transition.Before(to) {
				transitions = append(transitions, transition)
			}
		}
		recordOffset(probe)
		day = nextDay
	}

	offsets := make([]int, 0, len(offsetSet))
	for offset := range offsetSet {
		offsets = append(offsets, offset)
	}
	slices.Sort(offsets)
	return transitions, offsets
}

// refineOffsetChange narrows the first offset change inside (start, end] from
// hours to minutes to seconds, reading every candidate offset from the real
// zone data. end is known to carry an offset different from startOffset.
func refineOffsetChange(loc *time.Location, start, end time.Time, startOffset int) time.Time {
	for _, step := range []time.Duration{time.Hour, time.Minute, time.Second} {
		for tick := start.Add(step); !tick.After(end); tick = tick.Add(step) {
			if _, offset := tick.In(loc).Zone(); offset != startOffset {
				start = tick.Add(-step)
				end = tick
				break
			}
		}
	}
	return end
}

// slotSegment is one element of the partition induced by the collected
// boundaries. Every window's active state is constant across it, so a single
// classification at the midpoint holds for the whole half-open segment.
type slotSegment struct {
	// allowed is CanSync's answer without an operation start time.
	allowed bool
	// gate reports whether the overrun branch of canSyncFrom is reachable on
	// this segment. On a gated segment the answer depends on whether the
	// operation was allowed when it started.
	gate bool
	// allowedAtStart is canSyncAtTime's answer for an operation starting on
	// this segment.
	allowedAtStart bool
}

// slotSegments pairs the sorted UTC boundaries with the classification of the
// half-open segment between each consecutive pair.
type slotSegments struct {
	bounds   []time.Time
	segments []slotSegment
}

// buildSlotSegments classifies every segment between consecutive boundaries
// using the real partition and canSyncFrom/canSyncAtTime code paths.
func buildSlotSegments(w *SyncWindows, manual bool, bounds []time.Time) (slotSegments, error) {
	segments := make([]slotSegment, 0, len(bounds)-1)
	for i := range len(bounds) - 1 {
		mid := segmentMidpoint(bounds[i], bounds[i+1])
		active, inactiveAllows, err := w.partition(mid)
		if err != nil {
			return slotSegments{}, fmt.Errorf("invalid sync windows: %w", err)
		}
		allowed, err := w.canSyncFrom(manual, nil, active, inactiveAllows)
		if err != nil {
			return slotSegments{}, err
		}
		allowedAtStart, err := w.canSyncAtTime(manual, mid)
		if err != nil {
			return slotSegments{}, err
		}
		segments = append(segments, slotSegment{
			allowed:        allowed,
			gate:           overrunGate(active, inactiveAllows, manual),
			allowedAtStart: allowedAtStart,
		})
	}
	return slotSegments{bounds: bounds, segments: segments}, nil
}

func segmentMidpoint(start, end time.Time) time.Time {
	mid := start.Add(end.Sub(start) / 2)
	if !mid.Before(end) {
		// Sub-second segment: the inclusive start is itself a valid sample.
		return start
	}
	return mid
}

// overrunGate mirrors the operationStartTime branches of canSyncFrom: it
// reports a segment on which the admission decision is exactly "was the
// operation allowed when it started".
func overrunGate(active, inactiveAllows *SyncWindows, manual bool) bool {
	hasDeny, manualEnabled := active.hasDeny()
	if hasDeny {
		return (!manual || !manualEnabled) && active.denyAllowsOverrun()
	}
	if active.hasAllow() {
		return false
	}
	if inactiveAllows.HasWindows() {
		return (!manual || !inactiveAllows.manualEnabled()) && inactiveAllows.inactiveAllowsAllowOverrun()
	}
	return false
}

// findSlots turns the classified segments into maximal half-open start-time
// intervals. Start-time boundaries are the union of the decision boundaries and
// each boundary shifted by minus the operation duration: between two such
// instants the set of segments covered by [start, start+duration) is fixed.
func (s slotSegments) findSlots(mode SyncSlotMode, duration time.Duration, from, lastStart time.Time, slotLimit int) ([]SyncSlot, bool, error) {
	prefixBlocked := make([]int, len(s.segments)+1)
	prefixGated := make([]int, len(s.segments)+1)
	for i, segment := range s.segments {
		prefixBlocked[i+1] = prefixBlocked[i]
		prefixGated[i+1] = prefixGated[i]
		if !segment.allowed && !segment.gate {
			prefixBlocked[i+1]++
		}
		if segment.gate {
			prefixGated[i+1]++
		}
	}

	startBounds := map[time.Time]struct{}{from: {}, lastStart: {}}
	for _, bound := range s.bounds {
		if !bound.Before(from) && !bound.After(lastStart) {
			startBounds[bound] = struct{}{}
		}
		shifted, err := checkedTimeAdd(bound, -duration)
		if err != nil {
			return nil, false, fmt.Errorf("cannot shift sync window boundary by operation duration: %w", err)
		}
		if !shifted.Before(from) && !shifted.After(lastStart) {
			startBounds[shifted] = struct{}{}
		}
	}
	// Companion expansion mirrors the decision boundaries: a shifted boundary
	// instant can be admissible while every later instant in the same start
	// segment is not, and the one-nanosecond segment gives that instant its own
	// classification instead of being absorbed by midpoint sampling.
	expanded := make(map[time.Time]struct{}, len(startBounds)*2)
	for bound := range startBounds {
		expanded[bound] = struct{}{}
		if companion := bound.Add(time.Nanosecond); !companion.After(lastStart) {
			expanded[companion] = struct{}{}
		}
	}
	sorted := make([]time.Time, 0, len(expanded))
	for bound := range expanded {
		sorted = append(sorted, bound)
	}
	slices.SortFunc(sorted, func(a, b time.Time) int { return a.Compare(b) })

	var slots []SyncSlot
	limitHit := false
	var runStart time.Time
	closeRun := func(end time.Time) bool {
		slots = append(slots, SyncSlot{Start: runStart, End: end})
		runStart = time.Time{}
		return len(slots) >= slotLimit
	}
	for i := range len(sorted) - 1 {
		segmentStart := sorted[i]
		// Sample an interior point: coverage evaluated exactly at the left
		// boundary would exclude the boundary instant via half-open semantics
		// and over-approximate the whole segment. One-nanosecond companion
		// segments keep their midpoint on the boundary instant itself.
		sample := segmentMidpoint(sorted[i], sorted[i+1])
		admissible, err := s.admissible(mode, duration, sample, prefixBlocked, prefixGated)
		if err != nil {
			return nil, false, err
		}
		if admissible {
			if runStart.IsZero() {
				runStart = segmentStart
			}
			continue
		}
		if !runStart.IsZero() && closeRun(segmentStart) {
			limitHit = true
			break
		}
	}
	if !limitHit && !runStart.IsZero() {
		slots = append(slots, SyncSlot{Start: runStart, End: lastStart})
		if len(slots) > slotLimit {
			slots = slots[:slotLimit]
			limitHit = true
		}
	}
	return slots, limitHit, nil
}

// admissible evaluates one start-time segment. blocked counts non-gated
// segments where CanSync refuses regardless of start time; gated segments only
// refuse when the operation was not allowed at its start.
func (s slotSegments) admissible(mode SyncSlotMode, duration time.Duration, start time.Time, prefixBlocked, prefixGated []int) (bool, error) {
	end, err := checkedTimeAdd(start, duration)
	if err != nil {
		return false, fmt.Errorf("operation end overflows: %w", err)
	}
	// lo is the decision segment containing start; hi is the first segment
	// starting at or after the operation end.
	lo := max(slices.IndexFunc(s.bounds, func(bound time.Time) bool { return bound.After(start) })-1, 0)
	hi := slices.IndexFunc(s.bounds, func(bound time.Time) bool { return !bound.Before(end) })
	if hi < 0 {
		hi = len(s.segments)
	}
	if prefixBlocked[hi]-prefixBlocked[lo] > 0 {
		return false, nil
	}
	gated := prefixGated[hi] - prefixGated[lo]
	if mode == SyncSlotModeStrict {
		// Without an operation start time the overrun branch is unreachable:
		// a gated segment refuses the operation just like a blocked one.
		return gated == 0, nil
	}
	if gated == 0 {
		return true, nil
	}
	return s.segments[lo].allowedAtStart, nil
}
