package repository

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/go-jsonnet"
	log "github.com/sirupsen/logrus"

	"github.com/argoproj/argo-cd/v3/pkg/apis/application/v1alpha1"
	"github.com/argoproj/argo-cd/v3/reposerver/apiclient"
	"github.com/argoproj/argo-cd/v3/util/io/files"
)

// jsonnetReadSetProtocol is bumped when the record layout, the read-set
// semantics or the native VM evaluation protocol change in a way that makes
// entries produced by an older build unsafe to reuse. It is part of every
// cache key, so mixing builds never reuses stale records.
const jsonnetReadSetProtocol = "native-go-jsonnet-evaluate-file/v1"

// Safety limits for a single recorded Jsonnet evaluation and for the cache as
// a whole. A render whose read-set exceeds any limit is still served
// correctly, but its result is not cached.
const (
	defaultJsonnetReadSetMaxEntries = 512
	defaultJsonnetReadSetMaxReads   = 1000
	defaultJsonnetReadSetMaxChecks  = 4000
	defaultJsonnetReadSetMaxBytes   = 10 * 1024 * 1024
)

// jsonnetReadRecord is a positive read fact: one blob (a regular file,
// possibly reached through a validated in-repo symlink) whose bytes were
// handed to the Jsonnet VM.
type jsonnetReadRecord struct {
	// RelPath is the repository-relative path the importer opened, before
	// symlink resolution.
	RelPath string `json:"relPath"`
	// IsSymlink reports whether RelPath itself is a symlink.
	IsSymlink bool `json:"isSymlink,omitempty"`
	// LinkTarget is the raw os.Readlink result when IsSymlink is true.
	LinkTarget string `json:"linkTarget,omitempty"`
	// ResolvedRel is the repository-relative regular-file path after symlink
	// resolution.
	ResolvedRel string `json:"resolvedRel"`
	// Size is the number of bytes the importer returned for this read.
	Size int64 `json:"size"`
	// SHA256 is the hex digest of the exact bytes the importer returned.
	SHA256 string `json:"sha256"`
}

// jsonnetMissingRecord is a negative fact: a candidate path probed by the
// confined importer's search order that did not exist and therefore let the
// search fall through to a lower-priority location. Recording it is required
// for correctness: a new revision may create a higher-priority file at that
// path, changing import resolution without touching any previously read blob.
type jsonnetMissingRecord struct {
	RelPath string `json:"relPath"`
}

// jsonnetReadSet collects the complete I/O evidence of one native Jsonnet
// evaluation. It is safe for concurrent use only with a single VM evaluation,
// which is how the confined importer uses it.
type jsonnetReadSet struct {
	repoRoot string

	reads   map[string]*jsonnetReadRecord
	missing map[string]jsonnetMissingRecord

	totalBytes int64

	maxReads       int
	maxChecks      int
	maxTotalBytes  int64
	limitsExceeded bool
	// unrepresentable is set when a probed path cannot be expressed relative
	// to repoRoot (e.g. a path on another volume). Such a read-set can never be
	// re-verified on another checkout, so it must not be cached.
	unrepresentable bool
}

func newJsonnetReadSet(repoRoot string, maxReads, maxChecks int, maxTotalBytes int64) *jsonnetReadSet {
	return &jsonnetReadSet{
		repoRoot:      repoRoot,
		reads:         make(map[string]*jsonnetReadRecord),
		missing:       make(map[string]jsonnetMissingRecord),
		maxReads:      maxReads,
		maxChecks:     maxChecks,
		maxTotalBytes: maxTotalBytes,
	}
}

// relRepoPath converts an absolute probe path to its slash-separated path
// relative to repoRoot. Paths escaping the repo root keep their "../"
// segments; a path that cannot be relativized yields ok=false.
func (r *jsonnetReadSet) relRepoPath(absPath string) (string, bool) {
	rel, err := filepath.Rel(r.repoRoot, absPath)
	if err != nil {
		return "", false
	}
	return filepath.ToSlash(filepath.Clean(rel)), true
}

// recordMissing records a non-existent candidate probed by the confined
// importer's search order. It is a no-op when recording is disabled.
func (r *jsonnetReadSet) recordMissing(absPath string) {
	if r == nil {
		return
	}
	rel, ok := r.relRepoPath(absPath)
	if !ok {
		r.unrepresentable = true
		return
	}
	if _, exists := r.missing[rel]; exists {
		return
	}
	if len(r.missing) >= r.maxChecks {
		r.limitsExceeded = true
		return
	}
	r.missing[rel] = jsonnetMissingRecord{RelPath: rel}
}

// recordRead records the identity of a blob the importer successfully
// returned to the VM: its repository-relative path, symlink identity,
// resolved regular-file path, size and content digest. It is a no-op when
// recording is disabled.
func (r *jsonnetReadSet) recordRead(foundAt string, contents jsonnet.Contents) {
	if r == nil {
		return
	}
	rel, ok := r.relRepoPath(foundAt)
	if !ok {
		r.unrepresentable = true
		return
	}
	if _, exists := r.reads[rel]; exists {
		return
	}
	if len(r.reads) >= r.maxReads {
		r.limitsExceeded = true
		return
	}

	record := &jsonnetReadRecord{
		RelPath: rel,
		Size:    int64(len(contents.Data())),
	}

	lstatInfo, err := os.Lstat(foundAt)
	if err != nil {
		r.unrepresentable = true
		return
	}
	record.IsSymlink = files.IsSymlink(lstatInfo)
	if record.IsSymlink {
		target, err := os.Readlink(foundAt)
		if err != nil {
			r.unrepresentable = true
			return
		}
		record.LinkTarget = filepath.ToSlash(target)
	}

	// Mirror the boundary and regular-file checks of confinedImporter.validate
	// so the stored symlink identity is one that already passed confinement.
	resolved, ok, err := files.ResolveInbound(foundAt, r.repoRoot)
	if err != nil || !ok {
		r.unrepresentable = true
		return
	}
	resolvedRel, err := filepath.Rel(r.repoRoot, resolved)
	if err != nil {
		r.unrepresentable = true
		return
	}
	record.ResolvedRel = filepath.ToSlash(filepath.Clean(resolvedRel))

	digest := sha256.Sum256(contents.Data())
	record.SHA256 = hex.EncodeToString(digest[:])

	r.reads[rel] = record
	r.totalBytes += record.Size
	if r.totalBytes > r.maxTotalBytes {
		r.limitsExceeded = true
	}
}

// finalize returns the sorted, deterministic read-set records. ok is false
// when the read-set cannot be cached: a limit was exceeded, a path was not
// representable relative to repoRoot, or no read was recorded at all.
func (r *jsonnetReadSet) finalize() (reads []jsonnetReadRecord, missing []jsonnetMissingRecord, totalBytes int64, ok bool) {
	if r == nil || r.limitsExceeded || r.unrepresentable || len(r.reads) == 0 {
		return nil, nil, 0, false
	}
	reads = make([]jsonnetReadRecord, 0, len(r.reads))
	for _, record := range r.reads {
		reads = append(reads, *record)
	}
	sort.Slice(reads, func(i, j int) bool { return reads[i].RelPath < reads[j].RelPath })

	missing = make([]jsonnetMissingRecord, 0, len(r.missing))
	for _, record := range r.missing {
		missing = append(missing, record)
	}
	sort.Slice(missing, func(i, j int) bool { return missing[i].RelPath < missing[j].RelPath })

	return reads, missing, r.totalBytes, true
}

// jsonnetReadSetEntry is the cached evidence and reusable output of one
// successful native Jsonnet evaluation. It never stores extVar/TLA values,
// repository credentials or any other secret plaintext: semantic inputs are
// only represented by SemanticHash, and records contain relative paths and
// content digests.
type jsonnetReadSetEntry struct {
	SemanticHash string                 `json:"-"`
	RepoURL      string                 `json:"repoURL"`
	Project      string                 `json:"project"`
	Output       string                 `json:"output"`
	Reads        []jsonnetReadRecord    `json:"reads"`
	Missing      []jsonnetMissingRecord `json:"missing"`
	TotalBytes   int64                  `json:"totalBytes"`
	CreatedAt    time.Time              `json:"createdAt"`
}

// jsonnetReadSetCache is an optional, process-local cache that allows native
// Jsonnet renders to skip VM re-evaluation across repository revisions when
// every blob the VM read and every negative search fact can be re-proven
// unchanged on the new, immutable checkout.
//
// Safety model:
//   - Only VMs constructed by this package via newJsonnetVM with a
//     confinedImporter are eligible. Such VMs register no native callbacks and
//     perform no I/O except repository file reads through the importer, so the
//     read-set is a complete description of their inputs. CMP/plugin renders
//     and any VM with native callbacks never reach this code path.
//   - The cache key binds the entry path, resolved extVars/TLAs, library
//     search order, the evaluation protocol, project permissions, request
//     options, namespace and repository/credential identity. A cached entry can
//     never be reused for another namespace, project or credential.
//   - Every positive and negative fact is re-verified on the target checkout
//     before reuse; a single missing proof is a cache miss. Render errors are
//     never cached as successes.
type jsonnetReadSetCache struct {
	enabled bool

	maxEntries int
	maxReads   int
	maxChecks  int
	maxBytes   int64

	mu      sync.RWMutex
	entries map[string]*jsonnetReadSetEntry

	hits          atomic.Int64
	misses        atomic.Int64
	stores        atomic.Int64
	evictions     atomic.Int64
	vmEvaluations atomic.Int64
}

// jsonnetReadSetCacheStats is a point-in-time snapshot of cache counters, used
// for diagnostics and tests.
type jsonnetReadSetCacheStats struct {
	Hits          int64
	Misses        int64
	Stores        int64
	Evictions     int64
	VMEvaluations int64
	Entries       int
}

func newJsonnetReadSetCache(enabled bool, maxEntries, maxReads, maxChecks int, maxBytes int64) *jsonnetReadSetCache {
	if maxEntries <= 0 {
		maxEntries = defaultJsonnetReadSetMaxEntries
	}
	if maxReads <= 0 {
		maxReads = defaultJsonnetReadSetMaxReads
	}
	if maxChecks <= 0 {
		maxChecks = defaultJsonnetReadSetMaxChecks
	}
	if maxBytes <= 0 {
		maxBytes = defaultJsonnetReadSetMaxBytes
	}
	return &jsonnetReadSetCache{
		enabled:    enabled,
		maxEntries: maxEntries,
		maxReads:   maxReads,
		maxChecks:  maxChecks,
		maxBytes:   maxBytes,
		entries:    make(map[string]*jsonnetReadSetEntry),
	}
}

func (c *jsonnetReadSetCache) stats() jsonnetReadSetCacheStats {
	c.mu.RLock()
	entries := len(c.entries)
	c.mu.RUnlock()
	return jsonnetReadSetCacheStats{
		Hits:          c.hits.Load(),
		Misses:        c.misses.Load(),
		Stores:        c.stores.Load(),
		Evictions:     c.evictions.Load(),
		VMEvaluations: c.vmEvaluations.Load(),
		Entries:       entries,
	}
}

func (c *jsonnetReadSetCache) lookup(semanticHash string) (*jsonnetReadSetEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[semanticHash]
	return entry, ok
}

// store inserts or replaces an entry, evicting the oldest entry when the
// per-process entry limit is reached.
func (c *jsonnetReadSetCache) store(semanticHash string, entry *jsonnetReadSetEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[semanticHash]; !exists && len(c.entries) >= c.maxEntries {
		var oldestKey string
		var oldestAt time.Time
		for key, candidate := range c.entries {
			if oldestKey == "" || candidate.CreatedAt.Before(oldestAt) {
				oldestKey = key
				oldestAt = candidate.CreatedAt
			}
		}
		delete(c.entries, oldestKey)
		c.evictions.Add(1)
	}
	c.entries[semanticHash] = entry
	c.stores.Add(1)
}

// verify re-proves every positive read and every negative fact of a cached
// read-set against the current checkout, using the same repository boundary
// and symlink rules as confinedImporter. Any failed or unprovable check is an
// error and therefore a cache miss.
func (c *jsonnetReadSetCache) verify(repoRoot string, entry *jsonnetReadSetEntry) error {
	for _, record := range entry.Reads {
		absPath := filepath.Join(repoRoot, filepath.FromSlash(record.RelPath))

		lstatInfo, err := os.Lstat(absPath)
		if err != nil {
			return fmt.Errorf("read %q cannot be re-proven: %w", record.RelPath, err)
		}
		if files.IsSymlink(lstatInfo) != record.IsSymlink {
			return fmt.Errorf("read %q: symlink identity changed", record.RelPath)
		}
		if record.IsSymlink {
			target, err := os.Readlink(absPath)
			if err != nil {
				return fmt.Errorf("read %q: symlink target cannot be re-proven: %w", record.RelPath, err)
			}
			if filepath.ToSlash(target) != record.LinkTarget {
				return fmt.Errorf("read %q: symlink target changed", record.RelPath)
			}
		}

		// Same boundary and regular-file validation as confinedImporter.validate.
		resolved, ok, err := files.ResolveInbound(absPath, repoRoot)
		if err != nil {
			return fmt.Errorf("read %q: %w", record.RelPath, err)
		}
		if !ok {
			return fmt.Errorf("read %q resolves outside repository root", record.RelPath)
		}
		resolvedRel, err := filepath.Rel(repoRoot, resolved)
		if err != nil {
			return fmt.Errorf("read %q: %w", record.RelPath, err)
		}
		if filepath.ToSlash(filepath.Clean(resolvedRel)) != record.ResolvedRel {
			return fmt.Errorf("read %q: resolved path changed", record.RelPath)
		}
		info, err := os.Stat(resolved)
		if err != nil {
			return fmt.Errorf("read %q: %w", record.RelPath, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("read %q is not a regular file", record.RelPath)
		}

		data, err := os.ReadFile(absPath)
		if err != nil {
			return fmt.Errorf("read %q: %w", record.RelPath, err)
		}
		if int64(len(data)) != record.Size {
			return fmt.Errorf("read %q: size changed", record.RelPath)
		}
		digest := sha256.Sum256(data)
		if hex.EncodeToString(digest[:]) != record.SHA256 {
			return fmt.Errorf("read %q: content changed", record.RelPath)
		}
	}

	for _, negative := range entry.Missing {
		absPath := filepath.Join(repoRoot, filepath.FromSlash(negative.RelPath))
		_, err := os.Lstat(absPath)
		switch {
		case err == nil:
			return fmt.Errorf("negative fact %q violated: path now exists", negative.RelPath)
		case os.IsNotExist(err):
			continue
		default:
			return fmt.Errorf("negative fact %q cannot be re-proven: %w", negative.RelPath, err)
		}
	}
	return nil
}

// jsonnetSemanticKeyInput enumerates every semantic input of a native
// Jsonnet evaluation. It is only ever hashed: the plaintext extVar/TLA values
// and repository credentials it transiently contains are never persisted in a
// cache entry.
type jsonnetSemanticKeyInput struct {
	Protocol           string                              `json:"protocol"`
	RepoURL            string                              `json:"repoURL"`
	RepoIdentityHash   string                              `json:"repoIdentityHash"`
	Project            string                              `json:"project"`
	ProjectSourceRepos []string                            `json:"projectSourceRepos"`
	Namespace          string                              `json:"namespace"`
	AppName            string                              `json:"appName"`
	AppLabelKey        string                              `json:"appLabelKey"`
	TrackingMethod     string                              `json:"trackingMethod"`
	InstallationID     string                              `json:"installationID"`
	EntryRelPath       string                              `json:"entryRelPath"`
	Directory          v1alpha1.ApplicationSourceDirectory `json:"directory"`
	JPaths             []string                            `json:"jpaths"`
	ExtVars            []v1alpha1.JsonnetVar               `json:"extVars"`
	TLAs               []v1alpha1.JsonnetVar               `json:"tlas"`
}

func (k jsonnetSemanticKeyInput) hash() (string, error) {
	data, err := json.Marshal(k)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func buildJsonnetSemanticKeyInput(repoRoot, entryPath string, cfg resolvedJsonnetConfig, directory v1alpha1.ApplicationSourceDirectory, q *apiclient.ManifestRequest) (jsonnetSemanticKeyInput, error) {
	entryRel, err := filepath.Rel(repoRoot, entryPath)
	if err != nil {
		return jsonnetSemanticKeyInput{}, fmt.Errorf("failed to relativize jsonnet entry %q: %w", entryPath, err)
	}

	jpaths := make([]string, 0, len(cfg.jpaths))
	for _, jpath := range cfg.jpaths {
		rel, err := filepath.Rel(repoRoot, jpath)
		if err != nil {
			return jsonnetSemanticKeyInput{}, fmt.Errorf("failed to relativize jsonnet library path %q: %w", jpath, err)
		}
		jpaths = append(jpaths, filepath.ToSlash(filepath.Clean(rel)))
	}

	repoIdentityHash := ""
	if q.Repo != nil {
		// Hashing the full repository configuration binds credential changes
		// into the key without retaining any credential plaintext.
		repoJSON, err := json.Marshal(q.Repo)
		if err != nil {
			return jsonnetSemanticKeyInput{}, fmt.Errorf("failed to hash repository identity: %w", err)
		}
		digest := sha256.Sum256(repoJSON)
		repoIdentityHash = hex.EncodeToString(digest[:])
	}

	projectSourceRepos := slices.Clone(q.ProjectSourceRepos)
	sort.Strings(projectSourceRepos)

	repoURL := ""
	if q.Repo != nil {
		repoURL = q.Repo.Repo
	}

	return jsonnetSemanticKeyInput{
		Protocol:           jsonnetReadSetProtocol,
		RepoURL:            repoURL,
		RepoIdentityHash:   repoIdentityHash,
		Project:            q.ProjectName,
		ProjectSourceRepos: projectSourceRepos,
		Namespace:          q.Namespace,
		AppName:            q.AppName,
		AppLabelKey:        q.AppLabelKey,
		TrackingMethod:     q.TrackingMethod,
		InstallationID:     q.InstallationID,
		EntryRelPath:       filepath.ToSlash(filepath.Clean(entryRel)),
		Directory:          directory,
		JPaths:             jpaths,
		ExtVars:            cfg.extVars,
		TLAs:               cfg.tlas,
	}, nil
}

func newConfinedImporter(repoRoot string, jpaths []string, recorder *jsonnetReadSet) *confinedImporter {
	return &confinedImporter{
		FileImporter: &jsonnet.FileImporter{JPaths: jpaths},
		repoRoot:     repoRoot,
		recorder:     recorder,
	}
}

// evaluateEntry renders a single, eligible native Jsonnet entry, reusing a
// cached evaluation across revisions whenever the complete read-set can be
// re-proven. When the cache is disabled, unavailable or bypassed, it behaves
// exactly like the previous makeJsonnetVM/EvaluateFile path.
func (c *jsonnetReadSetCache) evaluateEntry(appPath, repoRoot, entryPath string, directory v1alpha1.ApplicationSourceDirectory, env *v1alpha1.Env, q *apiclient.ManifestRequest) (string, error) {
	if c == nil {
		return evaluateJsonnetEntryPlain(appPath, repoRoot, directory.Jsonnet, env, entryPath)
	}
	if !c.enabled {
		// Keep an accurate VM invocation count even when the cache is inert,
		// without changing the evaluation path.
		c.vmEvaluations.Add(1)
		return evaluateJsonnetEntryPlain(appPath, repoRoot, directory.Jsonnet, env, entryPath)
	}

	cfg, err := resolveJsonnetConfig(appPath, repoRoot, directory.Jsonnet, env)
	if err != nil {
		// Preserve the exact error behaviour of the standard VM builder.
		vm, vmErr := makeJsonnetVM(appPath, repoRoot, directory.Jsonnet, env)
		if vmErr != nil {
			return "", vmErr
		}
		c.vmEvaluations.Add(1)
		return vm.EvaluateFile(entryPath)
	}

	// Hard refreshes bypass both lookup and storage.
	bypassCache := q == nil || q.NoCache
	if bypassCache {
		vm := newJsonnetVM(cfg, newConfinedImporter(repoRoot, cfg.jpaths, nil))
		c.vmEvaluations.Add(1)
		return vm.EvaluateFile(entryPath)
	}

	keyInput, err := buildJsonnetSemanticKeyInput(repoRoot, entryPath, cfg, directory, q)
	if err != nil {
		log.WithError(err).Debug("jsonnet read-set cache: failed to build cache key, bypassing cache")
		vm := newJsonnetVM(cfg, newConfinedImporter(repoRoot, cfg.jpaths, nil))
		c.vmEvaluations.Add(1)
		return vm.EvaluateFile(entryPath)
	}
	semanticHash, err := keyInput.hash()
	if err != nil {
		log.WithError(err).Debug("jsonnet read-set cache: failed to hash cache key, bypassing cache")
		vm := newJsonnetVM(cfg, newConfinedImporter(repoRoot, cfg.jpaths, nil))
		c.vmEvaluations.Add(1)
		return vm.EvaluateFile(entryPath)
	}

	cached, found := c.lookup(semanticHash)
	var verifyErr error
	if found {
		verifyErr = c.verify(repoRoot, cached)
	}
	if found && verifyErr == nil {
		c.hits.Add(1)
		log.Debugf("jsonnet read-set cache hit for entry %q", keyInput.EntryRelPath)
		// A verified hit reuses the recorded output without invoking a VM.
		return cached.Output, nil
	}
	c.misses.Add(1)
	if verifyErr != nil {
		log.WithError(verifyErr).Debugf("jsonnet read-set cache verification failed for entry %q, re-evaluating", keyInput.EntryRelPath)
	}

	recorder := newJsonnetReadSet(repoRoot, c.maxReads, c.maxChecks, c.maxBytes)
	vm := newJsonnetVM(cfg, newConfinedImporter(repoRoot, cfg.jpaths, recorder))
	c.vmEvaluations.Add(1)
	output, err := vm.EvaluateFile(entryPath)
	if err != nil {
		// Render errors are never cached as successes.
		return "", err
	}

	reads, missing, totalBytes, cacheable := recorder.finalize()
	if cacheable {
		c.store(semanticHash, &jsonnetReadSetEntry{
			SemanticHash: semanticHash,
			RepoURL:      keyInput.RepoURL,
			Project:      keyInput.Project,
			Output:       output,
			Reads:        reads,
			Missing:      missing,
			TotalBytes:   totalBytes,
			CreatedAt:    time.Now(),
		})
	} else {
		log.Debugf("jsonnet read-set cache: read-set for entry %q is not cacheable", keyInput.EntryRelPath)
	}
	return output, nil
}

func evaluateJsonnetEntryPlain(appPath, repoRoot string, sourceJsonnet v1alpha1.ApplicationSourceJsonnet, env *v1alpha1.Env, entryPath string) (string, error) {
	vm, err := makeJsonnetVM(appPath, repoRoot, sourceJsonnet, env)
	if err != nil {
		return "", err
	}
	return vm.EvaluateFile(entryPath)
}
