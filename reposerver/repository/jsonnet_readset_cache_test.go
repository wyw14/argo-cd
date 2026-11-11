package repository

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/argoproj/argo-cd/v3/pkg/apis/application/v1alpha1"
	"github.com/argoproj/argo-cd/v3/reposerver/apiclient"
	"github.com/argoproj/argo-cd/v3/util/git"
)

// jsonnetCacheFixture bundles a temp checkout with the entry and library used
// by the read-set cache tests.
type jsonnetCacheFixture struct {
	*jsonnetFixture
}

func newJsonnetCacheFixture(t *testing.T) *jsonnetCacheFixture {
	t.Helper()
	return &jsonnetCacheFixture{jsonnetFixture: newJsonnetFixture(t)}
}

// entrySource is a single native Jsonnet entry whose only repository input is
// params.libsonnet next to it.
const jsonnetCacheEntry = `local params = import 'params.libsonnet';
{
  apiVersion: 'v1',
  kind: 'ConfigMap',
  metadata: { name: 'jsonnet-cache' },
  data: { value: params.value },
}
`

const jsonnetCacheExtVarEntry = `{
  apiVersion: 'v1',
  kind: 'ConfigMap',
  metadata: { name: 'jsonnet-cache' },
  data: { env: std.extVar('env') },
}
`

func jsonnetParamsLib(value string) string {
	return `{ value: ` + strconv.Quote(value) + ` }
`
}

// generateJsonnetWithCache renders the fixture through the package-level
// GenerateManifests entry point with the read-set cache option enabled, the
// same path production traffic takes.
func generateJsonnetWithCache(t *testing.T, appPath, repoRoot string, src v1alpha1.ApplicationSource, c *jsonnetReadSetCache, mutateReq func(*apiclient.ManifestRequest)) (*apiclient.ManifestResponse, error) {
	t.Helper()
	if src.Directory == nil {
		src.Directory = &v1alpha1.ApplicationSourceDirectory{}
	}
	if src.Path == "" {
		rel, err := filepath.Rel(repoRoot, appPath)
		require.NoError(t, err)
		src.Path = filepath.ToSlash(rel)
	}
	q := &apiclient.ManifestRequest{
		Repo:               &v1alpha1.Repository{},
		ApplicationSource:  &src,
		ProjectName:        "jsonnet-read-set",
		ProjectSourceRepos: []string{"*"},
	}
	if mutateReq != nil {
		mutateReq(q)
	}
	return GenerateManifests(t.Context(), appPath, repoRoot, "", q, false, &git.NoopCredsStore{}, resource.MustParse("0"), nil, WithJsonnetReadSetCache(c))
}

// assertFreshRenderEquals re-renders the same tree without any cache and
// proves the cached response is byte-for-byte identical to a from-scratch run.
func assertFreshRenderEquals(t *testing.T, appPath, repoRoot string, src v1alpha1.ApplicationSource, cached *apiclient.ManifestResponse) {
	t.Helper()
	fresh, err := generateJsonnet(t, appPath, repoRoot, src)
	require.NoError(t, err)
	require.NotNil(t, fresh)
	assert.Equal(t, fresh.Manifests, cached.Manifests)
	assert.Equal(t, fresh.SourceType, cached.SourceType)
	assert.Equal(t, fresh.Commands, cached.Commands)
}

func TestJsonnetReadSetCacheDisabledByDefault(t *testing.T) {
	t.Parallel()
	f := newJsonnetCacheFixture(t)
	f.write(t, filepath.Join(f.appDir, "app.jsonnet"), jsonnetCacheEntry)
	f.write(t, filepath.Join(f.appDir, "params.libsonnet"), jsonnetParamsLib("v1"))

	// An explicitly disabled cache must behave exactly like the old path:
	// every render evaluates a fresh VM and nothing is stored.
	c := newJsonnetReadSetCache(false, 10, 100, 100, 1<<20)
	src := v1alpha1.ApplicationSource{}

	res, err := generateJsonnetWithCache(t, f.appDir, f.repoRoot, src, c, nil)
	require.NoError(t, err)
	require.NotNil(t, res)
	res, err = generateJsonnetWithCache(t, f.appDir, f.repoRoot, src, c, nil)
	require.NoError(t, err)
	require.NotNil(t, res)

	stats := c.stats()
	assert.Equal(t, int64(2), stats.VMEvaluations)
	assert.Equal(t, int64(0), stats.Hits)
	assert.Equal(t, int64(0), stats.Stores)
	assert.Equal(t, 0, stats.Entries)

	// The nil-cache path (streamed uploads, local CLI renders) stays inert.
	res, err = generateJsonnet(t, f.appDir, f.repoRoot, src)
	require.NoError(t, err)
	require.NotNil(t, res)
}

func TestJsonnetReadSetCacheHitOnUnrelatedFileChange(t *testing.T) {
	t.Parallel()
	f := newJsonnetCacheFixture(t)
	f.write(t, filepath.Join(f.appDir, "app.jsonnet"), jsonnetCacheEntry)
	f.write(t, filepath.Join(f.appDir, "params.libsonnet"), jsonnetParamsLib("v1"))

	c := newJsonnetReadSetCache(true, 10, 100, 100, 1<<20)
	src := v1alpha1.ApplicationSource{}

	first, err := generateJsonnetWithCache(t, f.appDir, f.repoRoot, src, c, nil)
	require.NoError(t, err)
	require.NotNil(t, first)
	require.Equal(t, int64(1), c.stats().VMEvaluations)
	require.Equal(t, int64(1), c.stats().Stores)

	// A new revision that only adds an unrelated non-manifest file must not
	// force re-evaluation: none of the recorded reads or negative facts move.
	f.write(t, filepath.Join(f.appDir, "README.md"), "unrelated documentation\n")

	second, err := generateJsonnetWithCache(t, f.appDir, f.repoRoot, src, c, nil)
	require.NoError(t, err)
	require.NotNil(t, second)

	stats := c.stats()
	assert.Equal(t, int64(1), stats.VMEvaluations, "VM must not be re-evaluated on a cache hit")
	assert.Equal(t, int64(1), stats.Hits)
	assert.Equal(t, first.Manifests, second.Manifests)
	assert.Equal(t, first.SourceType, second.SourceType)

	// The reused output is identical to evaluating from scratch.
	assertFreshRenderEquals(t, f.appDir, f.repoRoot, src, second)
}

func TestJsonnetReadSetCacheMissWhenImportedFileChanges(t *testing.T) {
	t.Parallel()
	f := newJsonnetCacheFixture(t)
	f.write(t, filepath.Join(f.appDir, "app.jsonnet"), jsonnetCacheEntry)
	f.write(t, filepath.Join(f.appDir, "params.libsonnet"), jsonnetParamsLib("v1"))

	c := newJsonnetReadSetCache(true, 10, 100, 100, 1<<20)
	src := v1alpha1.ApplicationSource{}

	first, err := generateJsonnetWithCache(t, f.appDir, f.repoRoot, src, c, nil)
	require.NoError(t, err)
	require.NotNil(t, first)
	assert.Contains(t, first.Manifests[0], "v1")

	// The imported blob changes: the content digest recorded in the read-set
	// no longer matches, so verification fails and the VM must re-evaluate.
	f.write(t, filepath.Join(f.appDir, "params.libsonnet"), jsonnetParamsLib("v2"))

	second, err := generateJsonnetWithCache(t, f.appDir, f.repoRoot, src, c, nil)
	require.NoError(t, err)
	require.NotNil(t, second)

	stats := c.stats()
	assert.Equal(t, int64(2), stats.VMEvaluations)
	assert.Equal(t, int64(0), stats.Hits)
	// The first render misses because no entry exists yet; the second one
	// misses because the recorded content digest no longer verifies.
	assert.Equal(t, int64(2), stats.Misses)
	assert.NotEqual(t, first.Manifests, second.Manifests)
	assert.Contains(t, second.Manifests[0], "v2")
	assertFreshRenderEquals(t, f.appDir, f.repoRoot, src, second)
}

func TestJsonnetReadSetCacheMissWhenEntryFileChanges(t *testing.T) {
	t.Parallel()
	f := newJsonnetCacheFixture(t)
	f.write(t, filepath.Join(f.appDir, "app.jsonnet"), jsonnetCacheEntry)
	f.write(t, filepath.Join(f.appDir, "params.libsonnet"), jsonnetParamsLib("v1"))

	c := newJsonnetReadSetCache(true, 10, 100, 100, 1<<20)
	src := v1alpha1.ApplicationSource{}

	_, err := generateJsonnetWithCache(t, f.appDir, f.repoRoot, src, c, nil)
	require.NoError(t, err)

	// The entry itself is part of the read-set (it is loaded through the same
	// confined importer), so editing it invalidates the cached render.
	f.write(t, filepath.Join(f.appDir, "app.jsonnet"), jsonnetCacheEntry+"// touched in a new revision\n")

	_, err = generateJsonnetWithCache(t, f.appDir, f.repoRoot, src, c, nil)
	require.NoError(t, err)
	assert.Equal(t, int64(2), c.stats().VMEvaluations)
	assert.Equal(t, int64(0), c.stats().Hits)
}

func TestJsonnetReadSetCacheMissOnNewHigherPriorityFile(t *testing.T) {
	t.Parallel()
	f := newJsonnetCacheFixture(t)
	// params.libsonnet only exists in the vendor library path. The importer
	// first probes <appDir>/params.libsonnet, which does not exist; that
	// negative fact has to be recorded.
	f.write(t, filepath.Join(f.repoRoot, "vendor", "params.libsonnet"), jsonnetParamsLib("from-vendor"))
	f.write(t, filepath.Join(f.appDir, "app.jsonnet"), jsonnetCacheEntry)

	c := newJsonnetReadSetCache(true, 10, 100, 100, 1<<20)
	src := v1alpha1.ApplicationSource{
		Directory: &v1alpha1.ApplicationSourceDirectory{
			Jsonnet: v1alpha1.ApplicationSourceJsonnet{
				Libs: []string{"vendor"},
			},
		},
	}

	first, err := generateJsonnetWithCache(t, f.appDir, f.repoRoot, src, c, nil)
	require.NoError(t, err)
	require.NotNil(t, first)
	assert.Contains(t, first.Manifests[0], "from-vendor")

	// Sanity check: the higher-priority candidate really was recorded as a
	// negative fact, not just the successful vendor import.
	entry, ok := c.lookup(onlyCacheKey(t, c))
	require.True(t, ok)
	var sawMissingAppParams bool
	for _, negative := range entry.Missing {
		if negative.RelPath == filepath.ToSlash(filepath.Join("app", "params.libsonnet")) {
			sawMissingAppParams = true
		}
	}
	assert.True(t, sawMissingAppParams, "missing higher-priority import candidate must be recorded")

	// A new revision adds the same-named file in the app directory, which the
	// importer prefers over the vendor library. Reusing the old output would be
	// wrong, so the negative-fact check must force a miss.
	f.write(t, filepath.Join(f.appDir, "params.libsonnet"), jsonnetParamsLib("from-app"))

	second, err := generateJsonnetWithCache(t, f.appDir, f.repoRoot, src, c, nil)
	require.NoError(t, err)
	require.NotNil(t, second)
	assert.Equal(t, int64(2), c.stats().VMEvaluations)
	assert.Equal(t, int64(0), c.stats().Hits)
	assert.Contains(t, second.Manifests[0], "from-app")
	assert.NotContains(t, second.Manifests[0], "from-vendor")
	assertFreshRenderEquals(t, f.appDir, f.repoRoot, src, second)
}

func TestJsonnetReadSetCacheMissOnExtVarChange(t *testing.T) {
	t.Parallel()
	f := newJsonnetCacheFixture(t)
	f.write(t, filepath.Join(f.appDir, "app.jsonnet"), jsonnetCacheExtVarEntry)

	c := newJsonnetReadSetCache(true, 10, 100, 100, 1<<20)

	srcWith := func(env string) v1alpha1.ApplicationSource {
		return v1alpha1.ApplicationSource{
			Directory: &v1alpha1.ApplicationSourceDirectory{
				Jsonnet: v1alpha1.ApplicationSourceJsonnet{
					ExtVars: []v1alpha1.JsonnetVar{{Name: "env", Value: env}},
				},
			},
		}
	}

	prod, err := generateJsonnetWithCache(t, f.appDir, f.repoRoot, srcWith("prod"), c, nil)
	require.NoError(t, err)
	require.NotNil(t, prod)
	assert.Contains(t, prod.Manifests[0], "prod")

	dev, err := generateJsonnetWithCache(t, f.appDir, f.repoRoot, srcWith("dev"), c, nil)
	require.NoError(t, err)
	require.NotNil(t, dev)

	// Different semantic inputs produce different cache keys, so the second
	// render cannot reuse the first one despite an identical working tree.
	stats := c.stats()
	assert.Equal(t, int64(2), stats.VMEvaluations)
	assert.Equal(t, 2, stats.Entries)
	assert.Contains(t, dev.Manifests[0], "dev")
	assertFreshRenderEquals(t, f.appDir, f.repoRoot, srcWith("dev"), dev)

	// The same extVar still hits the entry produced for that exact input.
	prodAgain, err := generateJsonnetWithCache(t, f.appDir, f.repoRoot, srcWith("prod"), c, nil)
	require.NoError(t, err)
	assert.Equal(t, prod.Manifests, prodAgain.Manifests)
	assert.Equal(t, int64(1), c.stats().Hits)
}

func TestJsonnetReadSetCacheKeyIsolation(t *testing.T) {
	t.Parallel()
	f := newJsonnetCacheFixture(t)
	f.write(t, filepath.Join(f.appDir, "app.jsonnet"), jsonnetCacheEntry)
	f.write(t, filepath.Join(f.appDir, "params.libsonnet"), jsonnetParamsLib("v1"))

	t.Run("namespace is part of the key", func(t *testing.T) {
		t.Parallel()
		c := newJsonnetReadSetCache(true, 10, 100, 100, 1<<20)
		src := v1alpha1.ApplicationSource{}
		_, err := generateJsonnetWithCache(t, f.appDir, f.repoRoot, src, c, func(q *apiclient.ManifestRequest) { q.Namespace = "namespace-a" })
		require.NoError(t, err)
		_, err = generateJsonnetWithCache(t, f.appDir, f.repoRoot, src, c, func(q *apiclient.ManifestRequest) { q.Namespace = "namespace-b" })
		require.NoError(t, err)
		assert.Equal(t, int64(2), c.stats().VMEvaluations)
		assert.Equal(t, int64(0), c.stats().Hits)
		assert.Equal(t, 2, c.stats().Entries, "an entry must never be reused across namespaces")
	})

	t.Run("repository credential identity is part of the key", func(t *testing.T) {
		t.Parallel()
		c := newJsonnetReadSetCache(true, 10, 100, 100, 1<<20)
		src := v1alpha1.ApplicationSource{}
		withCreds := func(username string) func(*apiclient.ManifestRequest) {
			return func(q *apiclient.ManifestRequest) {
				q.Repo = &v1alpha1.Repository{Repo: "https://example.com/repo.git", Username: username}
			}
		}
		_, err := generateJsonnetWithCache(t, f.appDir, f.repoRoot, src, c, withCreds("deploy-key-a"))
		require.NoError(t, err)
		_, err = generateJsonnetWithCache(t, f.appDir, f.repoRoot, src, c, withCreds("deploy-key-b"))
		require.NoError(t, err)
		assert.Equal(t, int64(2), c.stats().VMEvaluations)
		assert.Equal(t, int64(0), c.stats().Hits, "a render must never reuse another credential's authorization result")
	})

	t.Run("project is part of the key", func(t *testing.T) {
		t.Parallel()
		c := newJsonnetReadSetCache(true, 10, 100, 100, 1<<20)
		src := v1alpha1.ApplicationSource{}
		_, err := generateJsonnetWithCache(t, f.appDir, f.repoRoot, src, c, func(q *apiclient.ManifestRequest) {
			q.ProjectName = "project-a"
			q.ProjectSourceRepos = []string{"https://example.com/repo.git"}
		})
		require.NoError(t, err)
		_, err = generateJsonnetWithCache(t, f.appDir, f.repoRoot, src, c, func(q *apiclient.ManifestRequest) {
			q.ProjectName = "project-b"
			q.ProjectSourceRepos = []string{"https://example.com/repo.git"}
		})
		require.NoError(t, err)
		assert.Equal(t, int64(2), c.stats().VMEvaluations)
		assert.Equal(t, int64(0), c.stats().Hits)
	})
}

func TestJsonnetReadSetCacheNoCacheBypassesReadSetCache(t *testing.T) {
	t.Parallel()
	f := newJsonnetCacheFixture(t)
	f.write(t, filepath.Join(f.appDir, "app.jsonnet"), jsonnetCacheEntry)
	f.write(t, filepath.Join(f.appDir, "params.libsonnet"), jsonnetParamsLib("v1"))

	c := newJsonnetReadSetCache(true, 10, 100, 100, 1<<20)
	src := v1alpha1.ApplicationSource{}

	_, err := generateJsonnetWithCache(t, f.appDir, f.repoRoot, src, c, func(q *apiclient.ManifestRequest) { q.NoCache = true })
	require.NoError(t, err)
	_, err = generateJsonnetWithCache(t, f.appDir, f.repoRoot, src, c, func(q *apiclient.ManifestRequest) { q.NoCache = true })
	require.NoError(t, err)

	stats := c.stats()
	assert.Equal(t, int64(2), stats.VMEvaluations)
	assert.Equal(t, int64(0), stats.Hits)
	assert.Equal(t, int64(0), stats.Stores)
}

func TestJsonnetReadSetCacheDoesNotCacheErrorsOrPathEscapes(t *testing.T) {
	t.Parallel()
	f := newJsonnetCacheFixture(t)
	f.write(t, filepath.Join(f.appDir, "app.jsonnet"), jsonnetConfigMap("importstr "+quoted(f.relFromApp(t, f.outsideFile))))

	c := newJsonnetReadSetCache(true, 10, 100, 100, 1<<20)
	src := v1alpha1.ApplicationSource{}

	// The escaping import is rejected by the confined importer and the failed
	// render must never be cached as a success.
	res, err := generateJsonnetWithCache(t, f.appDir, f.repoRoot, src, c, nil)
	assertImportDenied(t, res, err, outsideSentinel)
	assert.Equal(t, 0, c.stats().Entries)
	assert.Equal(t, int64(0), c.stats().Stores)

	// Replace the malicious entry with a legitimate one: the read-set of the
	// failed render did not poison the cache, so the new render succeeds and is
	// cached normally.
	f.write(t, filepath.Join(f.appDir, "app.jsonnet"), jsonnetCacheEntry)
	f.write(t, filepath.Join(f.appDir, "params.libsonnet"), jsonnetParamsLib("safe"))
	res, err = generateJsonnetWithCache(t, f.appDir, f.repoRoot, src, c, nil)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Contains(t, res.Manifests[0], "safe")
	assert.Equal(t, 1, c.stats().Entries)
}

// requireSymlink creates a symlink and skips the test on platforms/accounts
// that are not allowed to create them (e.g. Windows without Developer Mode).
func requireSymlink(t *testing.T, target, link string) {
	t.Helper()
	err := os.Symlink(target, link)
	if err != nil {
		t.Skipf("symlink creation unsupported in this environment: %v", err)
	}
}

func TestJsonnetReadSetCacheSymlinkIdentity(t *testing.T) {
	t.Parallel()
	f := newJsonnetCacheFixture(t)
	noteA := filepath.Join(f.repoRoot, "lib", "note-a.txt")
	noteB := filepath.Join(f.repoRoot, "lib", "note-b.txt")
	f.write(t, noteA, insideSentinel+"-a")
	f.write(t, noteB, insideSentinel+"-b")
	link := filepath.Join(f.appDir, "note-link")
	requireSymlink(t, noteA, link)
	f.write(t, filepath.Join(f.appDir, "app.jsonnet"), jsonnetConfigMap(`importstr 'note-link'`))

	c := newJsonnetReadSetCache(true, 10, 100, 100, 1<<20)
	src := v1alpha1.ApplicationSource{}

	first, err := generateJsonnetWithCache(t, f.appDir, f.repoRoot, src, c, nil)
	require.NoError(t, err)
	require.NotNil(t, first)
	assert.Contains(t, first.Manifests[0], insideSentinel+"-a")

	// Repoint the symlink: even though no blob content changed, the recorded
	// symlink identity no longer matches and the render must be re-evaluated.
	require.NoError(t, os.Remove(link))
	requireSymlink(t, noteB, link)

	second, err := generateJsonnetWithCache(t, f.appDir, f.repoRoot, src, c, nil)
	require.NoError(t, err)
	require.NotNil(t, second)
	assert.Equal(t, int64(2), c.stats().VMEvaluations)
	assert.Equal(t, int64(0), c.stats().Hits)
	assert.Contains(t, second.Manifests[0], insideSentinel+"-b")
	assertFreshRenderEquals(t, f.appDir, f.repoRoot, src, second)
}

func TestJsonnetReadSetCacheLimits(t *testing.T) {
	t.Parallel()
	f := newJsonnetCacheFixture(t)
	f.write(t, filepath.Join(f.appDir, "app.jsonnet"), jsonnetCacheEntry)
	f.write(t, filepath.Join(f.appDir, "params.libsonnet"), jsonnetParamsLib("v1"))

	t.Run("read count limit", func(t *testing.T) {
		t.Parallel()
		// The entry plus the import are two distinct reads; allowing only one
		// makes the read-set too large to cache.
		c := newJsonnetReadSetCache(true, 10, 1, 100, 1<<20)
		src := v1alpha1.ApplicationSource{}
		_, err := generateJsonnetWithCache(t, f.appDir, f.repoRoot, src, c, nil)
		require.NoError(t, err)
		_, err = generateJsonnetWithCache(t, f.appDir, f.repoRoot, src, c, nil)
		require.NoError(t, err)
		stats := c.stats()
		assert.Equal(t, int64(2), stats.VMEvaluations, "over-limit renders must still be served from a fresh VM")
		assert.Equal(t, 0, stats.Entries)
		assert.Equal(t, int64(0), stats.Hits)
	})

	t.Run("byte limit", func(t *testing.T) {
		t.Parallel()
		c := newJsonnetReadSetCache(true, 10, 100, 100, 1)
		src := v1alpha1.ApplicationSource{}
		_, err := generateJsonnetWithCache(t, f.appDir, f.repoRoot, src, c, nil)
		require.NoError(t, err)
		assert.Equal(t, 0, c.stats().Entries)
	})
}

func TestJsonnetReadSetCacheIneligibleMultipleManifests(t *testing.T) {
	t.Parallel()
	f := newJsonnetCacheFixture(t)
	f.write(t, filepath.Join(f.appDir, "app.jsonnet"), jsonnetCacheEntry)
	f.write(t, filepath.Join(f.appDir, "params.libsonnet"), jsonnetParamsLib("v1"))
	// A second, non-jsonnet manifest means the directory is no longer an
	// explicit single native Jsonnet entry; the read-set cache must stay out.
	f.write(t, filepath.Join(f.appDir, "extra.yaml"), "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: extra\ndata: {}\n")

	c := newJsonnetReadSetCache(true, 10, 100, 100, 1<<20)
	src := v1alpha1.ApplicationSource{}

	_, err := generateJsonnetWithCache(t, f.appDir, f.repoRoot, src, c, nil)
	require.NoError(t, err)
	_, err = generateJsonnetWithCache(t, f.appDir, f.repoRoot, src, c, nil)
	require.NoError(t, err)
	assert.Equal(t, 0, c.stats().Entries)
	assert.Equal(t, int64(0), c.stats().Stores)
}

// onlyCacheKey returns the sole cache entry key, failing the test if the entry
// count is not exactly one.
func onlyCacheKey(t *testing.T, c *jsonnetReadSetCache) string {
	t.Helper()
	c.mu.RLock()
	defer c.mu.RUnlock()
	require.Len(t, c.entries, 1)
	for key := range c.entries {
		return key
	}
	return ""
}

func TestJsonnetReadSetCacheDisabledInServiceByDefault(t *testing.T) {
	t.Parallel()
	// A service built with default init constants must keep the cache inert,
	// preserving the pre-feature revision-cache behaviour.
	service := newService(t, t.TempDir())
	require.NotNil(t, service.jsonnetReadSetCache)
	assert.False(t, service.jsonnetReadSetCache.enabled)

	f := newJsonnetCacheFixture(t)
	f.write(t, filepath.Join(f.appDir, "app.jsonnet"), jsonnetCacheEntry)
	f.write(t, filepath.Join(f.appDir, "params.libsonnet"), jsonnetParamsLib("v1"))
	src := v1alpha1.ApplicationSource{}

	first, err := generateJsonnetWithCache(t, f.appDir, f.repoRoot, src, service.jsonnetReadSetCache, nil)
	require.NoError(t, err)
	second, err := generateJsonnetWithCache(t, f.appDir, f.repoRoot, src, service.jsonnetReadSetCache, nil)
	require.NoError(t, err)
	assert.Equal(t, first.Manifests, second.Manifests)
	stats := service.jsonnetReadSetCache.stats()
	assert.Equal(t, int64(2), stats.VMEvaluations, "disabled cache evaluates a VM on every render")
	assert.Equal(t, int64(0), stats.Hits)
	assert.Equal(t, 0, stats.Entries)
}
