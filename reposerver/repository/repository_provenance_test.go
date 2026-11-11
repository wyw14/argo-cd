package repository

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/argoproj/argo-cd/v3/common"
	"github.com/argoproj/argo-cd/v3/pkg/apis/application/v1alpha1"
	"github.com/argoproj/argo-cd/v3/reposerver/apiclient"
	"github.com/argoproj/argo-cd/v3/reposerver/cache"
	"github.com/argoproj/argo-cd/v3/util/git"
	"github.com/argoproj/argo-cd/v3/util/provenance"
)

// findObjectNode locates an object node by kind and name.
func findObjectNode(t *testing.T, g *provenance.ManifestProvenanceGraph, kind, name string) *provenance.ObjectProvenance {
	t.Helper()
	for _, obj := range g.Objects {
		if obj.Kind == kind && obj.Name == name {
			return obj
		}
	}
	require.Failf(t, "object node not found", "kind=%s name=%s", kind, name)
	return nil
}

func fieldByPath(node *provenance.ObjectProvenance, path string) (provenance.FieldEvidence, bool) {
	for _, f := range node.Fields {
		if f.FieldPath == path {
			return f, true
		}
	}
	return provenance.FieldEvidence{}, false
}

func writeFile(t *testing.T, root, name, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Join(root, filepath.Dir(name)), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, name), []byte(content), 0o644))
}

func provenanceRequest() *apiclient.ManifestRequest {
	return &apiclient.ManifestRequest{
		Repo:               &v1alpha1.Repository{Repo: "https://s3cr3t-token@github.com/org/repo.git"},
		ApplicationSource:  &v1alpha1.ApplicationSource{Path: "."},
		ProjectName:        "something",
		ProjectSourceRepos: []string{"*"},
		Revision:           "deadbeef",
	}
}

// Native directory YAML/JSON must produce precise field-level evidence tied to concrete input
// documents, including document indexes inside multi-document YAML.
func TestProvenance_DirectoryFieldLevelEvidence(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "multi.yaml", `---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: sa1
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: sa2
---
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: sa3
`)
	writeFile(t, root, "cm.json", `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"cm-json","namespace":"default"},"data":{"k":"v"}}`)

	q := provenanceRequest()
	rec := provenance.NewRecorder(nil)
	ctx := provenance.WithRecorder(t.Context(), rec)

	res, err := GenerateManifests(ctx, root, root, "deadbeef", q, false, &git.NoopCredsStore{}, resource.MustParse("0"), nil)
	require.NoError(t, err)
	require.NotEmpty(t, res.Manifests)

	graph := rec.Graph()
	require.NoError(t, graph.Validate())
	assert.Equal(t, provenance.StatusAvailable, graph.Status)

	// Source identity is redacted and bound to the resolved revision and path digest.
	require.Len(t, graph.Sources, 1)
	src := graph.Sources[0]
	assert.Equal(t, "https://github.com/org/repo.git", src.RepoURLRedacted)
	assert.NotContains(t, src.RepoURLRedacted, "s3cr3t-token")
	assert.Equal(t, "deadbeef", src.ResolvedRevision)
	assert.Equal(t, provenance.DigestPath("."), src.PathDigest)
	assert.Equal(t, "Directory", src.SourceType)

	// Document references are repository-relative, never absolute checkout paths, and carry no
	// input text by default.
	docByPath := make(map[string]provenance.InputDocumentRef)
	for _, doc := range graph.Documents {
		docByPath[doc.RepoRelativePath] = doc
		assert.False(t, filepath.IsAbs(doc.RepoRelativePath))
		assert.Empty(t, doc.InputText)
		assert.Len(t, doc.PathDigest, 64)
	}
	require.Contains(t, docByPath, "multi.yaml")
	require.Contains(t, docByPath, "cm.json")

	// Every decoded document gets a stable, sequential document index within its file.
	sa1 := findObjectNode(t, graph, "ServiceAccount", "sa1")
	sa2 := findObjectNode(t, graph, "ServiceAccount", "sa2")
	sa3 := findObjectNode(t, graph, "ServiceAccount", "sa3")
	assert.Equal(t, provenance.EvidenceFieldLevel, sa1.Level)
	assert.Equal(t, provenance.EvidenceFieldLevel, sa2.Level)
	assert.Equal(t, 0, graph.Documents[0].DocumentIndex)
	indexes := []int{}
	for _, doc := range graph.Documents {
		if doc.RepoRelativePath == "multi.yaml" {
			indexes = append(indexes, doc.DocumentIndex)
		}
	}
	assert.Equal(t, []int{0, 1, 2}, indexes)
	require.NotEmpty(t, sa3.DocumentID)
	sa3Doc := docByPath["multi.yaml"]
	assert.Equal(t, "multi.yaml", sa3Doc.RepoRelativePath)
	for _, f := range sa3.Fields {
		assert.True(t, provenance.IsPreciseFieldEvidence(f), "sa3 field %q must be precise", f.FieldPath)
	}

	cm := findObjectNode(t, graph, "ConfigMap", "cm-json")
	assert.Equal(t, provenance.EvidenceFieldLevel, cm.Level)
	dataField, ok := fieldByPath(cm, "data")
	require.True(t, ok)
	assert.Equal(t, provenance.EvidenceFieldLevel, dataField.Level)

	// The serialized graph must leak neither credentials nor the temporary checkout root.
	require.NoError(t, graph.AssertNoSensitiveData(root, "s3cr3t-token", "s3cr3t"))
}

// List expansion and tracking metadata are explicit derived evidence, while body fields stay
// precise. Enabling the recorder must not change the rendered bytes.
func TestProvenance_ListExpansionAndTrackingDerived(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "list.yaml", `apiVersion: v1
kind: List
items:
- apiVersion: v1
  kind: ConfigMap
  metadata:
    name: cm-from-list
    namespace: default
  data:
    key: value
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: sa-plain
`)

	q := provenanceRequest()
	q.AppLabelKey = common.LabelKeyAppInstance
	q.AppName = "test-app"
	q.Namespace = "argocd"
	q.TrackingMethod = string(v1alpha1.TrackingMethodAnnotationAndLabel)

	// Baseline without recorder.
	baseline, err := GenerateManifests(t.Context(), root, root, "deadbeef", q, false, &git.NoopCredsStore{}, resource.MustParse("0"), nil)
	require.NoError(t, err)

	rec := provenance.NewRecorder(nil)
	res, err := GenerateManifests(provenance.WithRecorder(t.Context(), rec), root, root, "deadbeef", q, false, &git.NoopCredsStore{}, resource.MustParse("0"), nil)
	require.NoError(t, err)
	assert.Equal(t, baseline.Manifests, res.Manifests, "provenance collection must not change rendered output")

	graph := rec.Graph()
	require.NoError(t, graph.Validate())

	item := findObjectNode(t, graph, "ConfigMap", "cm-from-list")
	require.Len(t, item.Derived, 1)
	assert.Equal(t, provenance.DerivedListExpansion, item.Derived[0].Reason)
	// Body fields remain precise against the parent List document.
	dataField, ok := fieldByPath(item, "data")
	require.True(t, ok)
	assert.Equal(t, provenance.EvidenceFieldLevel, dataField.Level)
	// The output digest matches the exact delivered manifest bytes.
	require.NotEmpty(t, item.OutputDigest)

	// Tracking label and annotation are derived, not verbatim input values.
	labelField, ok := fieldByPath(item, `metadata.labels["app.kubernetes.io/instance"]`)
	require.True(t, ok)
	assert.Equal(t, provenance.EvidenceDerived, labelField.Level)
	assert.Equal(t, provenance.DerivedTrackingMetadata, labelField.DerivedReason)
	annotationField, ok := fieldByPath(item, `metadata.annotations["argocd.argoproj.io/tracking-id"]`)
	require.True(t, ok)
	assert.Equal(t, provenance.EvidenceDerived, annotationField.Level)

	// The plain ServiceAccount gets tracking evidence but no List expansion.
	sa := findObjectNode(t, graph, "ServiceAccount", "sa-plain")
	assert.Empty(t, sa.Derived)
	annotationField, ok = fieldByPath(sa, `metadata.annotations["argocd.argoproj.io/tracking-id"]`)
	require.True(t, ok)
	assert.Equal(t, provenance.EvidenceDerived, annotationField.Level)

	// Every delivered manifest has a matching output digest.
	require.Len(t, graph.Objects, 3) // parent List + two expanded/plain objects
	var digested int
	for _, obj := range graph.Objects {
		if obj.OutputDigest != "" {
			digested++
		}
	}
	assert.Len(t, res.Manifests, digested)
}

// Jsonnet evaluation cannot map output back to template lines, so its objects are Opaque and
// must never expose precise field evidence.
func TestProvenance_JsonnetObjectsAreOpaque(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "cm.jsonnet", `{
  apiVersion: "v1",
  kind: "ConfigMap",
  metadata: { name: "cm-jsonnet", namespace: "default" },
  data: { key: "value" },
}`)

	q := provenanceRequest()
	q.EnabledSourceTypes = map[string]bool{string(v1alpha1.ApplicationSourceTypeDirectory): true}

	rec := provenance.NewRecorder(nil)
	res, err := GenerateManifests(provenance.WithRecorder(t.Context(), rec), root, root, "deadbeef", q, false, &git.NoopCredsStore{}, resource.MustParse("0"), nil)
	require.NoError(t, err)
	require.NotEmpty(t, res.Manifests)

	graph := rec.Graph()
	require.NoError(t, graph.Validate())
	node := findObjectNode(t, graph, "ConfigMap", "cm-jsonnet")
	assert.Equal(t, provenance.EvidenceOpaque, node.Level)
	assert.Contains(t, node.Note, "Jsonnet")
	for _, f := range node.Fields {
		assert.NotEqual(t, provenance.EvidenceFieldLevel, f.Level, "jsonnet output must not be presented as precise evidence")
	}
}

// On a cache hit with a matching provenance artifact, the graph is reused alongside the cached
// manifests. The cache key itself does not change.
func TestProvenance_ServiceCacheHitReusesGraph(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "cm.yaml", `apiVersion: v1
kind: ConfigMap
metadata:
  name: cm-cache
  namespace: default
data:
  k: v
`)
	service := newService(t, root)
	q := provenanceRequest()

	first := provenance.NewRecorder(nil)
	res1, err := service.GenerateManifest(provenance.WithRecorder(t.Context(), first), q)
	require.NoError(t, err)
	graph1 := first.Graph()
	require.NoError(t, graph1.Validate())
	require.Equal(t, provenance.StatusAvailable, graph1.Status)
	require.NotEmpty(t, graph1.Objects)

	// Second call hits the cache; a fresh recorder receives the stored artifact.
	second := provenance.NewRecorder(nil)
	res2, err := service.GenerateManifest(provenance.WithRecorder(t.Context(), second), q)
	require.NoError(t, err)
	assert.Equal(t, res1.Manifests, res2.Manifests)

	graph2 := second.Graph()
	require.NoError(t, graph2.Validate())
	assert.Equal(t, provenance.StatusAvailable, graph2.Status)
	require.Len(t, graph2.Objects, len(graph1.Objects))
	assert.Equal(t, graph1.Objects[0].OutputDigest, graph2.Objects[0].OutputDigest)
	assert.Equal(t, provenance.ArtifactVersion, graph2.ArtifactVersion)

	// The cache entry carries the provenance artifact while the manifest key stays conventional.
	key := cache.NewManifestKey(mock.Anything, q.ApplicationSource, q.GetRefSources(), q.GetNamespace(), q.GetTrackingMethod(),
		q.GetAppLabelKey(), q.GetAppName(), q.GetInstallationID(), q.GetSourceIntegrity(), q, nil)
	entry := cache.CachedManifestResponse{}
	require.NoError(t, service.cache.GetManifests(key, &entry))
	require.NotNil(t, entry.ProvenanceGraph)
	assert.Equal(t, provenance.ArtifactVersion, entry.ProvenanceArtifactVersion)
}

// A cache entry without a provenance artifact (for example produced by an older version or with
// collection disabled) must yield an explicit Unavailable status, never invented evidence. The
// cached manifests are still returned normally.
func TestProvenance_ServiceCacheHitWithoutArtifactIsUnavailable(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "cm.yaml", `apiVersion: v1
kind: ConfigMap
metadata:
  name: cm-stale
  namespace: default
`)
	service := newService(t, root)
	q := provenanceRequest()

	key := cache.NewManifestKey(mock.Anything, q.ApplicationSource, q.GetRefSources(), q.GetNamespace(), q.GetTrackingMethod(),
		q.GetAppLabelKey(), q.GetAppName(), q.GetInstallationID(), q.GetSourceIntegrity(), q, nil)
	cachedManifests := []string{`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"cm-stale","namespace":"default"}}`}
	require.NoError(t, service.cache.SetManifests(key, &cache.CachedManifestResponse{
		ManifestResponse: &apiclient.ManifestResponse{Manifests: cachedManifests, SourceType: "Directory"},
	}))

	rec := provenance.NewRecorder(nil)
	res, err := service.GenerateManifest(provenance.WithRecorder(t.Context(), rec), q)
	require.NoError(t, err)
	assert.Equal(t, cachedManifests, res.Manifests, "cached manifests must still be served")

	graph := rec.Graph()
	assert.Equal(t, provenance.StatusUnavailable, graph.Status)
	assert.NotEmpty(t, graph.UnavailableReason)

	// An explicitly stale artifact version must be rejected the same way.
	require.NoError(t, service.cache.DeleteManifests(key))
	staleGraph := provenance.NewRecorder(nil).Graph()
	staleGraph.ArtifactVersion = "v0-old"
	require.NoError(t, service.cache.SetManifests(key, &cache.CachedManifestResponse{
		ManifestResponse:          &apiclient.ManifestResponse{Manifests: cachedManifests, SourceType: "Directory"},
		ProvenanceGraph:           staleGraph,
		ProvenanceArtifactVersion: "v0-old",
	}))
	rec2 := provenance.NewRecorder(nil)
	_, err = service.GenerateManifest(provenance.WithRecorder(t.Context(), rec2), q)
	require.NoError(t, err)
	graph2 := rec2.Graph()
	assert.Equal(t, provenance.StatusUnavailable, graph2.Status)
	assert.Contains(t, graph2.UnavailableReason, "artifact version")
}

// Rendering without a recorder must remain byte-identical and must not populate provenance.
func TestProvenance_DisabledLeavesRenderingUntouched(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "cm.yaml", `apiVersion: v1
kind: ConfigMap
metadata:
  name: cm-plain
  namespace: default
`)
	service := newService(t, root)
	q := provenanceRequest()

	res, err := service.GenerateManifest(t.Context(), q)
	require.NoError(t, err)
	require.NotEmpty(t, res.Manifests)

	key := cache.NewManifestKey(mock.Anything, q.ApplicationSource, q.GetRefSources(), q.GetNamespace(), q.GetTrackingMethod(),
		q.GetAppLabelKey(), q.GetAppName(), q.GetInstallationID(), q.GetSourceIntegrity(), q, nil)
	entry := cache.CachedManifestResponse{}
	require.NoError(t, service.cache.GetManifests(key, &entry))
	assert.Nil(t, entry.ProvenanceGraph)
	assert.Empty(t, entry.ProvenanceArtifactVersion)
}
