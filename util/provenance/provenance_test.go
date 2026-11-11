package provenance

import (
	"context"
	"encoding/json"
	"maps"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func newTestObj(group, kind, namespace, name string, extra map[string]any) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       kind,
		"metadata": map[string]any{
			"name":      name,
			"namespace": namespace,
		},
	}}
	if group != "" {
		obj.Object["apiVersion"] = group + "/v1"
	}
	maps.Copy(obj.Object, extra)
	return obj
}

func TestNewSourceIdentityRedactsCredentialsAndDigestsPath(t *testing.T) {
	t.Parallel()

	identity := NewSourceIdentity(1, "src", "https://s3cr3t-token@github.com/org/repo.git", "abc123", "apps/guestbook", "Directory")

	assert.Equal(t, 1, identity.SourceIndex)
	assert.Equal(t, "https://github.com/org/repo.git", identity.RepoURLRedacted)
	assert.NotContains(t, identity.RepoURLRedacted, "s3cr3t-token")
	assert.Equal(t, "abc123", identity.ResolvedRevision)
	assert.Len(t, identity.PathDigest, 64)
	// Digest must be stable and path-separator independent.
	assert.Equal(t, DigestPath("apps/guestbook"), identity.PathDigest)
	assert.Equal(t, DigestPath("apps/guestbook"), DigestPath("apps\\guestbook"))
}

func TestDirectoryObjectGetsFieldLevelEvidence(t *testing.T) {
	t.Parallel()

	rec := NewRecorder(nil)
	rec.BindSource(NewSourceIdentity(0, "", "https://github.com/org/repo", "deadbeef", "dir", "Directory"))
	docID := rec.RecordInputDocument(0, "manifests/cm.yaml", 0, nil)

	obj := newTestObj("", "ConfigMap", "default", "cm", map[string]any{
		"data": map[string]any{"key": "value"},
	})
	rec.RecordDirectoryObject(0, obj, docID)

	graph := rec.Graph()
	require.NoError(t, graph.Validate())
	require.Len(t, graph.Objects, 1)
	node := graph.Objects[0]
	assert.Equal(t, EvidenceFieldLevel, node.Level)
	assert.Equal(t, docID, node.DocumentID)

	paths := make(map[string]FieldEvidence)
	for _, f := range node.Fields {
		paths[f.FieldPath] = f
	}
	assert.Contains(t, paths, "apiVersion")
	assert.Contains(t, paths, "kind")
	assert.Contains(t, paths, "data")
	assert.Contains(t, paths, "metadata")
	assert.Contains(t, paths, "metadata.name")
	assert.Contains(t, paths, "metadata.namespace")
	for _, f := range node.Fields {
		assert.True(t, IsPreciseFieldEvidence(f), "directory field %q must be precise", f.FieldPath)
		assert.Equal(t, docID, f.DocumentID)
	}

	require.Len(t, graph.Documents, 1)
	assert.Equal(t, "manifests/cm.yaml", graph.Documents[0].RepoRelativePath)
	assert.Empty(t, graph.Documents[0].InputText, "input text must not be stored by default")
}

func TestInputDocumentTextOnlyStoredWhenEnabled(t *testing.T) {
	t.Parallel()

	content := []byte("apiVersion: v1\nkind: ConfigMap\n")

	rec := NewRecorder(nil)
	rec.RecordInputDocument(0, "cm.yaml", 0, content)
	assert.Empty(t, rec.Graph().Documents[0].InputText)
	assert.NotEmpty(t, rec.Graph().Documents[0].ContentDigest)

	recWithText := NewRecorder(&Options{IncludeInputText: true})
	recWithText.RecordInputDocument(0, "cm.yaml", 0, content)
	assert.Equal(t, string(content), recWithText.Graph().Documents[0].InputText)
}

func TestOpaqueObjectNeverCarriesPreciseFieldEvidence(t *testing.T) {
	t.Parallel()

	rec := NewRecorder(nil)
	rec.BindSource(NewSourceIdentity(0, "", "https://github.com/org/repo", "deadbeef", "chart", "Helm"))
	obj := newTestObj("", "ConfigMap", "default", "cm", nil)
	rec.RecordOpaqueObject(0, obj, "Helm")
	// A derived tracking field may still be attached.
	rec.RecordDerivedField(obj, `metadata.labels["app.kubernetes.io/instance"]`, DerivedTrackingMetadata)

	graph := rec.Graph()
	require.NoError(t, graph.Validate())
	node := graph.Objects[0]
	assert.Equal(t, EvidenceOpaque, node.Level)
	assert.Equal(t, "Helm", node.Note)
	var derived *FieldEvidence
	for i := range node.Fields {
		f := node.Fields[i]
		assert.NotEqual(t, EvidenceFieldLevel, f.Level, "opaque object must not expose precise evidence: %+v", f)
		if f.FieldPath == `metadata.labels["app.kubernetes.io/instance"]` {
			derived = &node.Fields[i]
		}
	}
	require.NotNil(t, derived)
	assert.Equal(t, EvidenceDerived, derived.Level)
	assert.Equal(t, DerivedTrackingMetadata, derived.DerivedReason)

	// Tampering with the graph to pretend precision must be rejected by Validate.
	node.Level = EvidenceOpaque
	node.Fields = append(node.Fields, FieldEvidence{FieldPath: "spec.replicas", Level: EvidenceFieldLevel, DocumentID: "doc-x", SourceIndex: 0})
	err := graph.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must not carry precise field evidence")
}

func TestListExpansionIsExplicitlyDerived(t *testing.T) {
	t.Parallel()

	rec := NewRecorder(nil)
	docID := rec.RecordInputDocument(0, "list.yaml", 0, nil)

	item := newTestObj("", "ConfigMap", "default", "cm", nil)
	list := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "List",
		"items":      []any{item.Object},
	}}
	rec.RecordDirectoryObject(0, list, docID)
	rec.RecordListExpansion(0, list, item)

	graph := rec.Graph()
	require.NoError(t, graph.Validate())
	var itemNode *ObjectProvenance
	for _, o := range graph.Objects {
		if o.Kind == "ConfigMap" {
			itemNode = o
		}
	}
	require.NotNil(t, itemNode)
	require.Len(t, itemNode.Derived, 1)
	assert.Equal(t, DerivedListExpansion, itemNode.Derived[0].Reason)
	assert.Equal(t, docID, itemNode.Derived[0].DocumentID)
	// Body fields remain precise against the parent document.
	assert.Equal(t, EvidenceFieldLevel, itemNode.Level)
}

func TestDerivedFieldReplacesPriorPreciseEvidence(t *testing.T) {
	t.Parallel()

	rec := NewRecorder(nil)
	docID := rec.RecordInputDocument(0, "cm.yaml", 0, nil)
	obj := newTestObj("", "ConfigMap", "", "cm", nil)
	rec.RecordDirectoryObject(0, obj, docID)

	rec.RecordDerivedField(obj, "metadata.namespace", DerivedDefaultNamespace)
	graph := rec.Graph()
	var nsEvidence *FieldEvidence
	for i := range graph.Objects[0].Fields {
		if graph.Objects[0].Fields[i].FieldPath == "metadata.namespace" {
			nsEvidence = &graph.Objects[0].Fields[i]
		}
	}
	require.NotNil(t, nsEvidence)
	assert.Equal(t, EvidenceDerived, nsEvidence.Level)
	assert.Equal(t, DerivedDefaultNamespace, nsEvidence.DerivedReason)
	assert.Empty(t, nsEvidence.DocumentID, "derived field must not reference an input document")
}

func TestWholeObjectOverrideDoesNotInheritOverriddenFields(t *testing.T) {
	t.Parallel()

	rec := NewRecorder(nil)
	// Two sources produce the same identity.
	objs := []*unstructured.Unstructured{
		newTestObj("", "ConfigMap", "default", "cm", map[string]any{"data": map[string]any{"from": "source-0"}}),
		newTestObj("", "ConfigMap", "default", "cm", map[string]any{"data": map[string]any{"from": "source-1"}}),
	}
	rec.RecordSourceOutput(NewSourceIdentity(0, "", "https://github.com/org/repo", "rev0", "a", "Directory"), nil, objs[:1])
	rec.RecordSourceOutput(NewSourceIdentity(1, "", "https://github.com/org/repo", "rev1", "b", "Directory"), nil, objs[1:])

	rec.RecordIdentityOverride(1, []int{0}, "/ConfigMap/default/cm")

	graph := rec.Graph()
	require.NoError(t, graph.Validate())
	require.Len(t, graph.Objects, 2)

	var winner, loser *ObjectProvenance
	for _, o := range graph.Objects {
		switch o.SourceIndex {
		case 0:
			loser = o
		case 1:
			winner = o
		}
	}
	require.NotNil(t, winner)
	require.NotNil(t, loser)
	assert.Equal(t, OutcomeWinner, winner.Outcome)
	assert.Equal(t, OutcomeOverridden, loser.Outcome)

	var outcomes []ContributionOutcome
	for _, c := range winner.Contributions {
		outcomes = append(outcomes, c.Outcome)
	}
	assert.Contains(t, outcomes, OutcomeOverridden)
	assert.NotEmpty(t, winner.Warnings)

	// Even if the loser had precise field evidence, the winner must not reference it.
	for _, f := range winner.Fields {
		assert.NotEqual(t, 0, f.SourceIndex, "winner must not inherit fields from overridden source 0")
	}
}

func TestLimitsTruncateNodesAndFields(t *testing.T) {
	t.Parallel()

	rec := NewRecorder(&Options{MaxNodes: 1, MaxFieldsPerObject: 2, MaxOutputBytes: DefaultMaxOutputBytes})
	docID := rec.RecordInputDocument(0, "cm.yaml", 0, nil)
	obj1 := newTestObj("", "ConfigMap", "default", "cm1", nil)
	obj2 := newTestObj("", "ConfigMap", "default", "cm2", nil)
	rec.RecordDirectoryObject(0, obj1, docID)
	rec.RecordDirectoryObject(0, obj2, docID)

	graph := rec.Graph()
	assert.True(t, graph.Truncated)
	assert.Equal(t, 1, graph.OmittedNodes)
	assert.Len(t, graph.Objects, 1)
	assert.Len(t, graph.Objects[0].Fields, 2)
	assert.Positive(t, graph.OmittedFields)
}

func TestByteBudgetDropsOptionalContent(t *testing.T) {
	t.Parallel()

	rec := NewRecorder(&Options{MaxOutputBytes: 512, IncludeInputText: true})
	docID := rec.RecordInputDocument(0, "cm.yaml", 0, []byte(strings.Repeat("x", 2000)))
	obj := newTestObj("", "ConfigMap", "default", "cm", map[string]any{"data": map[string]any{"k": "v"}})
	rec.RecordDirectoryObject(0, obj, docID)

	graph := rec.Graph()
	data, err := json.Marshal(graph)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(data), 512)
	assert.True(t, graph.Truncated)
	for _, doc := range graph.Documents {
		assert.Empty(t, doc.InputText)
	}
}

func TestUnavailableOnCachedArtifactMismatch(t *testing.T) {
	t.Parallel()

	cached := NewRecorder(nil).Graph()
	cached.ArtifactVersion = "v0-old"

	rec := NewRecorder(nil)
	rec.ImportCachedGraph(cached)
	graph := rec.Graph()
	assert.Equal(t, StatusUnavailable, graph.Status)
	assert.NotEmpty(t, graph.UnavailableReason)
}

func TestReusesCachedGraphWhenArtifactVersionMatches(t *testing.T) {
	t.Parallel()

	source := NewRecorder(nil)
	source.RecordInputDocument(0, "cm.yaml", 0, nil)
	source.RecordOpaqueObject(0, newTestObj("", "ConfigMap", "default", "cm", nil), "Kustomize")
	cached := source.Graph()

	rec := NewRecorder(nil)
	rec.ImportCachedGraph(cached)
	graph := rec.Graph()
	assert.Equal(t, StatusAvailable, graph.Status)
	require.Len(t, graph.Objects, 1)
	assert.Equal(t, EvidenceOpaque, graph.Objects[0].Level)
}

func TestGraphNeverContainsCheckoutRootOrCredentials(t *testing.T) {
	t.Parallel()

	checkoutRoot := `C:\Users\runner\AppData\Local\Temp\argocd-repo-12345`
	rec := NewRecorder(&Options{IncludeInputText: true})
	rec.BindSource(NewSourceIdentity(0, "", "https://user:pass@github.com/org/repo.git", "deadbeef", "dir", "Directory"))
	docID := rec.RecordInputDocument(0, "dir/cm.yaml", 0, []byte("kind: ConfigMap\n"))
	rec.RecordDirectoryObject(0, newTestObj("", "ConfigMap", "default", "cm", nil), docID)

	graph := rec.Graph()
	require.NoError(t, graph.Validate())
	require.NoError(t, graph.AssertNoSensitiveData(checkoutRoot, "user:pass", "pass"))
	for _, doc := range graph.Documents {
		assert.False(t, strings.HasPrefix(doc.RepoRelativePath, "/"))
	}
	for _, src := range graph.Sources {
		assert.NotContains(t, src.RepoURLRedacted, "pass")
	}
}

func TestRecorderContextRoundTrip(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	assert.Nil(t, RecorderFromContext(ctx))

	rec := NewRecorder(nil)
	ctx = WithRecorder(ctx, rec)
	assert.Same(t, rec, RecorderFromContext(ctx))

	// Nil recorder must leave the context untouched.
	assert.Equal(t, ctx, WithRecorder(ctx, nil))
}

func TestOutputDigestAlignsWithDeliveredBytes(t *testing.T) {
	t.Parallel()

	rec := NewRecorder(nil)
	obj := newTestObj("", "ConfigMap", "default", "cm", nil)
	manifest := []byte(`{"apiVersion":"v1","kind":"ConfigMap"}`)
	rec.RecordOpaqueObject(0, obj, "Helm")
	rec.RecordOutputManifest(obj, manifest)

	graph := rec.Graph()
	assert.Equal(t, DigestBytes(manifest), graph.Objects[0].OutputDigest)
}

func TestSameNameDifferentNamespaceAreDistinctNodes(t *testing.T) {
	t.Parallel()

	rec := NewRecorder(nil)
	objs := []*unstructured.Unstructured{
		newTestObj("", "ConfigMap", "ns-a", "cm", nil),
		newTestObj("", "ConfigMap", "ns-b", "cm", nil),
	}
	rec.RecordSourceOutput(NewSourceIdentity(0, "", "https://github.com/org/repo", "rev", "dir", "Directory"), nil, objs)

	graph := rec.Graph()
	require.Len(t, graph.Objects, 2)
	assert.NotEqual(t, graph.Objects[0].ObjectKey, graph.Objects[1].ObjectKey)
	for _, o := range graph.Objects {
		assert.Equal(t, OutcomeWinner, o.Outcome, "different namespaces must not be treated as overrides")
	}
}
