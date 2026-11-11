package controller

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/argoproj/argo-cd/v3/common"
	"github.com/argoproj/argo-cd/v3/pkg/apis/application/v1alpha1"
	"github.com/argoproj/argo-cd/v3/reposerver/apiclient"
	"github.com/argoproj/argo-cd/v3/test"
	"github.com/argoproj/argo-cd/v3/util/argo"
	"github.com/argoproj/argo-cd/v3/util/provenance"
)

func mustManifestString(t *testing.T, obj map[string]any) string {
	t.Helper()
	data, err := json.Marshal(obj)
	require.NoError(t, err)
	return string(data)
}

func fieldByPath(node *provenance.ObjectProvenance, path string) (provenance.FieldEvidence, bool) {
	for _, f := range node.Fields {
		if f.FieldPath == path {
			return f, true
		}
	}
	return provenance.FieldEvidence{}, false
}

func findProvenanceNode(g *provenance.ManifestProvenanceGraph, sourceIndex int, kind, name string) *provenance.ObjectProvenance {
	for _, obj := range g.Objects {
		if obj.SourceIndex == sourceIndex && obj.Kind == kind && obj.Name == name {
			return obj
		}
	}
	return nil
}

// TestProvenance_GetRepoObjsMultiSourceOverride drives the real GetRepoObjs with a mocked
// repo-server returning per-source manifest strings (as in production reconciles) and then runs
// the real NormalizeTargetObjectsWithProvenance. Provenance is checked against those exact
// outputs and the final rendered bytes.
func TestProvenance_GetRepoObjsMultiSourceOverrideAndNormalize(t *testing.T) {
	app := newFakeApp()
	app.Spec.Source = nil
	app.Spec.Sources = v1alpha1.ApplicationSources{
		{RepoURL: "https://s3cr3t-token@github.com/org/repo.git", Path: "dir-a", TargetRevision: "rev-a"},
		{RepoURL: "https://github.com/org/repo.git", Path: "dir-b", TargetRevision: "rev-b"},
	}
	// No synced revision: evaluateRevisionChanges falls through without additional RPCs.
	app.Status.Sync = v1alpha1.SyncStatus{}

	// Source 0: the shared ConfigMap that will be overridden, plus a namespaced object.
	source0Manifests := []string{
		mustManifestString(t, map[string]any{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata":   map[string]any{"name": "shared"},
			"data":       map[string]any{"origin": "source-a"},
		}),
		mustManifestString(t, map[string]any{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata":   map[string]any{"name": "distinct", "namespace": "ns-a"},
			"data":       map[string]any{"origin": "source-a"},
		}),
	}
	// Source 1: same-identity whole-object override plus the same name in a different namespace.
	source1Manifests := []string{
		mustManifestString(t, map[string]any{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata":   map[string]any{"name": "shared"},
			"data":       map[string]any{"origin": "source-b"},
		}),
		mustManifestString(t, map[string]any{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata":   map[string]any{"name": "distinct", "namespace": "ns-b"},
			"data":       map[string]any{"origin": "source-b"},
		}),
	}

	data := fakeData{
		manifestResponses: []*apiclient.ManifestResponse{
			{Manifests: source0Manifests, Namespace: test.FakeDestNamespace, Revision: "sha-a", SourceType: "Directory"},
			{Manifests: source1Manifests, Namespace: test.FakeDestNamespace, Revision: "sha-b", SourceType: "Directory"},
		},
	}
	ctrl := newFakeController(t.Context(), &data, nil)

	rec := provenance.NewRecorder(nil)
	ctx := provenance.WithRecorder(t.Context(), rec)

	targetObjs, manifestInfos, _, err := ctrl.appStateManager.GetRepoObjs(ctx, app, app.Spec.Sources, common.LabelKeyAppInstance,
		[]string{"rev-a", "rev-b"}, false, false, defaultProj.EffectiveSourceIntegrity(), &defaultProj, false)
	require.NoError(t, err)
	require.Len(t, targetObjs, 4)
	require.Len(t, manifestInfos, 2)

	// Run the real normalization with a real resource tracking callback, exactly like CompareAppState.
	resourceTracking := argo.NewResourceTracking()
	trackingMethod := v1alpha1.TrackingMethodAnnotation
	setAppInstance := func(u *unstructured.Unstructured) error {
		return resourceTracking.SetAppInstance(u, common.LabelKeyAppInstance, "test-app", test.FakeDestNamespace, trackingMethod, "")
	}
	trackingPaths := provenance.TrackingFieldPaths(trackingMethod, common.LabelKeyAppInstance, "")
	normalized, conditions, err := NormalizeTargetObjectsWithProvenance(test.FakeDestNamespace, targetObjs,
		&namespacedResourceInfoProvider{namespaced: true}, setAppInstance, rec, trackingPaths)
	require.NoError(t, err)

	graph := rec.Graph()
	require.NoError(t, graph.Validate())
	require.NoError(t, graph.AssertNoSensitiveData("s3cr3t-token", "s3cr3t"))

	// The repeated resource warning is retained both as an Application condition and a graph warning.
	require.Len(t, conditions, 1)
	assert.Equal(t, v1alpha1.ApplicationConditionRepeatedResourceWarning, conditions[0].Type)
	assert.Contains(t, conditions[0].Message, "appeared 2 times")
	assert.Contains(t, graph.Warnings, conditions[0].Message)

	// Last-wins merge: only one shared object survives, both distinct namespaces remain.
	require.Len(t, normalized, 3)
	normalizedKeys := make(map[string]bool)
	for _, obj := range normalized {
		normalizedKeys[obj.GetNamespace()+"/"+obj.GetName()] = true
	}
	assert.True(t, normalizedKeys[test.FakeDestNamespace+"/shared"])
	assert.True(t, normalizedKeys["ns-a/distinct"])
	assert.True(t, normalizedKeys["ns-b/distinct"])

	// The surviving shared object carries source-b data: an override must not inherit source-a fields.
	var winner *unstructured.Unstructured
	for _, obj := range normalized {
		if obj.GetName() == "shared" {
			winner = obj
		}
	}
	require.NotNil(t, winner)
	origin, _, err := unstructured.NestedString(winner.Object, "data", "origin")
	require.NoError(t, err)
	assert.Equal(t, "source-b", origin)
	winnerBytes, err := json.Marshal(winner.Object)
	require.NoError(t, err)
	assert.Equal(t, mustManifestString(t, winner.Object), string(winnerBytes))

	// Graph: winner and loser nodes record the whole-object override honestly.
	winnerNode := findProvenanceNode(graph, 1, "ConfigMap", "shared")
	require.NotNil(t, winnerNode)
	assert.Equal(t, provenance.OutcomeWinner, winnerNode.Outcome)
	var outcomes []provenance.ContributionOutcome
	for _, c := range winnerNode.Contributions {
		outcomes = append(outcomes, c.Outcome)
	}
	assert.Contains(t, outcomes, provenance.OutcomeWinner)
	assert.Contains(t, outcomes, provenance.OutcomeOverridden)
	assert.NotEmpty(t, winnerNode.Warnings)

	loserNode := findProvenanceNode(graph, 0, "ConfigMap", "shared")
	require.NotNil(t, loserNode)
	assert.Equal(t, provenance.OutcomeOverridden, loserNode.Outcome)

	// The winner must not reference any field from the overridden source 0.
	for _, f := range winnerNode.Fields {
		assert.NotEqual(t, 0, f.SourceIndex, "winner field %q must not be inherited from overridden source", f.FieldPath)
		assert.NotEqual(t, provenance.EvidenceFieldLevel, f.Level, "cross-process objects cannot claim precise field evidence")
	}

	// Default namespace injection and tracking annotation are explicit derived evidence.
	nsField, ok := fieldByPath(winnerNode, "metadata.namespace")
	require.True(t, ok)
	assert.Equal(t, provenance.EvidenceDerived, nsField.Level)
	assert.Equal(t, provenance.DerivedDefaultNamespace, nsField.DerivedReason)
	trackingField, ok := fieldByPath(winnerNode, `metadata.annotations["argocd.argoproj.io/tracking-id"]`)
	require.True(t, ok)
	assert.Equal(t, provenance.EvidenceDerived, trackingField.Level)
	assert.Equal(t, provenance.DerivedTrackingMetadata, trackingField.DerivedReason)
	// The tracking annotation really was written onto the normalized object.
	assert.Contains(t, winner.GetAnnotations(), common.AnnotationKeyAppInstance)

	// Same name, different namespace: distinct nodes, no override relationship.
	distinctA := findProvenanceNode(graph, 0, "ConfigMap", "distinct")
	distinctB := findProvenanceNode(graph, 1, "ConfigMap", "distinct")
	require.NotNil(t, distinctA)
	require.NotNil(t, distinctB)
	assert.NotEqual(t, distinctA.ObjectKey, distinctB.ObjectKey)
	assert.Equal(t, provenance.OutcomeWinner, distinctA.Outcome)
	assert.Equal(t, provenance.OutcomeWinner, distinctB.Outcome)
	assert.Empty(t, distinctA.Contributions)

	// Output digests match the exact bytes returned by the real GetRepoObjs responses.
	assert.Equal(t, provenance.DigestBytes([]byte(manifestInfos[1].Manifests[0])), winnerNode.OutputDigest)
	assert.Equal(t, provenance.DigestBytes([]byte(manifestInfos[0].Manifests[1])), distinctA.OutputDigest)

	// Source identities are redacted and bound to resolved revisions and path digests.
	require.Len(t, graph.Sources, 2)
	assert.Equal(t, "https://github.com/org/repo.git", graph.Sources[0].RepoURLRedacted)
	assert.NotContains(t, graph.Sources[0].RepoURLRedacted, "s3cr3t-token")
	assert.Equal(t, "sha-a", graph.Sources[0].ResolvedRevision)
	assert.Equal(t, provenance.DigestPath("dir-a"), graph.Sources[0].PathDigest)
	assert.Equal(t, "sha-b", graph.Sources[1].ResolvedRevision)

	// Across the gRPC boundary only object-level source attribution is available: no node may
	// present precise field evidence, and every field-level claim must validate against a document.
	for _, obj := range graph.Objects {
		assert.NotEqual(t, provenance.EvidenceFieldLevel, obj.Level)
		for _, f := range obj.Fields {
			assert.NotEqual(t, provenance.EvidenceFieldLevel, f.Level, "object %s must not fake precise evidence at field %s", obj.ObjectKey, f.FieldPath)
		}
	}
}

// TestProvenance_NormalizeWithoutRecorderIsUnchanged proves the optional recorder does not
// change the normalization result when absent.
func TestProvenance_NormalizeWithoutRecorderIsUnchanged(t *testing.T) {
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata":   map[string]any{"name": "cm"},
		"data":       map[string]any{"k": "v"},
	}}
	objs := []*unstructured.Unstructured{obj}
	noop := func(_ *unstructured.Unstructured) error { return nil }

	baseline, baselineConditions, err := NormalizeTargetObjects(test.FakeDestNamespace, objs, &namespacedResourceInfoProvider{namespaced: true}, noop)
	require.NoError(t, err)
	withRec, recConditions, err := NormalizeTargetObjectsWithProvenance(test.FakeDestNamespace, objs, &namespacedResourceInfoProvider{namespaced: true}, noop, provenance.NewRecorder(nil), nil)
	require.NoError(t, err)
	assert.Equal(t, baselineConditions, recConditions)
	require.Len(t, withRec, 1)
	assert.Equal(t, baseline[0].Object, withRec[0].Object)
	assert.Equal(t, test.FakeDestNamespace, withRec[0].GetNamespace())
}
