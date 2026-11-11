/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package projectcapabilities

import (
	"context"
	"encoding/json"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/argoproj/argo-cd/v3/pkg/apis/application/v1alpha1"
)

const (
	inClusterURL = "https://kubernetes.default.svc"
	stagingURL   = "https://staging.example.com"
	prodEastURL  = "https://prod-east.example.com"
	prodWestURL  = "https://prod-west.example.com"
)

func objectMeta(name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Name: name}
}

func newSnapshot() *Snapshot {
	return &Snapshot{
		Clusters: []*v1alpha1.Cluster{
			{Name: "in-cluster", Server: inClusterURL},
			{Name: "staging", Server: stagingURL},
			{Name: "prod-east", Server: prodEastURL},
			{Name: "prod-west", Server: prodWestURL},
		},
		ProjectScopedClusters: map[string][]*v1alpha1.Cluster{},
	}
}

func sourceRequest(repoURL string) CapabilityRequest {
	return CapabilityRequest{Kind: RequestKindSource, RepoURL: repoURL}
}

func destinationRequest(server string, name string, namespace string) CapabilityRequest {
	return CapabilityRequest{
		Kind:        RequestKindDestination,
		Destination: v1alpha1.ApplicationDestination{Server: server, Name: name, Namespace: namespace},
	}
}

func resourceRequest(group string, kind string, name string, namespaced bool, destination v1alpha1.ApplicationDestination) CapabilityRequest {
	return CapabilityRequest{
		Kind:         RequestKindResource,
		Group:        group,
		ResourceKind: kind,
		Name:         name,
		Namespaced:   namespaced,
		Destination:  destination,
	}
}

func runCompare(t *testing.T, projectA *v1alpha1.AppProject, projectB *v1alpha1.AppProject, snapshot *Snapshot, requests []CapabilityRequest) *CompareResponse {
	t.Helper()
	response, err := NewComparator().Compare(context.Background(), projectA, projectB, snapshot, requests, "")
	require.NoError(t, err)
	require.Len(t, response.Results, len(requests))
	for i, result := range response.Results {
		assert.Equal(t, i, result.Position)
	}
	return response
}

// referenceSourcePermitted calls the real AppProject source engine, which is
// the same primitive validateSyncPermissions and project validation rely on.
func referenceSourcePermitted(t *testing.T, project *v1alpha1.AppProject, repoURL string) bool {
	t.Helper()
	return project.IsSourcePermitted(v1alpha1.ApplicationSource{RepoURL: repoURL})
}

// referenceDestinationPermitted calls the real AppProject destination engine
// against the same fixed cluster resolution.
func referenceDestinationPermitted(t *testing.T, project *v1alpha1.AppProject, snapshot *Snapshot, destination v1alpha1.ApplicationDestination) (bool, bool) {
	t.Helper()
	cluster, _, resolved := snapshot.resolveCluster(destination)
	if !resolved {
		return false, false
	}
	permitted, err := project.IsDestinationPermitted(cluster, destination.Namespace, func(string) ([]*v1alpha1.Cluster, error) {
		return nil, nil
	})
	require.NoError(t, err)
	return permitted, true
}

// referenceResourcePermitted replays controller.validateSyncPermissions with
// its identical public building blocks: IsGroupKindNamePermitted plus, for
// namespaced resources, IsDestinationPermitted.
func referenceResourcePermitted(t *testing.T, project *v1alpha1.AppProject, snapshot *Snapshot, request CapabilityRequest) (bool, bool) {
	t.Helper()
	groupKind := schema.GroupKind{Group: request.Group, Kind: request.ResourceKind}
	if !project.IsGroupKindNamePermitted(groupKind, request.Name, request.Namespaced) {
		return false, true
	}
	if request.Namespaced {
		cluster, _, resolved := snapshot.resolveCluster(request.Destination)
		if !resolved {
			return false, false
		}
		permitted, err := project.IsDestinationPermitted(cluster, request.Destination.Namespace, func(string) ([]*v1alpha1.Cluster, error) {
			return nil, nil
		})
		require.NoError(t, err)
		return permitted, true
	}
	return true, true
}

func TestCompareValidation(t *testing.T) {
	t.Parallel()

	project := &v1alpha1.AppProject{ObjectMeta: objectMeta("proj-a")}
	snapshot := newSnapshot()
	requests := []CapabilityRequest{sourceRequest("https://github.com/argoproj/test")}
	comparator := NewComparator()

	_, err := comparator.Compare(context.Background(), nil, project, snapshot, requests, "")
	require.ErrorIs(t, err, ErrInvalidRequest)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	_, err = comparator.Compare(context.Background(), project, project, nil, requests, "")
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	_, err = comparator.Compare(context.Background(), project, project, snapshot, nil, "")
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	tooMany := make([]CapabilityRequest, MaxRequests+1)
	for i := range tooMany {
		tooMany[i] = sourceRequest("https://github.com/argoproj/test")
	}
	_, err = comparator.Compare(context.Background(), project, project, snapshot, tooMany, "")
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	badKind := []CapabilityRequest{{Kind: RequestKind("bogus")}}
	_, err = comparator.Compare(context.Background(), project, project, snapshot, badKind, "")
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestCompareSourceCapabilities(t *testing.T) {
	t.Parallel()

	projectA := &v1alpha1.AppProject{
		ObjectMeta: objectMeta("proj-a"),
		Spec: v1alpha1.AppProjectSpec{
			SourceRepos: []string{
				"*",
				"https://github.com/argoproj/*",
				"!https://github.com/argoproj/secret/*",
				"https://gitlab.com/group/**",
			},
		},
	}
	projectB := &v1alpha1.AppProject{
		ObjectMeta: objectMeta("proj-b"),
		Spec: v1alpha1.AppProjectSpec{
			SourceRepos: []string{"https://github.com/argoproj/public/*"},
		},
	}

	requests := []CapabilityRequest{
		sourceRequest("https://github.com/argoproj/public/app"),     // 0: wildcard allow
		sourceRequest("https://github.com/argoproj/secret/app"),     // 1: explicit deny wins
		sourceRequest("https://gitlab.com/group/sub/repo"),          // 2: double star allow
		sourceRequest("https://gitlab.com/other/repo"),              // 3: no matching rule
		sourceRequest("git@github.com:argoproj/argocd.git"),         // 4: SSH form, wildcard allow
		sourceRequest("https://user:hunter2@github.com/argoproj/x"), // 5: credentials must not leak
	}

	response := runCompare(t, projectA, projectB, newSnapshot(), requests)

	t.Run("verdicts match the real IsSourcePermitted engine", func(t *testing.T) {
		t.Parallel()
		for i, request := range requests {
			expectedA := referenceSourcePermitted(t, projectA, request.RepoURL)
			expectedB := referenceSourcePermitted(t, projectB, request.RepoURL)
			assert.Equal(t, expectedA, response.Results[i].A.Verdict == VerdictAllow, "position %d project A", i)
			assert.Equal(t, expectedB, response.Results[i].B.Verdict == VerdictAllow, "position %d project B", i)
			if expectedA {
				assert.Equal(t, VerdictAllow, response.Results[i].A.Verdict)
			} else {
				assert.Equal(t, VerdictDeny, response.Results[i].A.Verdict)
			}
		}
	})

	t.Run("deny pattern produces deciding negated evidence", func(t *testing.T) {
		t.Parallel()
		verdict := response.Results[1].A
		require.Equal(t, VerdictDeny, verdict.Verdict)
		require.NotEmpty(t, verdict.Evidence)
		assert.True(t, verdict.Evidence[0].Deciding)
		assert.Equal(t, RuleTypeSourceRepo, verdict.Evidence[0].RuleType)
		assert.True(t, strings.HasPrefix(verdict.Evidence[0].Pattern, "!"))
		assert.Contains(t, verdict.Evidence[0].Pattern, "secret")
	})

	t.Run("no matching rule is reported as deny with noMatchingRule evidence", func(t *testing.T) {
		t.Parallel()
		// Project A contains a wildcard so every source is allowed; project B
		// only lists github.com/argoproj/public, so the gitlab request misses.
		verdict := response.Results[3].B
		assert.Equal(t, VerdictDeny, verdict.Verdict)
		assert.Equal(t, RuleTypeNoMatchingRule, verdict.Evidence[0].RuleType)
	})

	t.Run("shortest matching allow rule is the deciding evidence", func(t *testing.T) {
		t.Parallel()
		shortestProject := &v1alpha1.AppProject{
			ObjectMeta: objectMeta("proj-shortest"),
			Spec: v1alpha1.AppProjectSpec{
				SourceRepos: []string{
					"https://github.com/argoproj/long-repo-name",
					"https://github.com/argoproj/*",
				},
			},
		}
		resp := runCompare(t, shortestProject, shortestProject, newSnapshot(),
			[]CapabilityRequest{sourceRequest("https://github.com/argoproj/long-repo-name")})
		evidence := resp.Results[0].A.Evidence
		require.Len(t, evidence, 2)
		assert.True(t, evidence[0].Deciding)
		assert.Less(t, len(evidence[0].Pattern), len(evidence[1].Pattern))
	})

	t.Run("credentials never appear in outputs", func(t *testing.T) {
		t.Parallel()
		verdict := response.Results[5].A
		assert.Equal(t, VerdictAllow, verdict.Verdict)
		encoded, err := json.Marshal(response)
		require.NoError(t, err)
		assert.NotContains(t, string(encoded), "hunter2")
		assert.NotContains(t, verdict.Evidence[0].Pattern, "user:")
		assert.Equal(t, "https://github.com/argoproj/x", response.Results[5].Request.RepoURL)
	})

	t.Run("normalization stays consistent with NormalizeGitURL", func(t *testing.T) {
		t.Parallel()
		normalizedProject := &v1alpha1.AppProject{
			ObjectMeta: objectMeta("proj-norm"),
			Spec: v1alpha1.AppProjectSpec{SourceRepos: []string{
				"https://github.com/argoproj/test",
				"ssh://git@github.com/argoproj/test",
			}},
		}
		variants := []string{
			"https://github.com/argoproj/test.git",
			"https://GITHUB.com/argoproj/test",
			"git@github.com:argoproj/test.git",
		}
		requests := make([]CapabilityRequest, len(variants))
		for i, variant := range variants {
			requests[i] = sourceRequest(variant)
		}
		resp := runCompare(t, normalizedProject, normalizedProject, newSnapshot(), requests)
		for i, variant := range variants {
			assert.True(t, referenceSourcePermitted(t, normalizedProject, variant))
			assert.Equal(t, VerdictAllow, resp.Results[i].A.Verdict, "variant %q", variant)
		}
	})

	t.Run("non-firing negated rule still permits, matching the real engine", func(t *testing.T) {
		t.Parallel()
		negationOnly := &v1alpha1.AppProject{
			ObjectMeta: objectMeta("proj-negation"),
			Spec: v1alpha1.AppProjectSpec{
				SourceRepos: []string{"!https://github.com/argoproj/secret/*"},
			},
		}
		request := sourceRequest("https://github.com/argoproj/public/app")
		assert.True(t, referenceSourcePermitted(t, negationOnly, request.RepoURL))
		resp := runCompare(t, negationOnly, negationOnly, newSnapshot(), []CapabilityRequest{request})
		verdict := resp.Results[0].A
		require.Equal(t, VerdictAllow, verdict.Verdict)
		require.NotEmpty(t, verdict.Evidence)
		assert.True(t, verdict.Evidence[0].Deciding)
		assert.Equal(t, "proj-negation", verdict.Evidence[0].Project)
		assert.True(t, strings.HasPrefix(verdict.Evidence[0].Pattern, "!"))
	})
}

func TestCompareDestinationCapabilities(t *testing.T) {
	t.Parallel()

	projectA := &v1alpha1.AppProject{
		ObjectMeta: objectMeta("proj-a"),
		Spec: v1alpha1.AppProjectSpec{
			Destinations: []v1alpha1.ApplicationDestination{
				{Server: inClusterURL, Namespace: "default"},
				{Server: "https://*.example.com", Namespace: "*"},
				{Server: prodEastURL, Namespace: "!kube-system"},
			},
		},
	}
	projectB := &v1alpha1.AppProject{
		ObjectMeta: objectMeta("proj-b"),
		Spec: v1alpha1.AppProjectSpec{
			Destinations: []v1alpha1.ApplicationDestination{{Server: "*", Namespace: "*"}},
		},
	}

	requests := []CapabilityRequest{
		destinationRequest(stagingURL, "", "team-a"),                 // 0: glob allow
		destinationRequest(inClusterURL, "", "kube-system"),          // 1: namespace not matched
		destinationRequest(prodEastURL, "", "kube-system"),           // 2: negated namespace deny
		destinationRequest(prodEastURL, "", "app"),                   // 3: allow
		destinationRequest("https://unknown.example", "", "default"), // 4: unknown cluster
		destinationRequest("", "missing-cluster", "default"),         // 5: unknown name
		destinationRequest(stagingURL, "staging", "default"),         // 6: both name and server
	}

	response := runCompare(t, projectA, projectB, newSnapshot(), requests)

	t.Run("evaluable verdicts match the real destination engine", func(t *testing.T) {
		t.Parallel()
		for i, request := range requests {
			permitted, evaluable := referenceDestinationPermitted(t, projectA, newSnapshot(), request.Destination)
			switch response.Results[i].A.Verdict {
			case VerdictUnknown:
				assert.False(t, evaluable, "position %d should be unevaluable", i)
			default:
				assert.True(t, evaluable, "position %d should be evaluable", i)
				assert.Equal(t, permitted, response.Results[i].A.Verdict == VerdictAllow, "position %d", i)
			}
		}
	})

	t.Run("glob and deny evidence", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, VerdictAllow, response.Results[0].A.Verdict)
		assert.Equal(t, RuleTypeDestination, response.Results[0].A.Evidence[0].RuleType)

		denied := response.Results[2].A
		require.Equal(t, VerdictDeny, denied.Verdict)
		assert.True(t, denied.Evidence[0].Deciding)
		assert.Contains(t, denied.Evidence[0].Pattern, "!kube-system")

		noMatch := response.Results[1].A
		assert.Equal(t, VerdictDeny, noMatch.Verdict)
		assert.Equal(t, RuleTypeNoMatchingRule, noMatch.Evidence[0].RuleType)
	})

	t.Run("unknown or malformed cluster targets are explicitly Unknown", func(t *testing.T) {
		t.Parallel()
		for _, position := range []int{4, 5, 6} {
			assert.Equal(t, VerdictUnknown, response.Results[position].A.Verdict, "position %d", position)
			assert.Equal(t, RuleTypeUnknownCluster, response.Results[position].A.Evidence[0].RuleType)
			assert.NotEmpty(t, response.Results[position].A.Reason)
		}
	})

	t.Run("ambiguous cluster name is Unknown", func(t *testing.T) {
		t.Parallel()
		ambiguous := &Snapshot{
			Clusters: []*v1alpha1.Cluster{
				{Name: "dup", Server: "https://one.example.com"},
				{Name: "dup", Server: "https://two.example.com"},
			},
			ProjectScopedClusters: map[string][]*v1alpha1.Cluster{},
		}
		resp := runCompare(t, projectA, projectA, ambiguous,
			[]CapabilityRequest{destinationRequest("", "dup", "default")})
		assert.Equal(t, VerdictUnknown, resp.Results[0].A.Verdict)
	})

	t.Run("name-based destinations resolve through the fixed mapping", func(t *testing.T) {
		t.Parallel()
		nameProject := &v1alpha1.AppProject{
			ObjectMeta: objectMeta("proj-name"),
			Spec: v1alpha1.AppProjectSpec{
				Destinations: []v1alpha1.ApplicationDestination{{Name: "staging", Namespace: "*"}},
			},
		}
		resp := runCompare(t, nameProject, nameProject, newSnapshot(),
			[]CapabilityRequest{destinationRequest("", "staging", "team-a")})
		assert.Equal(t, VerdictAllow, resp.Results[0].A.Verdict)
		assert.Contains(t, resp.Results[0].A.Evidence[0].Pattern, "name=staging")
	})
}

func TestCompareResourceCapabilities(t *testing.T) {
	t.Parallel()

	projectA := &v1alpha1.AppProject{
		ObjectMeta: objectMeta("proj-a"),
		Spec: v1alpha1.AppProjectSpec{
			Destinations: []v1alpha1.ApplicationDestination{{Server: "*", Namespace: "default"}},
			NamespaceResourceWhitelist: []metav1.GroupKind{
				{Group: "apps", Kind: "Deployment"},
				{Group: "", Kind: "ConfigMap"},
			},
			NamespaceResourceBlacklist: []metav1.GroupKind{
				{Group: "apps", Kind: "StatefulSet"},
			},
			ClusterResourceWhitelist: []v1alpha1.ClusterResourceRestrictionItem{
				{Group: "", Kind: "Namespace"},
				{Group: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "viewer-*"},
			},
			ClusterResourceBlacklist: []v1alpha1.ClusterResourceRestrictionItem{
				{Group: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "admin*"},
			},
		},
	}
	projectB := &v1alpha1.AppProject{ObjectMeta: objectMeta("proj-b")}

	defaultDestination := v1alpha1.ApplicationDestination{Server: inClusterURL, Namespace: "default"}
	unknownDestination := v1alpha1.ApplicationDestination{Server: "https://unknown.example", Namespace: "default"}

	requests := []CapabilityRequest{
		resourceRequest("apps", "Deployment", "web", true, defaultDestination),                                                              // 0: allow
		resourceRequest("apps", "StatefulSet", "db", true, defaultDestination),                                                              // 1: blacklist deny
		resourceRequest("batch", "Job", "cron", true, defaultDestination),                                                                   // 2: whitelist miss deny
		resourceRequest("", "ConfigMap", "cfg", true, defaultDestination),                                                                   // 3: allow
		resourceRequest("apps", "Deployment", "web", true, v1alpha1.ApplicationDestination{Server: inClusterURL, Namespace: "kube-system"}), // 4: namespace deny
		resourceRequest("", "Namespace", "team-a", false, v1alpha1.ApplicationDestination{}),                                                // 5: cluster allow
		resourceRequest("rbac.authorization.k8s.io", "ClusterRole", "viewer-ro", false, v1alpha1.ApplicationDestination{}),                  // 6: name glob allow
		resourceRequest("rbac.authorization.k8s.io", "ClusterRole", "admin-ro", false, v1alpha1.ApplicationDestination{}),                   // 7: blacklist deny
		resourceRequest("rbac.authorization.k8s.io", "ClusterRole", "editor", false, v1alpha1.ApplicationDestination{}),                     // 8: whitelist miss deny
		resourceRequest("apps", "Deployment", "web", true, unknownDestination),                                                              // 9: unknown cluster -> Unknown
	}

	response := runCompare(t, projectA, projectB, newSnapshot(), requests)

	t.Run("verdicts match validateSyncPermissions reference behavior", func(t *testing.T) {
		t.Parallel()
		for i, request := range requests {
			permitted, evaluable := referenceResourcePermitted(t, projectA, newSnapshot(), request)
			switch response.Results[i].A.Verdict {
			case VerdictUnknown:
				assert.False(t, evaluable, "position %d must be Unknown", i)
			default:
				assert.True(t, evaluable, "position %d must be evaluable", i)
				assert.Equal(t, permitted, response.Results[i].A.Verdict == VerdictAllow, "position %d", i)
			}
		}
	})

	t.Run("namespaced whitelist and blacklist evidence", func(t *testing.T) {
		t.Parallel()
		allow := response.Results[0].A
		require.Equal(t, VerdictAllow, allow.Verdict)
		ruleTypes := ruleTypeSet(allow.Evidence)
		assert.Contains(t, ruleTypes, RuleTypeNamespaceWhitelist)
		assert.Contains(t, ruleTypes, RuleTypeDestination)

		blacklisted := response.Results[1].A
		require.Equal(t, VerdictDeny, blacklisted.Verdict)
		assert.Equal(t, RuleTypeNamespaceBlacklist, blacklisted.Evidence[0].RuleType)

		missed := response.Results[2].A
		require.Equal(t, VerdictDeny, missed.Verdict)
		assert.Equal(t, RuleTypeNoMatchingRule, missed.Evidence[0].RuleType)
	})

	t.Run("namespace destination denial propagates for namespaced resources", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, VerdictDeny, response.Results[4].A.Verdict)
		assert.Equal(t, RuleTypeNoMatchingRule, response.Results[4].A.Evidence[0].RuleType)
	})

	t.Run("cluster-scoped resources ignore destinations", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, VerdictAllow, response.Results[5].A.Verdict)
		assert.Equal(t, VerdictAllow, response.Results[6].A.Verdict)
		assert.Equal(t, VerdictDeny, response.Results[7].A.Verdict)
		assert.Equal(t, RuleTypeClusterBlacklist, response.Results[7].A.Evidence[0].RuleType)
		assert.Equal(t, VerdictDeny, response.Results[8].A.Verdict)
		assert.Equal(t, RuleTypeNoMatchingRule, response.Results[8].A.Evidence[0].RuleType)
	})

	t.Run("unknown destination cluster makes a namespaced resource Unknown", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, VerdictUnknown, response.Results[9].A.Verdict)
	})

	t.Run("empty namespaced whitelist allows by default like the real engine", func(t *testing.T) {
		t.Parallel()
		defaults := &v1alpha1.AppProject{
			ObjectMeta: objectMeta("proj-defaults"),
			Spec: v1alpha1.AppProjectSpec{
				Destinations: []v1alpha1.ApplicationDestination{{Server: "*", Namespace: "*"}},
			},
		}
		request := resourceRequest("apps", "Deployment", "web", true, defaultDestination)
		permitted, evaluable := referenceResourcePermitted(t, defaults, newSnapshot(), request)
		require.True(t, evaluable)
		assert.True(t, permitted)
		resp := runCompare(t, defaults, defaults, newSnapshot(), []CapabilityRequest{request})
		assert.Equal(t, VerdictAllow, resp.Results[0].A.Verdict)
	})
}

func TestCompareGlobalProjectInheritance(t *testing.T) {
	t.Parallel()

	globalProject := &v1alpha1.AppProject{
		ObjectMeta: objectMeta("global-base"),
		Spec: v1alpha1.AppProjectSpec{
			SourceRepos: []string{
				"https://github.com/global/*",
				"!https://github.com/global/secret/*",
			},
			Destinations: []v1alpha1.ApplicationDestination{{Name: "staging", Namespace: "*"}},
			NamespaceResourceWhitelist: []metav1.GroupKind{
				{Group: "", Kind: "Secret"},
			},
		},
	}
	projectA := &v1alpha1.AppProject{
		ObjectMeta: objectMeta("proj-a"),
		Spec: v1alpha1.AppProjectSpec{
			SourceRepos: []string{"https://github.com/local/*"},
			Destinations: []v1alpha1.ApplicationDestination{
				{Server: inClusterURL, Namespace: "default"},
			},
		},
	}
	projectB := &v1alpha1.AppProject{ObjectMeta: objectMeta("proj-b")}

	snapshot := newSnapshot()
	snapshot.GlobalProjects = []*v1alpha1.AppProject{globalProject}

	requests := []CapabilityRequest{
		sourceRequest("https://github.com/global/app"),
		sourceRequest("https://github.com/global/secret/app"),
		destinationRequest("", "staging", "team-a"),
		resourceRequest("", "Secret", "token", true, v1alpha1.ApplicationDestination{Name: "staging", Namespace: "team-a"}),
		resourceRequest("", "ConfigMap", "cfg", true, v1alpha1.ApplicationDestination{Name: "staging", Namespace: "team-a"}),
	}

	response := runCompare(t, projectA, projectB, snapshot, requests)

	t.Run("global project rules are inherited by both projects", func(t *testing.T) {
		t.Parallel()
		virtualA := prepareProject(projectA, snapshot.GlobalProjects)
		assert.True(t, virtualA.virtual.IsSourcePermitted(v1alpha1.ApplicationSource{RepoURL: "https://github.com/global/app"}))
		assert.False(t, virtualA.virtual.IsSourcePermitted(v1alpha1.ApplicationSource{RepoURL: "https://github.com/global/secret/app"}))

		assert.Equal(t, VerdictAllow, response.Results[0].A.Verdict)
		assert.Equal(t, VerdictAllow, response.Results[0].B.Verdict)
		assert.Equal(t, VerdictDeny, response.Results[1].A.Verdict)
		assert.Equal(t, VerdictDeny, response.Results[1].B.Verdict)
		assert.Equal(t, VerdictAllow, response.Results[2].A.Verdict)
	})

	t.Run("evidence attributes inherited rules to the global project", func(t *testing.T) {
		t.Parallel()
		allowEvidence := response.Results[0].A.Evidence[0]
		assert.True(t, allowEvidence.Global)
		assert.Equal(t, "global-base", allowEvidence.Project)
		assert.Equal(t, 0, allowEvidence.RuleIndex)

		denyEvidence := response.Results[1].A.Evidence[0]
		assert.True(t, denyEvidence.Global)
		assert.Equal(t, "global-base", denyEvidence.Project)
		assert.Equal(t, 1, denyEvidence.RuleIndex)
		assert.True(t, strings.HasPrefix(denyEvidence.Pattern, "!"))

		destinationEvidence := response.Results[2].A.Evidence[0]
		assert.True(t, destinationEvidence.Global)
		assert.Equal(t, "global-base", destinationEvidence.Project)
	})

	t.Run("global resource whitelist applies and local rules remain local", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, VerdictAllow, response.Results[3].A.Verdict)
		assert.True(t, response.Results[3].A.Evidence[0].Global)

		// ConfigMap is not whitelisted by either layer.
		assert.Equal(t, VerdictDeny, response.Results[4].A.Verdict)
	})
}

func TestCompareActionAndSubjectAreUnknown(t *testing.T) {
	t.Parallel()

	project := &v1alpha1.AppProject{
		ObjectMeta: objectMeta("proj-a"),
		Spec: v1alpha1.AppProjectSpec{
			Roles: []v1alpha1.ProjectRole{{
				Name:     "ci",
				Policies: []string{"p, proj:proj-a:ci, applications, sync, my-app, allow"},
			}},
		},
	}

	requests := []CapabilityRequest{
		{Kind: RequestKindAction, Action: "sync", Subject: "proj:proj-a:ci"},
		{Kind: RequestKindAction, Action: "action/restart"},
		{Kind: RequestKindSource, RepoURL: "https://github.com/argoproj/test", Subject: "oidc:somebody"},
	}
	response := runCompare(t, project, project, newSnapshot(), requests)

	for i := range requests {
		assert.Equal(t, VerdictUnknown, response.Results[i].A.Verdict, "position %d", i)
		assert.Equal(t, VerdictUnknown, response.Results[i].B.Verdict, "position %d", i)
		assert.Equal(t, RuleTypeUnsupportedSubject, response.Results[i].A.Evidence[0].RuleType)
		assert.NotEmpty(t, response.Results[i].A.Reason)
	}
	assert.Contains(t, response.Results[1].A.Reason, "RBAC")
}

func TestCompareDuplicateRequestsPreservePositions(t *testing.T) {
	t.Parallel()

	project := &v1alpha1.AppProject{
		ObjectMeta: objectMeta("proj-a"),
		Spec:       v1alpha1.AppProjectSpec{SourceRepos: []string{"https://github.com/argoproj/test"}},
	}
	requests := []CapabilityRequest{
		sourceRequest("https://github.com/argoproj/test"),
		sourceRequest("https://github.com/argoproj/test.git"), // normalizes to the same identity
		sourceRequest("https://github.com/argoproj/test"),
		sourceRequest("https://github.com/other/repo"),
	}

	t.Run("full identities collapse under normalization", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, buildIdentity(requests[0]), buildIdentity(requests[1]))
		assert.Equal(t, buildIdentity(requests[0]), buildIdentity(requests[2]))
		assert.NotEqual(t, buildIdentity(requests[0]), buildIdentity(requests[3]))
	})

	response := runCompare(t, project, project, newSnapshot(), requests)

	assert.Equal(t, VerdictAllow, response.Results[0].A.Verdict)
	assert.Equal(t, VerdictAllow, response.Results[1].A.Verdict)
	assert.Equal(t, VerdictAllow, response.Results[2].A.Verdict)
	assert.Equal(t, VerdictDeny, response.Results[3].A.Verdict)

	// Every input row keeps its own position even though 0-2 share an identity.
	assert.Equal(t, 0, response.Results[0].Position)
	assert.Equal(t, 1, response.Results[1].Position)
	assert.Equal(t, 2, response.Results[2].Position)
	assert.Equal(t, 3, response.Results[3].Position)
	assert.Equal(t, response.Results[0].A, response.Results[1].A)
	assert.Equal(t, response.Results[0].A, response.Results[2].A)
}

func TestCompareAddedRemovedDirection(t *testing.T) {
	t.Parallel()

	projectA := &v1alpha1.AppProject{
		ObjectMeta: objectMeta("proj-a"),
		Spec: v1alpha1.AppProjectSpec{
			SourceRepos:  []string{"https://github.com/argoproj/old"},
			Destinations: []v1alpha1.ApplicationDestination{{Server: inClusterURL, Namespace: "default"}},
		},
	}
	projectB := &v1alpha1.AppProject{
		ObjectMeta: objectMeta("proj-b"),
		Spec: v1alpha1.AppProjectSpec{
			SourceRepos:  []string{"https://github.com/argoproj/new"},
			Destinations: []v1alpha1.ApplicationDestination{{Server: "*", Namespace: "*"}},
		},
	}

	requests := []CapabilityRequest{
		sourceRequest("https://github.com/argoproj/old"),             // A allow, B deny -> removed
		sourceRequest("https://github.com/argoproj/new"),             // A deny, B allow -> added
		destinationRequest(inClusterURL, "", "kube-system"),          // A deny, B allow -> added
		destinationRequest("https://unknown.example", "", "default"), // Unknown both -> no change
	}

	response := runCompare(t, projectA, projectB, newSnapshot(), requests)

	require.Len(t, response.RemovedPermissions, 1)
	assert.Equal(t, 0, response.RemovedPermissions[0].Position)
	assert.Equal(t, VerdictAllow, response.RemovedPermissions[0].From.Verdict)
	assert.Equal(t, VerdictDeny, response.RemovedPermissions[0].To.Verdict)

	require.Len(t, response.AddedPermissions, 2)
	addedPositions := []int{response.AddedPermissions[0].Position, response.AddedPermissions[1].Position}
	assert.ElementsMatch(t, []int{1, 2}, addedPositions)
	for _, change := range response.AddedPermissions {
		assert.Equal(t, VerdictDeny, change.From.Verdict)
		assert.Equal(t, VerdictAllow, change.To.Verdict)
	}

	// Swapping the projects flips added and removed.
	swapped := runCompare(t, projectB, projectA, newSnapshot(), requests)
	require.Len(t, swapped.AddedPermissions, 1)
	assert.Equal(t, 0, swapped.AddedPermissions[0].Position)
	assert.Len(t, swapped.RemovedPermissions, 2)
}

func TestCompareLimitsGeneration(t *testing.T) {
	t.Parallel()

	project := &v1alpha1.AppProject{ObjectMeta: objectMeta("proj-a")}
	requests := []CapabilityRequest{sourceRequest("https://github.com/argoproj/test")}
	comparator := NewComparator()

	snapshot := newSnapshot()
	first := runCompare(t, project, project, snapshot, requests)
	second := runCompare(t, project, project, snapshot, requests)
	assert.NotEmpty(t, first.LimitsGeneration)
	assert.Equal(t, first.LimitsGeneration, second.LimitsGeneration)

	// Echoing the current generation is accepted.
	accepted, err := comparator.Compare(context.Background(), project, project, snapshot, requests, first.LimitsGeneration)
	require.NoError(t, err)
	assert.Equal(t, first.LimitsGeneration, accepted.LimitsGeneration)

	// Changing the cluster inventory changes the generation and rejects stale artifacts.
	changed := newSnapshot()
	changed.Clusters = append(changed.Clusters, &v1alpha1.Cluster{Name: "new", Server: "https://new.example.com"})
	stale, err := comparator.Compare(context.Background(), project, project, changed, requests, first.LimitsGeneration)
	assert.Nil(t, stale)
	require.ErrorIs(t, err, ErrLimitsGenerationChanged)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))

	fresh, err := comparator.Compare(context.Background(), project, project, changed, requests, "")
	require.NoError(t, err)
	assert.NotEqual(t, first.LimitsGeneration, fresh.LimitsGeneration)

	// Global project changes also change the generation.
	withGlobal := newSnapshot()
	withGlobal.GlobalProjects = []*v1alpha1.AppProject{{
		ObjectMeta: objectMeta("global-base"),
		Spec:       v1alpha1.AppProjectSpec{SourceRepos: []string{"*"}},
	}}
	globalResponse, err := comparator.Compare(context.Background(), project, project, withGlobal, requests, "")
	require.NoError(t, err)
	assert.NotEqual(t, first.LimitsGeneration, globalResponse.LimitsGeneration)
}

func TestCompareDoesNotMutateInputs(t *testing.T) {
	t.Parallel()

	globalProject := &v1alpha1.AppProject{
		ObjectMeta: objectMeta("global-base"),
		Spec:       v1alpha1.AppProjectSpec{SourceRepos: []string{"https://github.com/global/*"}},
	}
	projectA := &v1alpha1.AppProject{
		ObjectMeta: objectMeta("proj-a"),
		Spec: v1alpha1.AppProjectSpec{
			SourceRepos:  []string{"https://github.com/local/*"},
			Destinations: []v1alpha1.ApplicationDestination{{Server: "*", Namespace: "default"}},
		},
	}
	projectB := projectA.DeepCopy()
	snapshot := newSnapshot()
	snapshot.GlobalProjects = []*v1alpha1.AppProject{globalProject}

	projectABefore := projectA.DeepCopy()
	globalBefore := globalProject.DeepCopy()
	requests := []CapabilityRequest{
		sourceRequest("https://github.com/global/app"),
		destinationRequest(inClusterURL, "", "default"),
	}

	_ = runCompare(t, projectA, projectB, snapshot, requests)

	assert.Equal(t, projectABefore.Spec, projectA.Spec)
	assert.Equal(t, globalBefore.Spec, globalProject.Spec)
	assert.Len(t, projectA.Spec.SourceRepos, 1, "local project must not gain global rules")
}

func TestComparePermitOnlyProjectScopedClusters(t *testing.T) {
	t.Parallel()

	project := &v1alpha1.AppProject{
		ObjectMeta: objectMeta("proj-a"),
		Spec: v1alpha1.AppProjectSpec{
			PermitOnlyProjectScopedClusters: true,
			Destinations:                    []v1alpha1.ApplicationDestination{{Name: "staging", Namespace: "*"}},
		},
	}
	request := []CapabilityRequest{destinationRequest("", "staging", "default")}

	t.Run("missing scoped cluster inventory is Unknown", func(t *testing.T) {
		t.Parallel()
		snapshot := newSnapshot()
		snapshot.ProjectScopedClusters = nil
		response := runCompare(t, project, project, snapshot, request)
		assert.Equal(t, VerdictUnknown, response.Results[0].A.Verdict)
		assert.Contains(t, response.Results[0].A.Reason, "project-scoped")
	})

	t.Run("unscoped cluster is denied with scoping evidence", func(t *testing.T) {
		t.Parallel()
		snapshot := newSnapshot()
		snapshot.ProjectScopedClusters = map[string][]*v1alpha1.Cluster{"proj-a": {}}
		response := runCompare(t, project, project, snapshot, request)
		assert.Equal(t, VerdictDeny, response.Results[0].A.Verdict)
		assert.Equal(t, RuleTypeProjectScopedClusters, response.Results[0].A.Evidence[0].RuleType)
	})

	t.Run("scoped cluster is allowed", func(t *testing.T) {
		t.Parallel()
		snapshot := newSnapshot()
		snapshot.ProjectScopedClusters = map[string][]*v1alpha1.Cluster{
			"proj-a": {{Name: "staging", Server: stagingURL}},
		}
		response := runCompare(t, project, project, snapshot, request)
		assert.Equal(t, VerdictAllow, response.Results[0].A.Verdict)
	})
}

func TestSanitizeURLString(t *testing.T) {
	t.Parallel()

	t.Run("credentials are stripped while URLs remain intact", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t,
			"https://github.com/argoproj/test",
			sanitizeURLString("https://user:secret@github.com/argoproj/test"),
		)
		assert.Equal(t,
			"https://github.com/argoproj/test",
			sanitizeURLString("https://user@github.com/argoproj/test"),
		)
	})

	t.Run("plain URLs and empty strings are unchanged", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, "https://github.com/argoproj/test", sanitizeURLString("https://github.com/argoproj/test"))
		assert.Empty(t, sanitizeURLString(""))
	})

	t.Run("deny prefix is preserved by source rule sanitization", func(t *testing.T) {
		t.Parallel()
		sanitized := sanitizeSourceRules([]string{"!https://user:secret@github.com/secret/*"})
		require.Len(t, sanitized, 1)
		assert.True(t, strings.HasPrefix(sanitized[0], "!"))
		assert.NotContains(t, sanitized[0], "secret:")
		assert.NotContains(t, sanitized[0], "user@")
	})
}

// TestCompareParityWithRealEngines fuzzes randomized rule sets and asserts
// that every evaluable comparator verdict equals the verdict produced by the
// real AppProject rule engines (the same primitives used by
// controller.validateSyncPermissions). The evidence walks are a parallel
// reimplementation of those engines, so drift here would fail immediately.
func TestCompareParityWithRealEngines(t *testing.T) {
	t.Parallel()

	snapshot := newSnapshot()
	comparator := NewComparator()
	projectB := &v1alpha1.AppProject{ObjectMeta: objectMeta("proj-b")}

	sourceRulePool := []string{
		"*", "**",
		"https://github.com/argoproj/*",
		"https://github.com/argoproj/**",
		"https://gitlab.com/group/*",
		"https://github.com/argoproj/test",
		"!https://github.com/argoproj/secret/*",
		"!https://gitlab.com/group/blocked",
	}
	sourceURLPool := []string{
		"https://github.com/argoproj/test",
		"https://github.com/argoproj/test.git",
		"https://github.com/argoproj/secret/app",
		"https://github.com/argoproj/nested/repo",
		"https://gitlab.com/group/repo",
		"https://gitlab.com/group/blocked",
		"https://bitbucket.org/team/repo",
	}

	t.Run("source verdicts parity", func(t *testing.T) {
		t.Parallel()
		rng := rand.New(rand.NewPCG(0x9849, 0x1))
		for iteration := range 200 {
			rules := randomSubset(rng, sourceRulePool)
			if len(rules) == 0 {
				rules = []string{"*"}
			}
			projectA := &v1alpha1.AppProject{
				ObjectMeta: objectMeta("proj-a"),
				Spec:       v1alpha1.AppProjectSpec{SourceRepos: rules},
			}
			requests := make([]CapabilityRequest, len(sourceURLPool))
			for i, repoURL := range sourceURLPool {
				requests[i] = sourceRequest(repoURL)
			}
			response, err := comparator.Compare(context.Background(), projectA, projectB, snapshot, requests, "")
			require.NoError(t, err)
			for i, repoURL := range sourceURLPool {
				expected := projectA.IsSourcePermitted(v1alpha1.ApplicationSource{RepoURL: repoURL})
				got := response.Results[i].A.Verdict == VerdictAllow
				assert.Equal(t, expected, got, "iteration %d rules=%v url=%s", iteration, rules, repoURL)
			}
		}
	})

	destinationPool := []v1alpha1.ApplicationDestination{
		{Server: "*", Namespace: "*"},
		{Server: inClusterURL, Namespace: "default"},
		{Server: "https://*.example.com", Namespace: "*"},
		{Server: prodEastURL, Namespace: "!kube-system"},
		{Name: "staging", Namespace: "team-*"},
		{Server: prodWestURL, Namespace: "!{kube-system,argocd}"},
	}
	destinationRequestPool := []v1alpha1.ApplicationDestination{
		{Server: inClusterURL, Namespace: "default"},
		{Server: inClusterURL, Namespace: "kube-system"},
		{Server: stagingURL, Namespace: "team-a"},
		{Server: prodEastURL, Namespace: "kube-system"},
		{Server: prodEastURL, Namespace: "app"},
		{Server: prodWestURL, Namespace: "argocd"},
		{Name: "staging", Namespace: "team-b"},
	}

	t.Run("destination verdicts parity", func(t *testing.T) {
		t.Parallel()
		rng := rand.New(rand.NewPCG(0x9849, 0x2))
		for iteration := range 200 {
			projectA := &v1alpha1.AppProject{
				ObjectMeta: objectMeta("proj-a"),
				Spec: v1alpha1.AppProjectSpec{
					Destinations: randomDestinationSubset(rng, destinationPool),
				},
			}
			requests := make([]CapabilityRequest, len(destinationRequestPool))
			for i, destination := range destinationRequestPool {
				requests[i] = destinationRequest(destination.Server, destination.Name, destination.Namespace)
			}
			response, err := comparator.Compare(context.Background(), projectA, projectB, snapshot, requests, "")
			require.NoError(t, err)
			for i, destination := range destinationRequestPool {
				cluster, _, resolved := snapshot.resolveCluster(destination)
				require.True(t, resolved)
				expected, destErr := projectA.IsDestinationPermitted(cluster, destination.Namespace,
					func(string) ([]*v1alpha1.Cluster, error) { return nil, nil })
				require.NoError(t, destErr)
				got := response.Results[i].A.Verdict == VerdictAllow
				assert.Equal(t, expected, got, "iteration %d destination=%v", iteration, destination)
			}
		}
	})

	groupKindPool := []metav1.GroupKind{
		{Group: "", Kind: "ConfigMap"},
		{Group: "apps", Kind: "Deployment"},
		{Group: "apps", Kind: "*"},
		{Group: "rbac.authorization.k8s.io", Kind: "ClusterRole"},
	}
	resourceRequestPool := []CapabilityRequest{
		resourceRequest("", "ConfigMap", "cfg", true, v1alpha1.ApplicationDestination{Server: inClusterURL, Namespace: "default"}),
		resourceRequest("apps", "Deployment", "web", true, v1alpha1.ApplicationDestination{Server: inClusterURL, Namespace: "default"}),
		resourceRequest("apps", "StatefulSet", "db", true, v1alpha1.ApplicationDestination{Server: inClusterURL, Namespace: "default"}),
		resourceRequest("batch", "Job", "job", true, v1alpha1.ApplicationDestination{Server: inClusterURL, Namespace: "default"}),
	}

	t.Run("namespaced resource verdicts parity", func(t *testing.T) {
		t.Parallel()
		rng := rand.New(rand.NewPCG(0x9849, 0x3))
		for iteration := range 200 {
			projectA := &v1alpha1.AppProject{
				ObjectMeta: objectMeta("proj-a"),
				Spec: v1alpha1.AppProjectSpec{
					Destinations:               []v1alpha1.ApplicationDestination{{Server: "*", Namespace: "default"}},
					NamespaceResourceWhitelist: randomGroupKindSubset(rng, groupKindPool),
					NamespaceResourceBlacklist: randomGroupKindSubset(rng, groupKindPool),
				},
			}
			response, err := comparator.Compare(context.Background(), projectA, projectB, snapshot, resourceRequestPool, "")
			require.NoError(t, err)
			for i, request := range resourceRequestPool {
				groupKind := schema.GroupKind{Group: request.Group, Kind: request.ResourceKind}
				expected := projectA.IsGroupKindNamePermitted(groupKind, request.Name, true)
				got := response.Results[i].A.Verdict == VerdictAllow
				assert.Equal(t, expected, got, "iteration %d request=%v", iteration, request)
			}
		}
	})
}

func randomSubset(rng *rand.Rand, pool []string) []string {
	var result []string
	for _, item := range pool {
		if rng.IntN(2) == 0 {
			result = append(result, item)
		}
	}
	return result
}

func randomDestinationSubset(rng *rand.Rand, pool []v1alpha1.ApplicationDestination) []v1alpha1.ApplicationDestination {
	var result []v1alpha1.ApplicationDestination
	for _, item := range pool {
		if rng.IntN(2) == 0 {
			result = append(result, item)
		}
	}
	if len(result) == 0 {
		return pool[:1]
	}
	return result
}

func randomGroupKindSubset(rng *rand.Rand, pool []metav1.GroupKind) []metav1.GroupKind {
	var result []metav1.GroupKind
	for _, item := range pool {
		if rng.IntN(2) == 0 {
			result = append(result, item)
		}
	}
	return result
}

func ruleTypeSet(evidence []RuleEvidence) map[string]struct{} {
	result := make(map[string]struct{}, len(evidence))
	for _, item := range evidence {
		result[item.RuleType] = struct{}{}
	}
	return result
}
