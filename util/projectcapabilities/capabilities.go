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

// Package projectcapabilities provides a read-only comparator for the
// permission-relevant parts of two AppProjects.
//
// The comparator answers a fixed, finite list of capability requests
// (source repositories, destinations, namespaced/cluster resources and
// actions) by reusing the real project rule engines: AppProject source
// normalization and glob/deny matching, destination glob/deny matching and
// resource whitelist/blacklist matching. Global project inheritance and the
// cluster name/URL mapping are taken from a single Snapshot that is shared by
// both projects, so the comparison never observes two different settings
// generations.
//
// Scope and limitations:
//
//   - Verdicts are scoped strictly to the explicit request list. A verdict
//     only describes the requested URL, destination, resource or action; it
//     never claims that two glob languages are equivalent for every possible
//     input.
//   - Project rules are not user RBAC. Role/Casbin policies are enforced
//     against an authenticated, dynamic subject and are not evaluated here;
//     such requests, and requests targeting clusters that are unknown to the
//     fixed snapshot, return VerdictUnknown instead of an allow/deny guess.
//   - The comparator is purely in-memory. It never updates a project, never
//     issues tokens, never contacts repositories or clusters and never
//     returns repository credentials: URL normalization mirrors
//     git.NormalizeGitURL for matching while every URL rendered in a response
//     is stripped of its userinfo component first.
package projectcapabilities

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/argoproj/argo-cd/v3/pkg/apis/application/v1alpha1"
)

// MaxRequests bounds the size of a single comparison request list. The
// comparator only answers explicit, finite lists and rejects unbounded ones.
const MaxRequests = 1000

// RequestKind enumerates the permission domains understood by the comparator.
type RequestKind string

const (
	// RequestKindSource asks whether a repository URL is an allowed source.
	RequestKindSource RequestKind = "source"
	// RequestKindDestination asks whether a cluster/namespace destination is allowed.
	RequestKindDestination RequestKind = "destination"
	// RequestKindResource asks whether a namespaced or cluster-scoped resource is allowed.
	RequestKindResource RequestKind = "resource"
	// RequestKindAction asks about a project role/Casbin action and is always Unknown.
	RequestKindAction RequestKind = "action"
)

// Verdict is the tri-state evaluation result for one capability request.
type Verdict string

const (
	// VerdictAllow means the real project rule engines permit the request.
	VerdictAllow Verdict = "Allow"
	// VerdictDeny means the real project rule engines reject the request.
	VerdictDeny Verdict = "Deny"
	// VerdictUnknown means the request is outside the supported evaluable
	// subset (for example dynamic Casbin subjects or unknown clusters); it is
	// never silently converted into an allow or deny decision.
	VerdictUnknown Verdict = "Unknown"
)

// Rule type labels for RuleEvidence.
const (
	RuleTypeSourceRepo            = "sourceRepo"
	RuleTypeDestination           = "destination"
	RuleTypeNamespaceWhitelist    = "namespaceResourceWhitelist"
	RuleTypeNamespaceBlacklist    = "namespaceResourceBlacklist"
	RuleTypeClusterWhitelist      = "clusterResourceWhitelist"
	RuleTypeClusterBlacklist      = "clusterResourceBlacklist"
	RuleTypeProjectScopedClusters = "projectScopedClusters"
	RuleTypeNoMatchingRule        = "noMatchingRule"
	RuleTypeUnsupportedSubject    = "unsupportedSubject"
)

// CapabilityRequest is one entry of the explicit comparison request list.
// The Kind field selects which of the remaining fields are interpreted:
//
//   - RequestKindSource: RepoURL.
//   - RequestKindDestination: Destination (Server or Name plus Namespace).
//   - RequestKindResource: Group, Kind, Name, Namespaced and, for namespaced
//     resources, Destination holding the target cluster and namespace.
//   - RequestKindAction: Action and, optionally, Subject.
//
// A non-empty Subject on any kind marks a role/Casbin dynamic-subject query,
// which is always evaluated as VerdictUnknown.
type CapabilityRequest struct {
	Kind        RequestKind
	RepoURL     string
	Destination v1alpha1.ApplicationDestination
	Group       string
	// ResourceKind is the Kubernetes resource kind (for example "Deployment").
	ResourceKind string
	Name         string
	Namespaced   bool
	Action       string
	Subject      string
}

// RuleEvidence points at the shortest project rule that explains a verdict.
// Patterns are rendered without credentials and glob negation ("!") is
// preserved so the evidence matches the rule as written in the project.
type RuleEvidence struct {
	// Project is the name of the project owning the rule.
	Project string
	// Global reports whether the rule was inherited from a global project.
	Global bool
	// RuleType is one of the RuleType* constants.
	RuleType string
	// Pattern is the sanitized, human-readable rule representation.
	Pattern string
	// RuleIndex is the zero-based index of the rule within its owning project.
	RuleIndex int
	// Deciding marks the rule that deterministically produced the verdict.
	Deciding bool
}

// RequestVerdict is one project's verdict for one request.
type RequestVerdict struct {
	Verdict  Verdict
	Reason   string
	Evidence []RuleEvidence
}

// RequestComparison pairs the verdicts of the two projects for one request
// and records its Position in the caller-provided request list.
type RequestComparison struct {
	Position int
	Request  CapabilityRequest
	A        RequestVerdict
	B        RequestVerdict
}

// PermissionChange describes one request whose allow state differs between
// the two projects.
type PermissionChange struct {
	Position int
	Request  CapabilityRequest
	From     RequestVerdict
	To       RequestVerdict
}

// CompareResponse is the read-only comparison result. Results preserve the
// order and length of the input list, including duplicate requests.
type CompareResponse struct {
	// LimitsGeneration fingerprints the Snapshot inputs that bound the
	// comparison. Callers can echo it back to reject artifacts computed
	// against a stale generation.
	LimitsGeneration string
	// Results has exactly one entry per input request, in input order.
	Results []RequestComparison
	// AddedPermissions lists requests allowed by project B but not project A.
	AddedPermissions []PermissionChange
	// RemovedPermissions lists requests allowed by project A but not project B.
	RemovedPermissions []PermissionChange
}

// Snapshot is the fixed, read-only view of global projects and cluster
// mappings shared by both compared projects. It is the only source of
// inheritance and cluster name/URL resolution; the comparator performs no
// lookups outside it.
type Snapshot struct {
	// GlobalProjects are the global AppProjects applicable to both compared
	// projects, in the same order as settings would merge them.
	GlobalProjects []*v1alpha1.AppProject
	// Clusters is the fixed cluster inventory. Only Name, Server and Project
	// fields are used; credential-bearing Config data is never read or hashed.
	Clusters []*v1alpha1.Cluster
	// ProjectScopedClusters supplies PermitOnlyProjectScopedClusters lookups
	// keyed by project name. A nil map makes such destinations Unknown.
	ProjectScopedClusters map[string][]*v1alpha1.Cluster
}

// CapabilityComparator evaluates capability request lists against two
// projects under one shared Snapshot. Implementations are read-only,
// deterministic and side-effect free.
type CapabilityComparator interface {
	// Compare evaluates every request against projectA and projectB using
	// the same snapshot. When expectedLimitsGeneration is non-empty it must
	// match the current snapshot generation or the call fails with
	// ErrLimitsGenerationChanged.
	Compare(
		ctx context.Context,
		projectA *v1alpha1.AppProject,
		projectB *v1alpha1.AppProject,
		snapshot *Snapshot,
		requests []CapabilityRequest,
		expectedLimitsGeneration string,
	) (*CompareResponse, error)
}

// Sentinel errors returned by the comparator.
var (
	// ErrLimitsGenerationChanged is returned when a caller-supplied limits
	// generation no longer matches the snapshot, so artifacts derived from
	// the old generation must not be reused.
	ErrLimitsGenerationChanged = status.Error(codes.FailedPrecondition, "limits generation changed: comparison artifacts computed against the previous generation are rejected")
	// ErrInvalidRequest is returned for malformed comparator invocations.
	ErrInvalidRequest = status.Error(codes.InvalidArgument, "invalid project capability comparison request")
	// ErrInternal is returned for unexpected failures unrelated to caller input.
	ErrInternal = status.Error(codes.Internal, "internal project capability comparison error")
)

type comparator struct{}

// NewComparator returns the default read-only CapabilityComparator.
func NewComparator() CapabilityComparator {
	return &comparator{}
}

// Compare implements CapabilityComparator.
func (c *comparator) Compare(
	_ context.Context,
	projectA *v1alpha1.AppProject,
	projectB *v1alpha1.AppProject,
	snapshot *Snapshot,
	requests []CapabilityRequest,
	expectedLimitsGeneration string,
) (*CompareResponse, error) {
	if projectA == nil || projectB == nil {
		return nil, fmt.Errorf("%w: both projects are required", ErrInvalidRequest)
	}
	if snapshot == nil {
		return nil, fmt.Errorf("%w: snapshot is required", ErrInvalidRequest)
	}
	if len(requests) == 0 {
		return nil, fmt.Errorf("%w: request list must not be empty", ErrInvalidRequest)
	}
	if len(requests) > MaxRequests {
		return nil, fmt.Errorf("%w: request list exceeds the limit of %d entries", ErrInvalidRequest, MaxRequests)
	}
	for i := range requests {
		if _, ok := supportedKinds[requests[i].Kind]; !ok {
			return nil, fmt.Errorf("%w: unsupported request kind %q at position %d", ErrInvalidRequest, requests[i].Kind, i)
		}
	}

	generation, err := snapshot.limitsGeneration()
	if err != nil {
		return nil, fmt.Errorf("%w: failed to compute limits generation: %s", ErrInternal, err.Error())
	}
	if expectedLimitsGeneration != "" && expectedLimitsGeneration != generation {
		return nil, ErrLimitsGenerationChanged
	}

	preparedA := prepareProject(projectA, snapshot.GlobalProjects)
	preparedB := prepareProject(projectB, snapshot.GlobalProjects)

	// Deduplicate identical requests by their full identity while preserving
	// every input position in the output.
	cache := make(map[requestIdentity]pairVerdict, len(requests))
	results := make([]RequestComparison, len(requests))
	var added, removed []PermissionChange

	for i := range requests {
		req := requests[i]
		identity := buildIdentity(req)
		pair, found := cache[identity]
		if !found {
			pair = pairVerdict{
				a: preparedA.evaluate(snapshot, req),
				b: preparedB.evaluate(snapshot, req),
			}
			cache[identity] = pair
		}

		sanitized := sanitizeRequest(req)
		results[i] = RequestComparison{
			Position: i,
			Request:  sanitized,
			A:        pair.a,
			B:        pair.b,
		}

		change := PermissionChange{Position: i, Request: sanitized, From: pair.a, To: pair.b}
		switch {
		case pair.a.Verdict != VerdictAllow && pair.b.Verdict == VerdictAllow:
			added = append(added, change)
		case pair.a.Verdict == VerdictAllow && pair.b.Verdict != VerdictAllow:
			removed = append(removed, change)
		}
	}

	return &CompareResponse{
		LimitsGeneration:   generation,
		Results:            results,
		AddedPermissions:   added,
		RemovedPermissions: removed,
	}, nil
}

var supportedKinds = map[RequestKind]struct{}{
	RequestKindSource:      {},
	RequestKindDestination: {},
	RequestKindResource:    {},
	RequestKindAction:      {},
}

type pairVerdict struct {
	a RequestVerdict
	b RequestVerdict
}

// requestIdentity is the comparable full identity of a request used for
// internal deduplication. URL fields use the same normalization as the real
// rule engines so syntactically different but equivalent inputs collapse to
// one evaluation, while every input row still gets its own output position.
type requestIdentity struct {
	Kind          RequestKind
	RepoURL       string
	DestServer    string
	DestName      string
	DestNamespace string
	Group         string
	ResourceKind  string
	Name          string
	Namespaced    bool
	Action        string
	Subject       string
}

func buildIdentity(req CapabilityRequest) requestIdentity {
	return requestIdentity{
		Kind:          req.Kind,
		RepoURL:       normalizeRepoURLForIdentity(req.RepoURL),
		DestServer:    strings.TrimRight(req.Destination.Server, "/"),
		DestName:      req.Destination.Name,
		DestNamespace: req.Destination.Namespace,
		Group:         req.Group,
		ResourceKind:  req.ResourceKind,
		Name:          req.Name,
		Namespaced:    req.Namespaced,
		Action:        req.Action,
		Subject:       req.Subject,
	}
}

// generationPayload is the canonical, credential-free representation of the
// snapshot inputs that bound a comparison.
type generationPayload struct {
	GlobalProjects        []generationProject            `json:"globalProjects"`
	Clusters              []generationCluster            `json:"clusters"`
	ProjectScopedClusters map[string][]generationCluster `json:"projectScopedClusters,omitempty"`
}

type generationProject struct {
	Name                            string                                    `json:"name"`
	Namespace                       string                                    `json:"namespace,omitempty"`
	SourceRepos                     []string                                  `json:"sourceRepos"`
	Destinations                    []v1alpha1.ApplicationDestination         `json:"destinations"`
	ClusterResourceWhitelist        []v1alpha1.ClusterResourceRestrictionItem `json:"clusterResourceWhitelist"`
	ClusterResourceBlacklist        []v1alpha1.ClusterResourceRestrictionItem `json:"clusterResourceBlacklist"`
	NamespaceResourceWhitelist      []metav1.GroupKind                        `json:"namespaceResourceWhitelist"`
	NamespaceResourceBlacklist      []metav1.GroupKind                        `json:"namespaceResourceBlacklist"`
	PermitOnlyProjectScopedClusters bool                                      `json:"permitOnlyProjectScopedClusters,omitempty"`
}

type generationCluster struct {
	Name    string `json:"name,omitempty"`
	Server  string `json:"server"`
	Project string `json:"project,omitempty"`
}

// limitsGeneration computes a stable fingerprint of the limits-relevant
// snapshot content. Only non-credential fields are included.
func (s *Snapshot) limitsGeneration() (string, error) {
	payload := generationPayload{
		GlobalProjects:        make([]generationProject, 0, len(s.GlobalProjects)),
		Clusters:              make([]generationCluster, 0, len(s.Clusters)),
		ProjectScopedClusters: make(map[string][]generationCluster, len(s.ProjectScopedClusters)),
	}

	for _, gp := range s.GlobalProjects {
		if gp == nil {
			continue
		}
		payload.GlobalProjects = append(payload.GlobalProjects, generationProject{
			Name:                            gp.Name,
			Namespace:                       gp.Namespace,
			SourceRepos:                     sanitizeSourceRules(gp.Spec.SourceRepos),
			Destinations:                    sanitizeDestinations(gp.Spec.Destinations),
			ClusterResourceWhitelist:        gp.Spec.ClusterResourceWhitelist,
			ClusterResourceBlacklist:        gp.Spec.ClusterResourceBlacklist,
			NamespaceResourceWhitelist:      gp.Spec.NamespaceResourceWhitelist,
			NamespaceResourceBlacklist:      gp.Spec.NamespaceResourceBlacklist,
			PermitOnlyProjectScopedClusters: gp.Spec.PermitOnlyProjectScopedClusters,
		})
	}

	for _, cluster := range s.Clusters {
		if cluster == nil {
			continue
		}
		payload.Clusters = append(payload.Clusters, generationCluster{
			Name:    cluster.Name,
			Server:  sanitizeURLString(cluster.Server),
			Project: cluster.Project,
		})
	}

	for projectName, clusters := range s.ProjectScopedClusters {
		views := make([]generationCluster, 0, len(clusters))
		for _, cluster := range clusters {
			if cluster == nil {
				continue
			}
			views = append(views, generationCluster{
				Name:    cluster.Name,
				Server:  sanitizeURLString(cluster.Server),
				Project: cluster.Project,
			})
		}
		payload.ProjectScopedClusters[projectName] = views
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// sanitizeRequest returns a copy of req with every URL field stripped of
// credentials. Matching still uses the original input; only outputs are
// sanitized.
func sanitizeRequest(req CapabilityRequest) CapabilityRequest {
	out := req
	out.RepoURL = sanitizeURLString(req.RepoURL)
	out.Destination.Server = sanitizeURLString(req.Destination.Server)
	return out
}

// sanitizeURLString removes userinfo (username/password) from a URL while
// preserving the rest of the string. Inputs that cannot be parsed fall back
// to a naive cut so credentials are never rendered.
func sanitizeURLString(raw string) string {
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed == nil {
		return naiveStripUserInfo(raw)
	}
	if parsed.User == nil {
		return raw
	}
	parsed.User = nil
	return parsed.String()
}

// naiveStripUserInfo handles URLs url.Parse cannot interpret by cutting the
// userinfo component between "://" (or the start) and the last "@" before the
// first path separator.
func naiveStripUserInfo(raw string) string {
	schemeIndex := strings.Index(raw, "://")
	prefix := ""
	rest := raw
	if schemeIndex >= 0 {
		prefix = raw[:schemeIndex+3]
		rest = raw[schemeIndex+3:]
	}
	pathIndex := strings.IndexAny(rest, "/?#")
	authority := rest
	remainder := ""
	if pathIndex >= 0 {
		authority = rest[:pathIndex]
		remainder = rest[pathIndex:]
	}
	if atIndex := strings.LastIndex(authority, "@"); atIndex >= 0 {
		authority = authority[atIndex+1:]
	}
	return prefix + authority + remainder
}

// errProjectScopedClustersUnavailable marks destinations whose
// PermitOnlyProjectScopedClusters check cannot be answered from the snapshot.
var errProjectScopedClustersUnavailable = errors.New("project-scoped cluster inventory is not available in the snapshot")
