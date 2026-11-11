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
	"cmp"
	"path/filepath"
	"slices"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/argoproj/argo-cd/v3/pkg/apis/application/v1alpha1"
	"github.com/argoproj/argo-cd/v3/util/git"
	"github.com/argoproj/argo-cd/v3/util/glob"
)

// Rule type label for requests whose target cluster is absent from or
// ambiguous within the fixed snapshot.
const RuleTypeUnknownCluster = "unknownCluster"

// ruleOrigin records which project owns an annotated rule and where the rule
// sits inside that project's spec.
type ruleOrigin struct {
	project string
	global  bool
	index   int
}

type annotatedSourceRule struct {
	origin     ruleOrigin
	normalized string
	deny       bool
}

type annotatedDestinationRule struct {
	origin ruleOrigin
	item   v1alpha1.ApplicationDestination
}

type annotatedGroupKind struct {
	origin ruleOrigin
	item   metav1.GroupKind
}

type annotatedClusterItem struct {
	origin ruleOrigin
	item   v1alpha1.ClusterResourceRestrictionItem
}

// preparedProject is one compared project after global project inheritance
// has been applied. The virtual project is consumed by the real rule engines
// while the annotated slices drive evidence collection with the exact same
// matching semantics.
type preparedProject struct {
	name               string
	virtual            *v1alpha1.AppProject
	sourceRules        []annotatedSourceRule
	destinationRules   []annotatedDestinationRule
	namespaceWhitelist []annotatedGroupKind
	namespaceBlacklist []annotatedGroupKind
	clusterWhitelist   []annotatedClusterItem
	clusterBlacklist   []annotatedClusterItem
}

// prepareProject deep-copies the input project and replays
// util/argo.mergeVirtualProject against the fixed global project snapshot.
// The inputs are never mutated.
func prepareProject(proj *v1alpha1.AppProject, globalProjects []*v1alpha1.AppProject) *preparedProject {
	prepared := &preparedProject{
		name:    proj.Name,
		virtual: proj.DeepCopy(),
	}
	prepared.annotateLayer(proj, false)

	for _, globalProj := range globalProjects {
		if globalProj == nil {
			continue
		}
		layer := globalProj.DeepCopy()

		// Mirror the append order of util/argo.mergeVirtualProject.
		prepared.virtual.Spec.ClusterResourceWhitelist = append(prepared.virtual.Spec.ClusterResourceWhitelist, layer.Spec.ClusterResourceWhitelist...)
		prepared.virtual.Spec.ClusterResourceBlacklist = append(prepared.virtual.Spec.ClusterResourceBlacklist, layer.Spec.ClusterResourceBlacklist...)
		prepared.virtual.Spec.NamespaceResourceWhitelist = append(prepared.virtual.Spec.NamespaceResourceWhitelist, layer.Spec.NamespaceResourceWhitelist...)
		prepared.virtual.Spec.NamespaceResourceBlacklist = append(prepared.virtual.Spec.NamespaceResourceBlacklist, layer.Spec.NamespaceResourceBlacklist...)
		prepared.virtual.Spec.SourceRepos = append(prepared.virtual.Spec.SourceRepos, layer.Spec.SourceRepos...)
		prepared.virtual.Spec.Destinations = append(prepared.virtual.Spec.Destinations, layer.Spec.Destinations...)

		prepared.annotateLayer(layer, true)
	}
	return prepared
}

func (p *preparedProject) annotateLayer(proj *v1alpha1.AppProject, global bool) {
	origin := func(index int) ruleOrigin {
		return ruleOrigin{project: proj.Name, global: global, index: index}
	}

	for i, repo := range proj.Spec.SourceRepos {
		var normalized string
		if isDenyPattern(repo) {
			normalized = "!" + git.NormalizeGitURL(strings.TrimPrefix(repo, "!"))
		} else {
			normalized = git.NormalizeGitURL(repo)
		}
		p.sourceRules = append(p.sourceRules, annotatedSourceRule{
			origin:     origin(i),
			normalized: normalized,
			deny:       isDenyPattern(repo),
		})
	}

	for i, destination := range proj.Spec.Destinations {
		p.destinationRules = append(p.destinationRules, annotatedDestinationRule{origin: origin(i), item: destination})
	}

	for i, item := range proj.Spec.NamespaceResourceWhitelist {
		p.namespaceWhitelist = append(p.namespaceWhitelist, annotatedGroupKind{origin: origin(i), item: item})
	}
	for i, item := range proj.Spec.NamespaceResourceBlacklist {
		p.namespaceBlacklist = append(p.namespaceBlacklist, annotatedGroupKind{origin: origin(i), item: item})
	}
	for i, item := range proj.Spec.ClusterResourceWhitelist {
		p.clusterWhitelist = append(p.clusterWhitelist, annotatedClusterItem{origin: origin(i), item: item})
	}
	for i, item := range proj.Spec.ClusterResourceBlacklist {
		p.clusterBlacklist = append(p.clusterBlacklist, annotatedClusterItem{origin: origin(i), item: item})
	}
}

// evaluate computes the verdict for one request against one prepared
// project. Dynamic-subject and action requests are always Unknown; all other
// verdicts are produced by the real AppProject rule engines, with the
// annotated rule slices providing the shortest rule evidence.
func (p *preparedProject) evaluate(snapshot *Snapshot, req CapabilityRequest) RequestVerdict {
	if req.Subject != "" {
		return unknownVerdict(
			RuleTypeUnsupportedSubject,
			"role/Casbin decisions depend on the authenticated subject '"+req.Subject+"', which is outside the supported read-only project rule subset",
			"",
		)
	}

	switch req.Kind {
	case RequestKindSource:
		return p.evaluateSource(req)
	case RequestKindDestination:
		return p.evaluateDestination(snapshot, req.Destination, req.Destination.Namespace)
	case RequestKindResource:
		return p.evaluateResource(snapshot, req)
	case RequestKindAction:
		return unknownVerdict(
			RuleTypeUnsupportedSubject,
			"project role and Casbin action '"+req.Action+"' is enforced per authenticated subject; project-level allow does not imply the user's final RBAC decision",
			req.Action,
		)
	default:
		return unknownVerdict(RuleTypeUnsupportedSubject, "unsupported request kind", string(req.Kind))
	}
}

// evaluateSource mirrors AppProject.IsSourcePermitted: the real engine
// provides the authoritative verdict while a parallel walk over the same
// normalized rules records the deciding rule.
func (p *preparedProject) evaluateSource(req CapabilityRequest) RequestVerdict {
	requestNormalized := git.NormalizeGitURL(req.RepoURL)
	permitted := p.virtual.IsSourcePermitted(v1alpha1.ApplicationSource{RepoURL: req.RepoURL})

	var decidingDeny *annotatedSourceRule
	var allowRules []annotatedSourceRule
	var nonFiringDeny *annotatedSourceRule

	for i := range p.sourceRules {
		rule := &p.sourceRules[i]
		matched := globMatch(rule.normalized, requestNormalized, '/')
		if matched {
			// Same semantics as IsSourcePermitted: a negated rule whose inner
			// glob does not match flips to true and only counts as "matched".
			switch {
			case !rule.deny:
				allowRules = append(allowRules, *rule)
			case nonFiringDeny == nil:
				ruleCopy := *rule
				nonFiringDeny = &ruleCopy
			}
			continue
		}
		if rule.deny {
			ruleCopy := *rule
			decidingDeny = &ruleCopy
			break
		}
	}

	switch {
	case decidingDeny != nil:
		return RequestVerdict{
			Verdict:  VerdictDeny,
			Reason:   "source repository is explicitly denied by a negated source repo rule",
			Evidence: shortestFirst(sourceEvidence(*decidingDeny, true)),
		}
	case permitted:
		if len(allowRules) == 0 && nonFiringDeny != nil {
			// The only match came from a non-firing negated rule; report the
			// real rule origin honestly instead of inventing an allow rule.
			return RequestVerdict{
				Verdict:  VerdictAllow,
				Reason:   "no negated source repo rule matches the requested URL",
				Evidence: shortestFirst(sourceEvidence(*nonFiringDeny, true)),
			}
		}
		if len(allowRules) == 0 {
			return RequestVerdict{
				Verdict: VerdictAllow,
				Reason:  "no source repository rule denies the requested URL",
				Evidence: shortestFirst([]RuleEvidence{{
					Project:  p.name,
					RuleType: RuleTypeSourceRepo,
					Pattern:  sanitizeURLString(requestNormalized),
					Deciding: true,
				}}),
			}
		}
		evidence := make([]RuleEvidence, 0, len(allowRules))
		for _, rule := range allowRules {
			evidence = append(evidence, sourceEvidence(rule, false)...)
		}
		return RequestVerdict{
			Verdict:  VerdictAllow,
			Reason:   "source repository matches an allowed source repo rule",
			Evidence: shortestFirst(evidence),
		}
	default:
		return RequestVerdict{
			Verdict: VerdictDeny,
			Reason:  "no source repository rule permits the requested URL",
			Evidence: []RuleEvidence{{
				Project:  p.name,
				RuleType: RuleTypeNoMatchingRule,
				Pattern:  sanitizeURLString(requestNormalized),
				Deciding: true,
			}},
		}
	}
}

// evaluateDestination mirrors AppProject.IsDestinationPermitted, including
// glob negation and PermitOnlyProjectScopedClusters, using only the fixed
// snapshot for cluster resolution.
func (p *preparedProject) evaluateDestination(snapshot *Snapshot, destination v1alpha1.ApplicationDestination, namespace string) RequestVerdict {
	cluster, reason, resolved := snapshot.resolveCluster(destination)
	if !resolved {
		return unknownVerdict(RuleTypeUnknownCluster, reason, destinationDisplayName(destination))
	}

	permitted, err := p.virtual.IsDestinationPermitted(cluster, namespace, p.projectClustersGetter(snapshot))
	if err != nil {
		return unknownVerdict(RuleTypeUnknownCluster, "destination cannot be evaluated: "+err.Error(), destinationDisplayName(destination))
	}

	dst := v1alpha1.ApplicationDestination{Server: cluster.Server, Name: cluster.Name, Namespace: namespace}
	anyMatched := false
	var decidingDeny *annotatedDestinationRule
	var allowRules []annotatedDestinationRule

	for i := range p.destinationRules {
		rule := &p.destinationRules[i]
		nameMatched := dst.Name != "" && globMatch(rule.item.Name, dst.Name)
		serverMatched := dst.Server != "" && globMatch(rule.item.Server, dst.Server)
		namespaceMatched := globMatch(rule.item.Namespace, dst.Namespace)

		matched := (serverMatched || nameMatched) && namespaceMatched
		switch {
		case matched:
			anyMatched = true
			allowRules = append(allowRules, *rule)
		case ((!nameMatched && isDenyPattern(rule.item.Name)) || (!serverMatched && isDenyPattern(rule.item.Server))) && namespaceMatched:
			ruleCopy := *rule
			decidingDeny = &ruleCopy
		case !namespaceMatched && isDenyPattern(rule.item.Namespace) && serverMatched:
			ruleCopy := *rule
			decidingDeny = &ruleCopy
		}
		if decidingDeny != nil {
			break
		}
	}

	switch {
	case decidingDeny != nil:
		return RequestVerdict{
			Verdict:  VerdictDeny,
			Reason:   "destination is explicitly denied by a negated destination rule",
			Evidence: shortestFirst(destinationEvidence(*decidingDeny, true)),
		}
	case !permitted && anyMatched && p.virtual.Spec.PermitOnlyProjectScopedClusters:
		return RequestVerdict{
			Verdict: VerdictDeny,
			Reason:  "destination matches a glob rule but the cluster is not project-scoped to this project",
			Evidence: shortestFirst([]RuleEvidence{{
				Project:  p.name,
				RuleType: RuleTypeProjectScopedClusters,
				Pattern:  cluster.Server,
				Deciding: true,
			}}),
		}
	case permitted:
		evidence := make([]RuleEvidence, 0, len(allowRules))
		for _, rule := range allowRules {
			evidence = append(evidence, destinationEvidence(rule, false)...)
		}
		return RequestVerdict{
			Verdict:  VerdictAllow,
			Reason:   "destination matches an allowed destination rule",
			Evidence: shortestFirst(evidence),
		}
	default:
		return RequestVerdict{
			Verdict: VerdictDeny,
			Reason:  "no destination rule permits the requested cluster/namespace",
			Evidence: []RuleEvidence{{
				Project:  p.name,
				RuleType: RuleTypeNoMatchingRule,
				Pattern:  destinationDisplayName(dst),
				Deciding: true,
			}},
		}
	}
}

// evaluateResource mirrors validateSyncPermissions: group/kind/name rules are
// checked first, and namespaced resources additionally require the namespace
// destination to be permitted. Cluster-scoped resources skip the destination
// check exactly as the controller does.
func (p *preparedProject) evaluateResource(snapshot *Snapshot, req CapabilityRequest) RequestVerdict {
	groupKind := schema.GroupKind{Group: req.Group, Kind: req.ResourceKind}

	if !req.Namespaced {
		return p.evaluateClusterResource(groupKind, req.Name)
	}

	groupKindVerdict := p.evaluateNamespacedGroupKind(groupKind)
	if groupKindVerdict.Verdict == VerdictDeny {
		return groupKindVerdict
	}

	destinationVerdict := p.evaluateDestination(snapshot, req.Destination, req.Destination.Namespace)
	if destinationVerdict.Verdict == VerdictUnknown || destinationVerdict.Verdict == VerdictDeny {
		return destinationVerdict
	}

	return RequestVerdict{
		Verdict:  VerdictAllow,
		Reason:   "namespaced resource is whitelisted and its namespace destination is permitted",
		Evidence: shortestFirst(append(groupKindVerdict.Evidence, destinationVerdict.Evidence...)),
	}
}

func (p *preparedProject) evaluateNamespacedGroupKind(groupKind schema.GroupKind) RequestVerdict {
	whitelist := p.virtual.Spec.NamespaceResourceWhitelist
	blacklist := p.virtual.Spec.NamespaceResourceBlacklist
	isWhitelisted := whitelist == nil || (len(whitelist) != 0 && p.matchesNamespaceList(p.namespaceWhitelist, groupKind))
	isBlacklisted := len(blacklist) != 0 && p.matchesNamespaceList(p.namespaceBlacklist, groupKind)

	if isBlacklisted {
		var evidence []RuleEvidence
		for _, rule := range p.namespaceBlacklist {
			if groupKindMatch(rule.item, groupKind) {
				evidence = append(evidence, groupKindEvidence(rule.origin, rule.item, RuleTypeNamespaceBlacklist, true))
			}
		}
		return RequestVerdict{
			Verdict:  VerdictDeny,
			Reason:   "namespaced resource matches the namespace resource blacklist",
			Evidence: shortestFirst(evidence),
		}
	}

	if !isWhitelisted {
		return RequestVerdict{
			Verdict: VerdictDeny,
			Reason:  "namespaced resource does not match any namespace resource whitelist rule",
			Evidence: []RuleEvidence{{
				Project:  p.name,
				RuleType: RuleTypeNoMatchingRule,
				Pattern:  groupKindPattern(groupKind.Group, groupKind.Kind),
				Deciding: true,
			}},
		}
	}

	var evidence []RuleEvidence
	for _, rule := range p.namespaceWhitelist {
		if groupKindMatch(rule.item, groupKind) {
			evidence = append(evidence, groupKindEvidence(rule.origin, rule.item, RuleTypeNamespaceWhitelist, false))
		}
	}
	if len(evidence) == 0 {
		// An empty/nil whitelist permits every namespaced resource by default.
		return RequestVerdict{
			Verdict:  VerdictAllow,
			Reason:   "empty namespace resource whitelist permits all namespaced resources by default",
			Evidence: nil,
		}
	}
	return RequestVerdict{
		Verdict:  VerdictAllow,
		Reason:   "namespaced resource matches the namespace resource whitelist",
		Evidence: shortestFirst(evidence),
	}
}

func (p *preparedProject) evaluateClusterResource(groupKind schema.GroupKind, name string) RequestVerdict {
	isWhitelisted := len(p.virtual.Spec.ClusterResourceWhitelist) != 0 && p.matchesClusterList(p.clusterWhitelist, groupKind, name)
	isBlacklisted := len(p.virtual.Spec.ClusterResourceBlacklist) != 0 && p.matchesClusterList(p.clusterBlacklist, groupKind, name)

	if isBlacklisted {
		var evidence []RuleEvidence
		for _, rule := range p.clusterBlacklist {
			if clusterItemMatch(rule.item, groupKind, name) {
				evidence = append(evidence, clusterItemEvidence(rule.origin, rule.item, RuleTypeClusterBlacklist, true))
			}
		}
		return RequestVerdict{
			Verdict:  VerdictDeny,
			Reason:   "cluster-scoped resource matches the cluster resource blacklist",
			Evidence: shortestFirst(evidence),
		}
	}

	if !isWhitelisted {
		return RequestVerdict{
			Verdict: VerdictDeny,
			Reason:  "cluster-scoped resource does not match any cluster resource whitelist rule",
			Evidence: []RuleEvidence{{
				Project:  p.name,
				RuleType: RuleTypeNoMatchingRule,
				Pattern:  clusterItemPattern(groupKind.Group, groupKind.Kind, name),
				Deciding: true,
			}},
		}
	}

	var evidence []RuleEvidence
	for _, rule := range p.clusterWhitelist {
		if clusterItemMatch(rule.item, groupKind, name) {
			evidence = append(evidence, clusterItemEvidence(rule.origin, rule.item, RuleTypeClusterWhitelist, false))
		}
	}
	return RequestVerdict{
		Verdict:  VerdictAllow,
		Reason:   "cluster-scoped resource matches the cluster resource whitelist",
		Evidence: shortestFirst(evidence),
	}
}

func (p *preparedProject) matchesNamespaceList(rules []annotatedGroupKind, groupKind schema.GroupKind) bool {
	for _, rule := range rules {
		if groupKindMatch(rule.item, groupKind) {
			return true
		}
	}
	return false
}

func (p *preparedProject) matchesClusterList(rules []annotatedClusterItem, groupKind schema.GroupKind, name string) bool {
	for _, rule := range rules {
		if clusterItemMatch(rule.item, groupKind, name) {
			return true
		}
	}
	return false
}

// projectClustersGetter builds the PermitOnlyProjectScopedClusters lookup
// used by the real destination engine. A nil snapshot map makes the check
// unevaluable rather than guessing.
func (p *preparedProject) projectClustersGetter(snapshot *Snapshot) func(string) ([]*v1alpha1.Cluster, error) {
	return func(projectName string) ([]*v1alpha1.Cluster, error) {
		if snapshot.ProjectScopedClusters == nil {
			return nil, errProjectScopedClustersUnavailable
		}
		return snapshot.ProjectScopedClusters[projectName], nil
	}
}

// resolveCluster maps a name- or server-based destination onto the fixed
// cluster inventory. Ambiguous and unknown clusters are unevaluable.
func (s *Snapshot) resolveCluster(destination v1alpha1.ApplicationDestination) (*v1alpha1.Cluster, string, bool) {
	switch {
	case destination.Name != "" && destination.Server != "":
		return nil, "destination cannot specify both cluster name and server", false
	case destination.Server != "":
		server := strings.TrimRight(destination.Server, "/")
		for _, cluster := range s.Clusters {
			if cluster != nil && strings.TrimRight(cluster.Server, "/") == server {
				return cluster, "", true
			}
		}
		return nil, "unknown external cluster server not present in the fixed cluster snapshot: " + sanitizeURLString(server), false
	case destination.Name != "":
		var matches []*v1alpha1.Cluster
		for _, cluster := range s.Clusters {
			if cluster != nil && cluster.Name == destination.Name {
				matches = append(matches, cluster)
			}
		}
		switch len(matches) {
		case 0:
			return nil, "unknown cluster name not present in the fixed cluster snapshot: " + destination.Name, false
		case 1:
			return matches[0], "", true
		default:
			return nil, "ambiguous cluster name resolving to multiple clusters in the fixed snapshot: " + destination.Name, false
		}
	default:
		return nil, "destination has neither cluster name nor server", false
	}
}

// globMatch replicates the unexported v1alpha1.globMatch (always called with
// negation enabled) so evidence walks stay byte-identical to the real engines.
func globMatch(pattern string, val string, separators ...rune) bool {
	if isDenyPattern(pattern) {
		return !glob.Match(pattern[1:], val, separators...)
	}
	if pattern == "*" {
		return true
	}
	return glob.Match(pattern, val, separators...)
}

func isDenyPattern(pattern string) bool {
	return strings.HasPrefix(pattern, "!")
}

// groupKindMatch replicates isResourceInList using filepath.Match semantics.
func groupKindMatch(item metav1.GroupKind, groupKind schema.GroupKind) bool {
	kindOK, err := filepath.Match(item.Kind, groupKind.Kind)
	if !kindOK || err != nil {
		return false
	}
	groupOK, err := filepath.Match(item.Group, groupKind.Group)
	return groupOK && err == nil
}

// clusterItemMatch replicates isNamedResourceInList: an empty name matches
// every resource of the given group/kind.
func clusterItemMatch(item v1alpha1.ClusterResourceRestrictionItem, groupKind schema.GroupKind, name string) bool {
	if !groupKindMatch(metav1.GroupKind{Group: item.Group, Kind: item.Kind}, groupKind) {
		return false
	}
	if item.Name == "" {
		return true
	}
	ok, err := filepath.Match(item.Name, name)
	return ok && err == nil
}

func unknownVerdict(ruleType string, reason string, pattern string) RequestVerdict {
	return RequestVerdict{
		Verdict: VerdictUnknown,
		Reason:  reason,
		Evidence: []RuleEvidence{{
			RuleType: ruleType,
			Pattern:  sanitizeURLString(pattern),
			Deciding: true,
		}},
	}
}

func sourceEvidence(rule annotatedSourceRule, deciding bool) []RuleEvidence {
	return []RuleEvidence{{
		Project:   rule.origin.project,
		Global:    rule.origin.global,
		RuleType:  RuleTypeSourceRepo,
		Pattern:   sanitizeURLString(rule.normalized),
		RuleIndex: rule.origin.index,
		Deciding:  deciding,
	}}
}

func destinationEvidence(rule annotatedDestinationRule, deciding bool) []RuleEvidence {
	return []RuleEvidence{{
		Project:   rule.origin.project,
		Global:    rule.origin.global,
		RuleType:  RuleTypeDestination,
		Pattern:   destinationDisplayName(rule.item),
		RuleIndex: rule.origin.index,
		Deciding:  deciding,
	}}
}

func groupKindEvidence(origin ruleOrigin, item metav1.GroupKind, ruleType string, deciding bool) RuleEvidence {
	return RuleEvidence{
		Project:   origin.project,
		Global:    origin.global,
		RuleType:  ruleType,
		Pattern:   groupKindPattern(item.Group, item.Kind),
		RuleIndex: origin.index,
		Deciding:  deciding,
	}
}

func clusterItemEvidence(origin ruleOrigin, item v1alpha1.ClusterResourceRestrictionItem, ruleType string, deciding bool) RuleEvidence {
	return RuleEvidence{
		Project:   origin.project,
		Global:    origin.global,
		RuleType:  ruleType,
		Pattern:   clusterItemPattern(item.Group, item.Kind, item.Name),
		RuleIndex: origin.index,
		Deciding:  deciding,
	}
}

// shortestFirst orders evidence by pattern length (the shortest sufficient
// rule first), with deterministic tie-breaks, and marks the first entry as
// the deciding rule.
func shortestFirst(evidence []RuleEvidence) []RuleEvidence {
	if len(evidence) == 0 {
		return evidence
	}
	slices.SortFunc(evidence, func(a, b RuleEvidence) int {
		if compared := cmp.Compare(len(a.Pattern), len(b.Pattern)); compared != 0 {
			return compared
		}
		if compared := strings.Compare(a.RuleType, b.RuleType); compared != 0 {
			return compared
		}
		if compared := strings.Compare(a.Project, b.Project); compared != 0 {
			return compared
		}
		return cmp.Compare(a.RuleIndex, b.RuleIndex)
	})
	for i := range evidence {
		evidence[i].Deciding = i == 0
	}
	return evidence
}

func groupKindPattern(group string, kind string) string {
	return "group=" + group + ",kind=" + kind
}

func clusterItemPattern(group string, kind string, name string) string {
	return "group=" + group + ",kind=" + kind + ",name=" + name
}

func destinationDisplayName(destination v1alpha1.ApplicationDestination) string {
	return "server=" + sanitizeURLString(destination.Server) +
		",name=" + destination.Name +
		",namespace=" + destination.Namespace
}

func sanitizeSourceRules(rules []string) []string {
	sanitized := make([]string, len(rules))
	for i, rule := range rules {
		if isDenyPattern(rule) {
			sanitized[i] = "!" + sanitizeURLString(strings.TrimPrefix(rule, "!"))
		} else {
			sanitized[i] = sanitizeURLString(rule)
		}
	}
	return sanitized
}

func sanitizeDestinations(destinations []v1alpha1.ApplicationDestination) []v1alpha1.ApplicationDestination {
	sanitized := make([]v1alpha1.ApplicationDestination, len(destinations))
	for i, destination := range destinations {
		destination.Server = sanitizeURLString(destination.Server)
		sanitized[i] = destination
	}
	return sanitized
}

func normalizeRepoURLForIdentity(repoURL string) string {
	return git.NormalizeGitURL(repoURL)
}
