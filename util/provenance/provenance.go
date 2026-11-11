// Package provenance implements the optional ManifestProvenanceGraph, which records where
// rendered manifests and their fields came from.
//
// The graph is built by observers that are explicitly attached to the rendering and
// normalization pipeline. When no observer is attached the pipeline behaves exactly as before:
// rendering output, merge order, cache keys and permission checks are unchanged.
//
// Evidence levels are deliberately conservative:
//   - FieldLevel is only produced for native directory YAML/JSON documents that Argo CD decoded
//     itself, so every field can be tied to a concrete input document.
//   - Helm, Kustomize, CMP and Jsonnet renderers cannot provide field-to-template mappings, so
//     their objects are recorded as Opaque. Argo CD never guesses template line numbers from
//     coincidentally identical text.
//   - Values produced by Argo CD processing (List expansion, default namespace injection,
//     tracking metadata and other generated fields) are recorded with explicit Derived evidence.
//   - Unavailable means evidence could not be obtained (for example a cache entry produced by an
//     incompatible artifact version); it must never be silently upgraded to precise evidence.
package provenance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/argoproj/argo-cd/v3/common"
	appv1 "github.com/argoproj/argo-cd/v3/pkg/apis/application/v1alpha1"
	"github.com/argoproj/argo-cd/v3/util/git"
)

// ArtifactVersion identifies the on-disk/in-cache layout of the graph. A cached graph is only
// reused when its artifact version matches this constant; otherwise the graph is reported as
// Unavailable instead of being interpreted under a mismatched schema.
const ArtifactVersion = "v1"

// Default graph size limits. The graph is a diagnostic side channel and must never be allowed
// to grow without bounds.
const (
	DefaultMaxNodes           = 10000
	DefaultMaxFieldsPerObject = 200
	DefaultMaxOutputBytes     = 4 * 1024 * 1024
)

// EvidenceLevel states how precisely the origin of an object or field is known.
type EvidenceLevel string

const (
	// EvidenceFieldLevel means the value was decoded from a specific, known input document.
	EvidenceFieldLevel EvidenceLevel = "FieldLevel"
	// EvidenceObjectLevel means the owning source is known but no field mapping is available.
	EvidenceObjectLevel EvidenceLevel = "ObjectLevel"
	// EvidenceOpaque means the object came from a renderer (Helm/Kustomize/CMP/Jsonnet) that
	// cannot provide field-level mappings.
	EvidenceOpaque EvidenceLevel = "Opaque"
	// EvidenceDerived means the value was produced by Argo CD processing rather than read
	// verbatim from an input document.
	EvidenceDerived EvidenceLevel = "Derived"
	// EvidenceUnavailable means evidence cannot be provided for this object or field.
	EvidenceUnavailable EvidenceLevel = "Unavailable"
)

// GraphStatus is the overall availability of the graph.
type GraphStatus string

const (
	StatusAvailable   GraphStatus = "Available"
	StatusUnavailable GraphStatus = "Unavailable"
)

// DerivedReason explains why a value is considered derived by Argo CD.
type DerivedReason string

const (
	// DerivedListExpansion marks objects extracted from a Kubernetes List document.
	DerivedListExpansion DerivedReason = "ListExpansion"
	// DerivedDefaultNamespace marks a namespace injected from the Application destination.
	DerivedDefaultNamespace DerivedReason = "DefaultNamespace"
	// DerivedTrackingMetadata marks tracking labels/annotations written by resource tracking.
	DerivedTrackingMetadata DerivedReason = "TrackingMetadata"
	// DerivedGeneratedField marks any other field generated outside of the input documents.
	DerivedGeneratedField DerivedReason = "GeneratedField"
)

// ContributionOutcome describes what happened to a source contribution for a shared object.
type ContributionOutcome string

const (
	// OutcomeWinner is the source whose object survived target object normalization.
	OutcomeWinner ContributionOutcome = "Winner"
	// OutcomeOverridden is a source whose whole object was replaced by a later source. Its
	// fields are never represented as inherited by the winning object.
	OutcomeOverridden ContributionOutcome = "Overridden"
)

// Options controls graph collection limits. The zero value is replaced by defaults; callers
// only need to set the fields they want to override.
type Options struct {
	// MaxNodes caps the number of object nodes in the graph.
	MaxNodes int
	// MaxFieldsPerObject caps the number of field evidence entries stored per object.
	MaxFieldsPerObject int
	// MaxOutputBytes caps the serialized size of the final graph.
	MaxOutputBytes int
	// IncludeInputText allows storing input document text. It is disabled by default: the
	// graph stores document identity (path digest, content digest) but never full contents.
	IncludeInputText bool
}

func (o Options) withDefaults() Options {
	if o.MaxNodes <= 0 {
		o.MaxNodes = DefaultMaxNodes
	}
	if o.MaxFieldsPerObject <= 0 {
		o.MaxFieldsPerObject = DefaultMaxFieldsPerObject
	}
	if o.MaxOutputBytes <= 0 {
		o.MaxOutputBytes = DefaultMaxOutputBytes
	}
	return o
}

// SourceIdentity binds a source to redacted, non-temporary identity information.
type SourceIdentity struct {
	// SourceIndex is the zero-based index of the source in the Application sources list.
	SourceIndex int `json:"sourceIndex"`
	// Name is the optional source name from the Application spec.
	Name string `json:"name,omitempty"`
	// RepoURLRedacted is the repository URL with embedded credentials (userinfo) stripped.
	RepoURLRedacted string `json:"repoURLRedacted,omitempty"`
	// ResolvedRevision is the concrete commit SHA the revision resolved to.
	ResolvedRevision string `json:"resolvedRevision,omitempty"`
	// PathDigest is the SHA-256 digest of the repository-relative source path.
	PathDigest string `json:"pathDigest"`
	// SourceType is the resolved application source type (Directory, Helm, Kustomize, ...).
	SourceType string `json:"sourceType,omitempty"`
}

// InputDocumentRef points at a document inside a source without embedding its full text.
type InputDocumentRef struct {
	// ID is the graph-local stable identifier referenced by field evidence.
	ID string `json:"id"`
	// SourceIndex is the owning source index.
	SourceIndex int `json:"sourceIndex"`
	// RepoRelativePath is the path relative to the repository root. Temporary checkout roots
	// are never stored.
	RepoRelativePath string `json:"repoRelativePath,omitempty"`
	// PathDigest is the SHA-256 digest of the repository-relative path.
	PathDigest string `json:"pathDigest"`
	// DocumentIndex is the zero-based document index within a multi-document YAML file.
	DocumentIndex int `json:"documentIndex"`
	// ContentDigest is the optional SHA-256 digest of the raw document bytes.
	ContentDigest string `json:"contentDigest,omitempty"`
	// InputText is only populated when Options.IncludeInputText is explicitly enabled.
	InputText string `json:"inputText,omitempty"`
}

// FieldEvidence associates a field path with an evidence level.
type FieldEvidence struct {
	// FieldPath is a deterministic dotted/bracketed path, e.g.
	// `metadata.labels["app.kubernetes.io/instance"]`.
	FieldPath string `json:"fieldPath"`
	// Level is the evidence level. FieldLevel entries must reference an input document.
	Level EvidenceLevel `json:"level"`
	// SourceIndex is the source that produced the value.
	SourceIndex int `json:"sourceIndex"`
	// DocumentID references the input document for FieldLevel evidence.
	DocumentID string `json:"documentID,omitempty"`
	// DerivedReason is set for Derived evidence.
	DerivedReason DerivedReason `json:"derivedReason,omitempty"`
	// Note carries short non-sensitive diagnostics (e.g. the opaque renderer name).
	Note string `json:"note,omitempty"`
}

// DerivedOrigin records that an object node exists because of an Argo CD transformation.
type DerivedOrigin struct {
	// Reason is the kind of transformation.
	Reason DerivedReason `json:"reason"`
	// SourceIndex is the source in which the transformation happened.
	SourceIndex int `json:"sourceIndex"`
	// DocumentID is the underlying document, when one is known (e.g. the parent List document).
	DocumentID string `json:"documentID,omitempty"`
}

// ObjectContribution records the participation of a source in a shared (same-identity) object.
type ObjectContribution struct {
	// SourceIndex is the contributing source.
	SourceIndex int `json:"sourceIndex"`
	// DocumentID is the input document, when known.
	DocumentID string `json:"documentID,omitempty"`
	// Level is the best evidence available for this contribution.
	Level EvidenceLevel `json:"level"`
	// Outcome states whether this contribution won or was overridden.
	Outcome ContributionOutcome `json:"outcome"`
}

// ObjectProvenance is one node of the manifest provenance graph.
type ObjectProvenance struct {
	// ObjectKey is group/kind/namespace/name of the object.
	ObjectKey string `json:"objectKey"`
	Group     string `json:"group,omitempty"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	// SourceIndex is the winning source for this object.
	SourceIndex int `json:"sourceIndex"`
	// OutputIndex is the zero-based index of the object within its source output manifests.
	OutputIndex int `json:"outputIndex"`
	// OutputDigest is the SHA-256 digest of the exact rendered manifest bytes returned for the
	// object. It lets consumers verify that evidence matches the bytes they actually received.
	OutputDigest string `json:"outputDigest,omitempty"`
	// Level is the best evidence level available for the object body.
	Level EvidenceLevel `json:"level"`
	// Note carries short object-level, non-sensitive diagnostics (e.g. the opaque renderer
	// name). It is never field evidence.
	Note string `json:"note,omitempty"`
	// DocumentID is the originating input document for precise evidence.
	DocumentID string `json:"documentID,omitempty"`
	// Fields contains field-level and derived evidence, subject to the configured field cap.
	Fields []FieldEvidence `json:"fields,omitempty"`
	// Derived lists transformations (e.g. List expansion) that produced this node.
	Derived []DerivedOrigin `json:"derived,omitempty"`
	// Contributions records every source that produced an object with the same identity.
	Contributions []ObjectContribution `json:"contributions,omitempty"`
	// Outcome is Winner for surviving objects and Overridden for whole-object losers.
	Outcome ContributionOutcome `json:"outcome"`
	// Warnings contains object-scoped non-sensitive warnings.
	Warnings []string `json:"warnings,omitempty"`
}

// GraphLimits reports the limits that were in effect while building the graph.
type GraphLimits struct {
	MaxNodes           int  `json:"maxNodes"`
	MaxFieldsPerObject int  `json:"maxFieldsPerObject"`
	MaxOutputBytes     int  `json:"maxOutputBytes"`
	IncludeInputText   bool `json:"includeInputText"`
}

// ManifestProvenanceGraph is the serialized provenance artifact.
type ManifestProvenanceGraph struct {
	// ArtifactVersion is the schema/artifact version of this graph.
	ArtifactVersion string `json:"artifactVersion"`
	// Status is Available or Unavailable.
	Status GraphStatus `json:"status"`
	// UnavailableReason explains why evidence is unavailable.
	UnavailableReason string `json:"unavailableReason,omitempty"`
	// Sources are the redacted source identities, ordered by source index.
	Sources []SourceIdentity `json:"sources"`
	// Documents are input document references, ordered by ID.
	Documents []InputDocumentRef `json:"documents"`
	// Objects are object nodes, ordered by source index, output index and object key.
	Objects []*ObjectProvenance `json:"objects"`
	// Warnings are graph-level warnings (e.g. duplicate resources).
	Warnings []string `json:"warnings,omitempty"`
	// Limits reports the effective collection limits.
	Limits GraphLimits `json:"limits"`
	// Truncated is true when any limit was reached.
	Truncated bool `json:"truncated"`
	// OmittedNodes counts object nodes dropped because of MaxNodes.
	OmittedNodes int `json:"omittedNodes,omitempty"`
	// OmittedFields counts field entries dropped because of field/byte limits.
	OmittedFields int `json:"omittedFields,omitempty"`
}

// Recorder collects provenance for one render/normalize pipeline. It is safe for concurrent
// use because repo-server manifest generation is asynchronous.
type Recorder struct {
	mu sync.Mutex

	opts Options

	sources       map[int]*SourceIdentity
	documents     map[string]*InputDocumentRef
	documentOrder []string
	docSeq        int

	objects   []*ObjectProvenance
	ptrIndex  map[uintptr]*ObjectProvenance
	posIndex  map[int]*ObjectProvenance
	outputSeq map[int]int
	warnings  []string
	truncated bool

	omittedNodes  int
	omittedFields int

	status            GraphStatus
	unavailableReason string
}

// NewRecorder creates a recorder with the given options. A nil options pointer selects defaults.
func NewRecorder(opts *Options) *Recorder {
	var o Options
	if opts != nil {
		o = *opts
	}
	o = o.withDefaults()
	return &Recorder{
		opts:      o,
		sources:   make(map[int]*SourceIdentity),
		documents: make(map[string]*InputDocumentRef),
		ptrIndex:  make(map[uintptr]*ObjectProvenance),
		posIndex:  make(map[int]*ObjectProvenance),
		outputSeq: make(map[int]int),
		status:    StatusAvailable,
	}
}

// DigestPath returns the SHA-256 hex digest of a repository-relative path. Path separators are
// normalized so the digest is stable across operating systems.
func DigestPath(repoRelativePath string) string {
	sum := sha256.Sum256([]byte(filepath.ToSlash(repoRelativePath)))
	return hex.EncodeToString(sum[:])
}

// DigestBytes returns the SHA-256 hex digest of raw bytes.
func DigestBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// NewSourceIdentity builds a redacted source identity. The raw repository URL is sanitized
// (userinfo/credentials stripped) and only the digest of the source path is retained.
func NewSourceIdentity(sourceIndex int, name, rawRepoURL, resolvedRevision, repoRelativePath, sourceType string) SourceIdentity {
	return SourceIdentity{
		SourceIndex:      sourceIndex,
		Name:             name,
		RepoURLRedacted:  git.SanitizeRepoURL(rawRepoURL),
		ResolvedRevision: resolvedRevision,
		PathDigest:       DigestPath(repoRelativePath),
		SourceType:       sourceType,
	}
}

// BindSource registers (or updates) the identity of a source.
func (r *Recorder) BindSource(identity SourceIdentity) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := identity
	r.sources[identity.SourceIndex] = &cp
}

// BindRenderedSource fills in the render-time parts of a source identity (redacted repository
// URL, resolved revision, source path digest and source type) while preserving the source index
// and optional name configured by the caller.
func (r *Recorder) BindRenderedSource(sourceIndex int, rawRepoURL, resolvedRevision, repoRelativePath, sourceType string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	identity := SourceIdentity{
		SourceIndex:      sourceIndex,
		RepoURLRedacted:  git.SanitizeRepoURL(rawRepoURL),
		ResolvedRevision: resolvedRevision,
		PathDigest:       DigestPath(repoRelativePath),
		SourceType:       sourceType,
	}
	if existing, ok := r.sources[sourceIndex]; ok {
		identity.Name = existing.Name
	}
	r.sources[sourceIndex] = &identity
}

// SourceIndex returns the source index the recorder was created for. A repo-server manifest
// generation always handles a single source; the index defaults to zero when unset.
func (r *Recorder) SourceIndex() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.sources) == 0 {
		return 0
	}
	indexes := make([]int, 0, len(r.sources))
	for idx := range r.sources {
		indexes = append(indexes, idx)
	}
	sort.Ints(indexes)
	return indexes[0]
}

// MarkUnavailable marks the whole graph as unavailable. Existing collected nodes are retained
// but consumers must not treat their evidence as authoritative.
func (r *Recorder) MarkUnavailable(reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status = StatusUnavailable
	r.unavailableReason = reason
}

// AddWarning records a graph-level, non-sensitive warning.
func (r *Recorder) AddWarning(msg string) {
	if msg == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.warnings = append(r.warnings, msg)
}

// RecordInputDocument registers an input document and returns its graph-local ID. The raw
// document content is only stored when IncludeInputText is enabled; otherwise only digests are
// kept. repoRelativePath must not be a temporary checkout path.
func (r *Recorder) RecordInputDocument(sourceIndex int, repoRelativePath string, documentIndex int, content []byte) string {
	r.mu.Lock()
	defer r.mu.Unlock()

	// A document is uniquely identified by source, repository-relative path and document index.
	uniqueKey := fmt.Sprintf("%d|%s|%d", sourceIndex, filepath.ToSlash(safeRelPath(repoRelativePath)), documentIndex)
	if existing, ok := r.documents[uniqueKey]; ok {
		return existing.ID
	}

	docID := fmt.Sprintf("s%d-doc%d", sourceIndex, r.docSeq)
	r.docSeq++
	ref := &InputDocumentRef{
		ID:               docID,
		SourceIndex:      sourceIndex,
		RepoRelativePath: safeRelPath(repoRelativePath),
		PathDigest:       DigestPath(repoRelativePath),
		DocumentIndex:    documentIndex,
	}
	if len(content) > 0 {
		ref.ContentDigest = DigestBytes(content)
		if r.opts.IncludeInputText {
			ref.InputText = string(content)
		}
	}
	r.documents[docID] = ref
	r.documents[uniqueKey] = ref
	r.documentOrder = append(r.documentOrder, docID)
	return docID
}

// RecordDirectoryObject records an object decoded from a native directory YAML/JSON document.
// Its fields get FieldLevel evidence pointing at the given input document.
func (r *Recorder) RecordDirectoryObject(sourceIndex int, obj *unstructured.Unstructured, docID string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	rec := r.newObjectLocked(sourceIndex, obj, EvidenceFieldLevel)
	if rec == nil {
		return
	}
	rec.DocumentID = docID
	r.recordDirectoryFieldsLocked(rec, obj, docID)
	r.ptrIndex[objectPointer(obj)] = rec
}

// RecordOpaqueObject records an object produced by a renderer that cannot provide field
// mappings (Helm, Kustomize, CMP, Jsonnet). No FieldLevel evidence is ever created; only
// Argo-generated fields may be attached later as Derived evidence.
func (r *Recorder) RecordOpaqueObject(sourceIndex int, obj *unstructured.Unstructured, renderer string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	rec := r.newObjectLocked(sourceIndex, obj, EvidenceOpaque)
	if rec == nil {
		return
	}
	rec.DocumentID = ""
	rec.Note = renderer
	r.ptrIndex[objectPointer(obj)] = rec
}

// RecordListExpansion records that items were extracted from a Kubernetes List object. Each
// item gets an explicit Derived origin referencing the parent document; the item body fields
// remain FieldLevel when they were decoded from that same document.
func (r *Recorder) RecordListExpansion(sourceIndex int, parent, item *unstructured.Unstructured) {
	r.mu.Lock()
	defer r.mu.Unlock()

	parentRec := r.ptrIndex[objectPointer(parent)]
	docID := ""
	if parentRec != nil {
		docID = parentRec.DocumentID
	}

	itemRec := r.ptrIndex[objectPointer(item)]
	if itemRec == nil {
		itemRec = r.newObjectLocked(sourceIndex, item, EvidenceFieldLevel)
		if itemRec == nil {
			return
		}
		if docID != "" {
			itemRec.DocumentID = docID
			r.recordDirectoryFieldsLocked(itemRec, item, docID)
		} else {
			itemRec.Level = EvidenceDerived
		}
		r.ptrIndex[objectPointer(item)] = itemRec
	}
	itemRec.Derived = append(itemRec.Derived, DerivedOrigin{
		Reason:      DerivedListExpansion,
		SourceIndex: sourceIndex,
		DocumentID:  docID,
	})
}

// RecordDerivedField records that a field value was produced by Argo CD processing. Any
// previous evidence for the same field path is replaced, so generated values (tracking
// metadata, default namespace) are never presented as verbatim input values.
func (r *Recorder) RecordDerivedField(obj *unstructured.Unstructured, fieldPath string, reason DerivedReason) {
	r.mu.Lock()
	defer r.mu.Unlock()

	rec := r.ptrIndex[objectPointer(obj)]
	if rec == nil {
		return
	}
	r.upsertDerivedFieldLocked(rec, fieldPath, reason)
}

// RecordOutputManifest binds an object to the exact rendered output bytes. The digest allows
// later consumers (and the cache layer) to verify that evidence matches the delivered bytes.
func (r *Recorder) RecordOutputManifest(obj *unstructured.Unstructured, manifest []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()

	rec := r.ptrIndex[objectPointer(obj)]
	if rec == nil {
		return
	}
	rec.OutputIndex = r.outputSeq[rec.SourceIndex]
	r.outputSeq[rec.SourceIndex]++
	rec.OutputDigest = DigestBytes(manifest)
}

// RecordSourceOutput registers the objects of one source in global target-object slice order.
// It is used on the normalization side (for example after GetRepoObjs), where only rendered
// manifest strings cross the process boundary: object-level source attribution is precise,
// while field-level mapping stays unavailable unless a matching source graph is attached.
func (r *Recorder) RecordSourceOutput(identity SourceIdentity, manifestStrings []string, objs []*unstructured.Unstructured) {
	r.mu.Lock()
	defer r.mu.Unlock()

	cp := identity
	r.sources[identity.SourceIndex] = &cp

	globalBase := len(r.posIndex)
	for i, obj := range objs {
		if obj == nil {
			continue
		}
		rec := r.newObjectLocked(identity.SourceIndex, obj, EvidenceObjectLevel)
		if rec == nil {
			continue
		}
		rec.OutputIndex = i
		if i < len(manifestStrings) {
			rec.OutputDigest = DigestBytes([]byte(manifestStrings[i]))
		}
		pos := globalBase + i
		r.posIndex[pos] = rec
		r.ptrIndex[objectPointer(obj)] = rec
	}
}

// RecordNormalizeDerived records a derived field during target object normalization,
// addressing the object by its global target-object slice position.
func (r *Recorder) RecordNormalizeDerived(globalIndex int, fieldPath string, reason DerivedReason) {
	r.mu.Lock()
	defer r.mu.Unlock()

	rec := r.posIndex[globalIndex]
	if rec == nil {
		return
	}
	r.upsertDerivedFieldLocked(rec, fieldPath, reason)
}

// RecordIdentityOverride records same-identity whole-object replacement during target object
// normalization. winnerGlobalIndex is the surviving object; overriddenGlobalIndexes are the
// losers. Loser field evidence stays attached to the loser nodes but is never copied onto the
// winner, so an override can never be displayed as merged field inheritance.
func (r *Recorder) RecordIdentityOverride(winnerGlobalIndex int, overriddenGlobalIndexes []int, key string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	winner := r.posIndex[winnerGlobalIndex]
	if winner == nil {
		return
	}

	winner.Contributions = appendContribution(winner.Contributions, ObjectContribution{
		SourceIndex: winner.SourceIndex,
		DocumentID:  winner.DocumentID,
		Level:       winner.Level,
		Outcome:     OutcomeWinner,
	})
	winner.Outcome = OutcomeWinner
	winner.Warnings = append(winner.Warnings, fmt.Sprintf("Resource %s: source %d object overrides %d earlier source object(s); overridden fields are not inherited", key, winner.SourceIndex, len(overriddenGlobalIndexes)))

	for _, idx := range overriddenGlobalIndexes {
		loser := r.posIndex[idx]
		if loser == nil {
			continue
		}
		loser.Outcome = OutcomeOverridden
		loser.Contributions = appendContribution(loser.Contributions, ObjectContribution{
			SourceIndex: loser.SourceIndex,
			DocumentID:  loser.DocumentID,
			Level:       loser.Level,
			Outcome:     OutcomeOverridden,
		})
		winner.Contributions = appendContribution(winner.Contributions, ObjectContribution{
			SourceIndex: loser.SourceIndex,
			DocumentID:  loser.DocumentID,
			Level:       loser.Level,
			Outcome:     OutcomeOverridden,
		})
	}
}

// ImportCachedGraph adopts a graph produced by a previous render, provided its artifact
// version matches. A mismatch marks the recorder Unavailable instead of reusing stale evidence.
func (r *Recorder) ImportCachedGraph(g *ManifestProvenanceGraph) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if g == nil {
		r.markUnavailableLocked("cached manifest entry has no provenance artifact")
		return
	}
	if g.ArtifactVersion != ArtifactVersion {
		r.markUnavailableLocked(fmt.Sprintf("cached provenance artifact version %q does not match %q", g.ArtifactVersion, ArtifactVersion))
		return
	}
	r.status = g.Status
	r.unavailableReason = g.UnavailableReason
	r.truncated = g.Truncated
	r.omittedNodes = g.OmittedNodes
	r.omittedFields = g.OmittedFields
	r.warnings = append(r.warnings, g.Warnings...)
	for i := range g.Sources {
		src := g.Sources[i]
		r.sources[src.SourceIndex] = &src
	}
	r.documents = make(map[string]*InputDocumentRef, len(g.Documents))
	r.documentOrder = r.documentOrder[:0]
	for i := range g.Documents {
		doc := g.Documents[i]
		cp := doc
		r.documents[doc.ID] = &cp
		r.documentOrder = append(r.documentOrder, doc.ID)
	}
	r.objects = append(r.objects, g.Objects...)
	for _, obj := range g.Objects {
		// Cached objects can only be re-aligned by output position/digest, not pointer.
		r.posIndex[len(r.posIndex)] = obj
	}
}

// Graph finalizes and returns the collected graph. The recorder must not be used after calling
// Graph. The returned graph is sorted deterministically and enforced against MaxOutputBytes.
func (r *Recorder) Graph() *ManifestProvenanceGraph {
	r.mu.Lock()
	defer r.mu.Unlock()

	graph := &ManifestProvenanceGraph{
		ArtifactVersion:   ArtifactVersion,
		Status:            r.status,
		UnavailableReason: r.unavailableReason,
		Warnings:          append([]string(nil), r.warnings...),
		Limits: GraphLimits{
			MaxNodes:           r.opts.MaxNodes,
			MaxFieldsPerObject: r.opts.MaxFieldsPerObject,
			MaxOutputBytes:     r.opts.MaxOutputBytes,
			IncludeInputText:   r.opts.IncludeInputText,
		},
		Truncated:     r.truncated,
		OmittedNodes:  r.omittedNodes,
		OmittedFields: r.omittedFields,
	}

	sourceIndexes := make([]int, 0, len(r.sources))
	for idx := range r.sources {
		sourceIndexes = append(sourceIndexes, idx)
	}
	sort.Ints(sourceIndexes)
	for _, idx := range sourceIndexes {
		graph.Sources = append(graph.Sources, *r.sources[idx])
	}

	for _, docID := range r.documentOrder {
		doc := *r.documents[docID]
		graph.Documents = append(graph.Documents, doc)
	}

	// Work on copies so byte-budget trimming never mutates recorder state: Graph() may be
	// called more than once (for example once to cache the artifact and once by the caller).
	for _, obj := range r.objects {
		cp := *obj
		cp.Fields = append([]FieldEvidence(nil), obj.Fields...)
		cp.Derived = append([]DerivedOrigin(nil), obj.Derived...)
		cp.Contributions = append([]ObjectContribution(nil), obj.Contributions...)
		cp.Warnings = append([]string(nil), obj.Warnings...)
		graph.Objects = append(graph.Objects, &cp)
	}
	sort.SliceStable(graph.Objects, func(i, j int) bool {
		a, b := graph.Objects[i], graph.Objects[j]
		if a.SourceIndex != b.SourceIndex {
			return a.SourceIndex < b.SourceIndex
		}
		if a.OutputIndex != b.OutputIndex {
			return a.OutputIndex < b.OutputIndex
		}
		return a.ObjectKey < b.ObjectKey
	})

	r.enforceByteBudgetLocked(graph)
	return graph
}

// Validate checks graph invariants. It is used by tests and cautious consumers to make sure
// opaque/unavailable evidence is never presented as precise field evidence.
func (g *ManifestProvenanceGraph) Validate() error {
	if g == nil {
		return errors.New("provenance graph is nil")
	}
	if g.ArtifactVersion != ArtifactVersion {
		return fmt.Errorf("provenance graph artifact version %q does not match %q", g.ArtifactVersion, ArtifactVersion)
	}
	docIDs := make(map[string]bool, len(g.Documents))
	for _, doc := range g.Documents {
		if doc.ID == "" {
			return errors.New("provenance document has empty ID")
		}
		if docIDs[doc.ID] {
			return fmt.Errorf("duplicate provenance document ID %q", doc.ID)
		}
		docIDs[doc.ID] = true
		if filepath.IsAbs(doc.RepoRelativePath) {
			return fmt.Errorf("provenance document %q leaks an absolute path: %q", doc.ID, doc.RepoRelativePath)
		}
	}
	for _, obj := range g.Objects {
		switch obj.Level {
		case EvidenceFieldLevel:
			if obj.DocumentID == "" {
				return fmt.Errorf("field-level object %q has no input document", obj.ObjectKey)
			}
		case EvidenceOpaque, EvidenceObjectLevel, EvidenceUnavailable:
			for _, field := range obj.Fields {
				if field.Level == EvidenceFieldLevel {
					return fmt.Errorf("object %q at level %q must not carry precise field evidence for %q", obj.ObjectKey, obj.Level, field.FieldPath)
				}
			}
		}
		for _, field := range obj.Fields {
			if field.Level == EvidenceFieldLevel && !docIDs[field.DocumentID] {
				return fmt.Errorf("object %q field %q references unknown document %q", obj.ObjectKey, field.FieldPath, field.DocumentID)
			}
			if field.Level == EvidenceDerived && field.DerivedReason == "" {
				return fmt.Errorf("object %q field %q is derived without a reason", obj.ObjectKey, field.FieldPath)
			}
		}
		if obj.Outcome == OutcomeWinner {
			for _, field := range obj.Fields {
				if field.Level == EvidenceFieldLevel && field.SourceIndex != obj.SourceIndex {
					return fmt.Errorf("winning object %q inherited field %q from overridden source %d", obj.ObjectKey, field.FieldPath, field.SourceIndex)
				}
			}
		}
	}
	return nil
}

// IsPreciseFieldEvidence reports whether evidence is precise (FieldLevel) and therefore safe
// to display as field-level origin proof.
func IsPreciseFieldEvidence(field FieldEvidence) bool {
	return field.Level == EvidenceFieldLevel && field.DocumentID != ""
}

// AssertNoSensitiveData fails if the serialized graph contains any of the forbidden
// substrings (credentials, secret values, temporary checkout roots, ...).
func (g *ManifestProvenanceGraph) AssertNoSensitiveData(forbiddenSubstrings ...string) error {
	data, err := json.Marshal(g)
	if err != nil {
		return fmt.Errorf("failed to marshal provenance graph: %w", err)
	}
	serialized := string(data)
	for _, forbidden := range forbiddenSubstrings {
		if forbidden == "" {
			continue
		}
		if strings.Contains(serialized, forbidden) {
			return fmt.Errorf("provenance graph contains forbidden substring %q", forbidden)
		}
	}
	return nil
}

// --- internal helpers ---

func (r *Recorder) markUnavailableLocked(reason string) {
	r.status = StatusUnavailable
	r.unavailableReason = reason
}

func (r *Recorder) newObjectLocked(sourceIndex int, obj *unstructured.Unstructured, level EvidenceLevel) *ObjectProvenance {
	if obj == nil {
		return nil
	}
	if len(r.objects) >= r.opts.MaxNodes {
		r.omittedNodes++
		r.truncated = true
		return nil
	}
	gvk := obj.GroupVersionKind()
	rec := &ObjectProvenance{
		ObjectKey:   objectKey(obj),
		Group:       gvk.Group,
		Kind:        gvk.Kind,
		Namespace:   obj.GetNamespace(),
		Name:        obj.GetName(),
		SourceIndex: sourceIndex,
		Level:       level,
		Outcome:     OutcomeWinner,
	}
	r.objects = append(r.objects, rec)
	return rec
}

func (r *Recorder) recordDirectoryFieldsLocked(rec *ObjectProvenance, obj *unstructured.Unstructured, docID string) {
	topLevel := make([]string, 0, len(obj.Object))
	for k := range obj.Object {
		topLevel = append(topLevel, k)
	}
	sort.Strings(topLevel)
	for _, k := range topLevel {
		r.addFieldLocked(rec, FieldEvidence{
			FieldPath:   escapeFieldName(k),
			Level:       EvidenceFieldLevel,
			SourceIndex: rec.SourceIndex,
			DocumentID:  docID,
		})
		// Expand metadata one level so default-namespace and tracking transformations can be
		// attached to precise field paths.
		if k == "metadata" {
			meta, ok := obj.Object[k].(map[string]any)
			if !ok {
				continue
			}
			metaKeys := make([]string, 0, len(meta))
			for mk := range meta {
				metaKeys = append(metaKeys, mk)
			}
			sort.Strings(metaKeys)
			for _, mk := range metaKeys {
				r.addFieldLocked(rec, FieldEvidence{
					FieldPath:   "metadata." + escapeFieldName(mk),
					Level:       EvidenceFieldLevel,
					SourceIndex: rec.SourceIndex,
					DocumentID:  docID,
				})
			}
		}
	}
}

func (r *Recorder) addFieldLocked(rec *ObjectProvenance, field FieldEvidence) {
	if len(rec.Fields) >= r.opts.MaxFieldsPerObject {
		r.omittedFields++
		r.truncated = true
		return
	}
	rec.Fields = append(rec.Fields, field)
}

func (r *Recorder) upsertDerivedFieldLocked(rec *ObjectProvenance, fieldPath string, reason DerivedReason) {
	for i := range rec.Fields {
		if rec.Fields[i].FieldPath == fieldPath {
			rec.Fields[i] = FieldEvidence{
				FieldPath:     fieldPath,
				Level:         EvidenceDerived,
				SourceIndex:   rec.SourceIndex,
				DerivedReason: reason,
			}
			return
		}
	}
	r.addFieldLocked(rec, FieldEvidence{
		FieldPath:     fieldPath,
		Level:         EvidenceDerived,
		SourceIndex:   rec.SourceIndex,
		DerivedReason: reason,
	})
}

// enforceByteBudget shrinks optional graph content until the serialized graph fits
// MaxOutputBytes, recording every truncation.
func (r *Recorder) enforceByteBudgetLocked(graph *ManifestProvenanceGraph) {
	budget := r.opts.MaxOutputBytes
	if budget <= 0 {
		return
	}
	withinBudget := func() bool {
		data, err := json.Marshal(graph)
		return err == nil && len(data) <= budget
	}
	if withinBudget() {
		return
	}
	graph.Truncated = true
	r.truncated = true

	// First drop any embedded input text.
	for i := range graph.Documents {
		if graph.Documents[i].InputText != "" {
			graph.Documents[i].InputText = ""
		}
	}
	if withinBudget() {
		return
	}

	// Then drop field evidence, keeping object-level provenance intact.
	for _, obj := range graph.Objects {
		if len(obj.Fields) == 0 {
			continue
		}
		r.omittedFields += len(obj.Fields)
		obj.Fields = nil
		if withinBudget() {
			return
		}
	}

	// Then drop document path text, retaining only digests and identity information.
	for i := range graph.Documents {
		graph.Documents[i].RepoRelativePath = ""
		if withinBudget() {
			return
		}
	}

	// As a last resort, drop object nodes while retaining source identity and warnings.
	for len(graph.Objects) > 0 {
		graph.Objects = graph.Objects[:len(graph.Objects)-1]
		graph.OmittedNodes++
		if withinBudget() {
			return
		}
	}
}

func appendContribution(existing []ObjectContribution, add ObjectContribution) []ObjectContribution {
	for _, c := range existing {
		if c.SourceIndex == add.SourceIndex && c.Outcome == add.Outcome {
			return existing
		}
	}
	return append(existing, add)
}

func objectKey(obj *unstructured.Unstructured) string {
	gvk := obj.GroupVersionKind()
	return fmt.Sprintf("%s/%s/%s/%s", gvk.Group, gvk.Kind, obj.GetNamespace(), obj.GetName())
}

func objectPointer(obj *unstructured.Unstructured) uintptr {
	return reflect.ValueOf(obj).Pointer()
}

// escapeFieldName renders map keys as bracket-quoted segments when they contain characters
// that would be ambiguous in dotted paths (labels, annotations, ...).
func escapeFieldName(key string) string {
	if strings.ContainsAny(key, `.[]/"`) {
		return fmt.Sprintf("[%q]", key)
	}
	return key
}

// safeRelPath defensively strips any absolute path so temporary checkout roots can never be
// emitted by the graph.
func safeRelPath(p string) string {
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) {
		return filepath.Base(p)
	}
	return filepath.ToSlash(p)
}

// TrackingFieldPaths returns the exact field paths that resource tracking writes for the given
// tracking method. Only these paths may be marked as tracking-derived evidence; everything else
// must keep its actual origin evidence.
func TrackingFieldPaths(method appv1.TrackingMethod, appLabelKey, installationID string) []string {
	paths := make([]string, 0, 3)
	switch method {
	case appv1.TrackingMethodLabel:
		if appLabelKey != "" {
			paths = append(paths, fmt.Sprintf("metadata.labels[%q]", appLabelKey))
		}
	case appv1.TrackingMethodAnnotationAndLabel:
		if appLabelKey != "" {
			paths = append(paths, fmt.Sprintf("metadata.labels[%q]", appLabelKey))
		}
		paths = append(paths, fmt.Sprintf("metadata.annotations[%q]", common.AnnotationKeyAppInstance))
	default:
		// Empty method defaults to annotation tracking (see resourceTracking.SetAppInstance).
		paths = append(paths, fmt.Sprintf("metadata.annotations[%q]", common.AnnotationKeyAppInstance))
	}
	if installationID != "" {
		paths = append(paths, fmt.Sprintf("metadata.annotations[%q]", common.AnnotationInstallationID))
	}
	return paths
}

// --- context plumbing ---

type recorderCtxKey struct{}

// WithRecorder attaches a provenance recorder to a context. Pipeline components opt in by
// looking it up; a context without a recorder keeps the legacy behavior.
func WithRecorder(ctx context.Context, recorder *Recorder) context.Context {
	if recorder == nil {
		return ctx
	}
	return context.WithValue(ctx, recorderCtxKey{}, recorder)
}

// RecorderFromContext returns the recorder attached to the context, or nil when provenance is
// not requested.
func RecorderFromContext(ctx context.Context) *Recorder {
	if ctx == nil {
		return nil
	}
	recorder, _ := ctx.Value(recorderCtxKey{}).(*Recorder)
	return recorder
}
