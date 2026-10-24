// Package v1alpha1 contains the ProctorRun API: one batch of sandboxed RL rollouts.
//
// +kubebuilder:object:generate=true
// +groupName=proctor.dev
package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	GroupVersion  = schema.GroupVersion{Group: "proctor.dev", Version: "v1alpha1"}
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}
	AddToScheme   = SchemeBuilder.AddToScheme
)

func init() { SchemeBuilder.Register(&ProctorRun{}, &ProctorRunList{}) }

// WorkerBounds limits the autoscaler.
type WorkerBounds struct {
	// +kubebuilder:validation:Minimum=1
	Min int32 `json:"min"`
	// +kubebuilder:validation:Minimum=1
	Max int32 `json:"max"`
}

// RunQuota is enforced per run.
type RunQuota struct {
	// MaxEpisodes rejects runs asking for more rollouts than this (0 = unlimited).
	// +kubebuilder:validation:Minimum=0
	MaxEpisodes int32 `json:"maxEpisodes,omitempty"`
	// MaxStepsPerEpisode is passed to workers, which truncate episodes at this many steps.
	// +kubebuilder:validation:Minimum=0
	MaxStepsPerEpisode int32 `json:"maxStepsPerEpisode,omitempty"`
	// MaxWallSeconds becomes the Job's activeDeadlineSeconds: a hard wall-clock cap (0 = none).
	// +kubebuilder:validation:Minimum=0
	MaxWallSeconds int64 `json:"maxWallSeconds,omitempty"`
}

// EgressRule is the only traffic a worker pod may initiate: an in-cluster destination and port.
type EgressRule struct {
	// PodSelector selects destination pods (same namespace unless NamespaceSelector is set).
	PodSelector *metav1.LabelSelector `json:"podSelector"`
	// NamespaceSelector optionally selects the destination namespace.
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`
}

// ProctorRunSpec describes the desired batch of rollouts.
type ProctorRunSpec struct {
	// +kubebuilder:validation:Enum=coding;sql;fsops;mixed
	EnvType string `json:"envType"`
	// Rollouts is the number of episodes to run in total.
	// +kubebuilder:validation:Minimum=1
	Rollouts int32 `json:"rollouts"`
	// RolloutsPerShard is the episodes one worker pod executes per Job index (default 50).
	// +kubebuilder:validation:Minimum=1
	// +optional
	RolloutsPerShard int32 `json:"rolloutsPerShard,omitempty"`
	Workers          WorkerBounds `json:"workers"`
	Quota            RunQuota     `json:"quota,omitempty"`
	// Image of the worker (proctor runner).
	Image string `json:"image"`
	// +kubebuilder:validation:Enum=naive;hardened
	// +kubebuilder:default=hardened
	Policy string `json:"policy,omitempty"`
	// Egress lists the ONLY destinations workers may reach (datastore, telemetry). Everything else is dropped.
	Egress []EgressRule `json:"egress,omitempty"`
	// AllowDNS permits UDP/TCP 53 to cluster DNS. Disable for a fully air-gapped run.
	// +kubebuilder:default=true
	AllowDNS *bool `json:"allowDNS,omitempty"`
	// SkipEgressSelfTest disables the pre-flight check that proves the NetworkPolicy is actually enforced by
	// the cluster CNI (a NetworkPolicy object alone does nothing on a CNI without policy support).
	SkipEgressSelfTest bool `json:"skipEgressSelfTest,omitempty"`
	// Env is passed through to workers (e.g. DSNs from secrets).
	Env []corev1.EnvVar `json:"env,omitempty"`
	// Resources for each worker pod.
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
	// Privileged gives the worker the rights the execution core needs to build namespaces. Use dedicated,
	// tainted nodes (or a sandboxed RuntimeClass) when this is set.
	// +kubebuilder:default=true
	Privileged *bool `json:"privileged,omitempty"`
	// RuntimeClassName optionally runs workers under a sandboxed runtime (gVisor, Kata, ...).
	RuntimeClassName *string `json:"runtimeClassName,omitempty"`
	// NodeSelector / Tolerations place workers on dedicated sandbox nodes.
	NodeSelector map[string]string   `json:"nodeSelector,omitempty"`
	Tolerations  []corev1.Toleration `json:"tolerations,omitempty"`
}

// Phase of a run.
type Phase string

const (
	PhasePending   Phase = "Pending"
	PhaseSelfTest  Phase = "SelfTest"
	PhaseRunning   Phase = "Running"
	PhaseSucceeded Phase = "Succeeded"
	PhaseFailed    Phase = "Failed"
)

// ProctorRunStatus is observed state.
type ProctorRunStatus struct {
	Phase              Phase              `json:"phase,omitempty"`
	Message            string             `json:"message,omitempty"`
	Shards             int32              `json:"shards,omitempty"`
	ShardsSucceeded    int32              `json:"shardsSucceeded,omitempty"`
	ShardsFailed       int32              `json:"shardsFailed,omitempty"`
	ActiveWorkers      int32              `json:"activeWorkers,omitempty"`
	DesiredWorkers     int32              `json:"desiredWorkers,omitempty"`
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	StartTime          *metav1.Time       `json:"startTime,omitempty"`
	CompletionTime     *metav1.Time       `json:"completionTime,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
}

// ProctorRun is a batch of sandboxed rollouts with quotas and a deny-all-egress network policy.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Workers",type=integer,JSONPath=`.status.activeWorkers`
// +kubebuilder:printcolumn:name="Shards",type=string,JSONPath=`.status.shardsSucceeded`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type ProctorRun struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ProctorRunSpec   `json:"spec,omitempty"`
	Status            ProctorRunStatus `json:"status,omitempty"`
}

// ProctorRunList is a list of ProctorRun.
//
// +kubebuilder:object:root=true
type ProctorRunList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ProctorRun `json:"items"`
}

var _ runtime.Object = &ProctorRun{}
