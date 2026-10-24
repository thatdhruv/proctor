// Package controller reconciles ProctorRun objects: it fans a batch of rollouts out over indexed Job shards,
// spreads workers across nodes, scales parallelism with the backlog, enforces per-run quotas, and installs a
// deny-all-egress NetworkPolicy before any worker can start.
package controller

import (
	"context"
	"fmt"
	"strconv"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	proctorv1 "proctor.dev/operator/api/v1alpha1"
)

const (
	LabelRun   = "proctor.dev/run"
	LabelRole  = "proctor.dev/role"
	RoleWorker = "sandbox"

	DefaultRolloutsPerShard = 50
	requeueWhileRunning     = 10 * time.Second
)

// Reconciler implements the ProctorRun control loop.
type Reconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
	Now      func() metav1.Time
}

// +kubebuilder:rbac:groups=proctor.dev,resources=proctorruns,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=proctor.dev,resources=proctorruns/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=proctor.dev,resources=proctorruns/finalizers,verbs=update
// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;create;delete
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	lg := log.FromContext(ctx)
	var run proctorv1.ProctorRun
	if err := r.Get(ctx, req.NamespacedName, &run); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !run.DeletionTimestamp.IsZero() || run.Status.Phase == proctorv1.PhaseSucceeded || run.Status.Phase == proctorv1.PhaseFailed {
		return ctrl.Result{}, nil
	}

	if err := Validate(&run); err != nil {
		lg.Info("rejecting run", "reason", err.Reason, "msg", err.Error())
		return ctrl.Result{}, r.fail(ctx, &run, err.Reason, err.Error())
	}
	shards := Shards(&run)

	// 1. The egress policy goes in first: a worker must never be schedulable without it.
	np := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: run.Name + "-egress", Namespace: run.Namespace}}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, np, func() error {
		np.Labels = map[string]string{LabelRun: run.Name}
		np.Spec = BuildNetworkPolicySpec(&run)
		return controllerutil.SetControllerReference(&run, np, r.Scheme)
	}); err != nil {
		return ctrl.Result{}, err
	}

	// 1b. Prove the policy is enforced before any agent code can run: a pod carrying the worker labels must not
	// be able to reach the internet or the API server. Fails closed on CNIs that ignore NetworkPolicy.
	if !run.Spec.SkipEgressSelfTest {
		ok, done, err := r.egressSelfTest(ctx, &run)
		if err != nil {
			return ctrl.Result{}, err
		}
		if !done {
			run.Status.Phase, run.Status.Message = proctorv1.PhaseSelfTest, "verifying that the egress policy is enforced"
			run.Status.ObservedGeneration = run.Generation
			if err := r.Status().Update(ctx, &run); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
		}
		if !ok {
			return ctrl.Result{}, r.fail(ctx, &run, "NetworkPolicyNotEnforced",
				"egress self-test failed: a pod under the run's NetworkPolicy reached a forbidden destination; the cluster CNI "+
					"does not enforce NetworkPolicy. Refusing to start workers (see logs of pod "+run.Name+"-selftest).")
		}
	}

	// 2. The Job: indexed shards, spread across nodes. Everything but parallelism is immutable afterwards.
	var job batchv1.Job
	err := r.Get(ctx, client.ObjectKey{Namespace: run.Namespace, Name: run.Name}, &job)
	switch {
	case apierrors.IsNotFound(err):
		job = *BuildJob(&run, shards)
		if err := controllerutil.SetControllerReference(&run, &job, r.Scheme); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.Create(ctx, &job); err != nil {
			return ctrl.Result{}, err
		}
		r.event(&run, corev1.EventTypeNormal, "Started", fmt.Sprintf("created job with %d shards, parallelism %d", shards, *job.Spec.Parallelism))
	case err != nil:
		return ctrl.Result{}, err
	default:
		// 3. Autoscale: workers follow the backlog, clamped to the run's bounds.
		want := DesiredWorkers(shards, job.Status.Succeeded, run.Spec.Workers.Min, run.Spec.Workers.Max)
		if !jobFinished(&job) && (job.Spec.Parallelism == nil || *job.Spec.Parallelism != want) {
			patch := client.MergeFrom(job.DeepCopy())
			job.Spec.Parallelism = ptr.To(want)
			if err := r.Patch(ctx, &job, patch); err != nil {
				return ctrl.Result{}, err
			}
			r.event(&run, corev1.EventTypeNormal, "Scaled", fmt.Sprintf("workers -> %d (backlog %d shards)", want, shards-job.Status.Succeeded))
		}
	}

	// 4. Mirror Job state into ProctorRun status.
	return r.syncStatus(ctx, &run, &job, shards)
}

// egressSelfTest runs `proctor netprobe --strict` in a pod selected by the run's NetworkPolicy.
// It returns (passed, finished, error).
func (r *Reconciler) egressSelfTest(ctx context.Context, run *proctorv1.ProctorRun) (bool, bool, error) {
	key := client.ObjectKey{Namespace: run.Namespace, Name: run.Name + "-selftest"}
	var pod corev1.Pod
	err := r.Get(ctx, key, &pod)
	if apierrors.IsNotFound(err) {
		p := BuildSelfTestPod(run)
		if err := controllerutil.SetControllerReference(run, p, r.Scheme); err != nil {
			return false, false, err
		}
		return false, false, r.Create(ctx, p)
	}
	if err != nil {
		return false, false, err
	}
	switch pod.Status.Phase {
	case corev1.PodSucceeded:
		return true, true, nil
	case corev1.PodFailed:
		return false, true, nil
	}
	return false, false, nil
}

// BuildSelfTestPod is labelled like a worker so the run's NetworkPolicy applies to it.
func BuildSelfTestPod(run *proctorv1.ProctorRun) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: run.Name + "-selftest", Namespace: run.Namespace, Labels: workerLabels(run)},
		Spec: corev1.PodSpec{
			RestartPolicy:                corev1.RestartPolicyNever,
			AutomountServiceAccountToken: ptr.To(false),
			EnableServiceLinks:           ptr.To(false),
			NodeSelector:                 run.Spec.NodeSelector,
			Tolerations:                  run.Spec.Tolerations,
			Containers: []corev1.Container{{
				Name:    "selftest",
				Image:   run.Spec.Image,
				Command: []string{"proctor"},
				Args:    []string{"netprobe", "--strict", "--timeout", "3"},
				SecurityContext: &corev1.SecurityContext{
					AllowPrivilegeEscalation: ptr.To(false),
					Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
				},
			}},
		},
	}
}

func (r *Reconciler) syncStatus(ctx context.Context, run *proctorv1.ProctorRun, job *batchv1.Job, shards int32) (ctrl.Result, error) {
	st := &run.Status
	st.ObservedGeneration = run.Generation
	st.Shards, st.ShardsSucceeded, st.ShardsFailed = shards, job.Status.Succeeded, job.Status.Failed
	st.ActiveWorkers = job.Status.Active
	st.DesiredWorkers = DesiredWorkers(shards, job.Status.Succeeded, run.Spec.Workers.Min, run.Spec.Workers.Max)
	if st.StartTime == nil {
		now := r.now()
		st.StartTime = &now
	}
	st.Phase = proctorv1.PhaseRunning
	for _, c := range job.Status.Conditions {
		if c.Status != corev1.ConditionTrue {
			continue
		}
		now := r.now()
		switch c.Type {
		case batchv1.JobComplete:
			st.Phase, st.CompletionTime, st.Message = proctorv1.PhaseSucceeded, &now, "all shards completed"
			setCond(run, "Complete", metav1.ConditionTrue, "AllShardsDone", st.Message)
		case batchv1.JobFailed:
			reason, msg := "WorkersFailed", "job failed: "+c.Message
			if c.Reason == "DeadlineExceeded" {
				reason, msg = "WallClockQuotaExceeded", fmt.Sprintf("exceeded quota.maxWallSeconds=%d", run.Spec.Quota.MaxWallSeconds)
			}
			st.Phase, st.CompletionTime, st.Message = proctorv1.PhaseFailed, &now, msg
			setCond(run, "Complete", metav1.ConditionFalse, reason, msg)
		}
	}
	if err := r.Status().Update(ctx, run); err != nil {
		return ctrl.Result{}, err
	}
	if st.Phase == proctorv1.PhaseRunning {
		return ctrl.Result{RequeueAfter: requeueWhileRunning}, nil
	}
	return ctrl.Result{}, nil
}

func (r *Reconciler) fail(ctx context.Context, run *proctorv1.ProctorRun, reason, msg string) error {
	now := r.now()
	run.Status.Phase, run.Status.Message, run.Status.CompletionTime = proctorv1.PhaseFailed, msg, &now
	run.Status.ObservedGeneration = run.Generation
	setCond(run, "Complete", metav1.ConditionFalse, reason, msg)
	r.event(run, corev1.EventTypeWarning, reason, msg)
	return r.Status().Update(ctx, run)
}

func (r *Reconciler) now() metav1.Time {
	if r.Now != nil {
		return r.Now()
	}
	return metav1.Now()
}

func (r *Reconciler) event(run *proctorv1.ProctorRun, typ, reason, msg string) {
	if r.Recorder != nil {
		r.Recorder.Event(run, typ, reason, msg)
	}
}

func setCond(run *proctorv1.ProctorRun, t string, s metav1.ConditionStatus, reason, msg string) {
	meta.SetStatusCondition(&run.Status.Conditions, metav1.Condition{
		Type: t, Status: s, Reason: reason, Message: msg, ObservedGeneration: run.Generation,
	})
}

func jobFinished(j *batchv1.Job) bool {
	for _, c := range j.Status.Conditions {
		if (c.Type == batchv1.JobComplete || c.Type == batchv1.JobFailed) && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

// SetupWithManager wires the controller; owned objects trigger reconciles of their parent run.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.Recorder = mgr.GetEventRecorderFor("proctor-operator")
	return ctrl.NewControllerManagedBy(mgr).
		For(&proctorv1.ProctorRun{}).
		Owns(&batchv1.Job{}).
		Owns(&networkingv1.NetworkPolicy{}).
		Owns(&corev1.Pod{}).
		Complete(r)
}

// ------------------------------------------------------------------ pure helpers (unit-tested)

// ValidationError carries a machine-readable reason for status conditions.
type ValidationError struct{ Reason, Msg string }

func (e *ValidationError) Error() string { return e.Msg }

// Validate applies the per-run quotas that can be decided before anything starts.
func Validate(run *proctorv1.ProctorRun) *ValidationError {
	s := &run.Spec
	switch {
	case s.Workers.Min < 1 || s.Workers.Max < s.Workers.Min:
		return &ValidationError{"InvalidWorkerBounds", fmt.Sprintf("workers.min=%d workers.max=%d must satisfy 1 <= min <= max", s.Workers.Min, s.Workers.Max)}
	case s.Quota.MaxEpisodes > 0 && s.Rollouts > s.Quota.MaxEpisodes:
		return &ValidationError{"EpisodeQuotaExceeded", fmt.Sprintf("rollouts=%d exceeds quota.maxEpisodes=%d", s.Rollouts, s.Quota.MaxEpisodes)}
	case s.Image == "":
		return &ValidationError{"MissingImage", "spec.image is required"}
	}
	return nil
}

// Shards is the number of indexed Job completions needed to cover all rollouts.
func Shards(run *proctorv1.ProctorRun) int32 {
	per := run.Spec.RolloutsPerShard
	if per <= 0 {
		per = DefaultRolloutsPerShard
	}
	return (run.Spec.Rollouts + per - 1) / per
}

// DesiredWorkers sizes the pool to the remaining backlog (one shard per worker), clamped to [min, max].
func DesiredWorkers(shards, succeeded, min, max int32) int32 {
	pending := shards - succeeded
	if pending < min {
		pending = min
	}
	if pending > max {
		pending = max
	}
	return pending
}

func workerLabels(run *proctorv1.ProctorRun) map[string]string {
	return map[string]string{LabelRun: run.Name, LabelRole: RoleWorker}
}

// BuildNetworkPolicySpec: no ingress at all; egress only to the listed in-cluster destinations (+ DNS unless disabled).
func BuildNetworkPolicySpec(run *proctorv1.ProctorRun) networkingv1.NetworkPolicySpec {
	var egress []networkingv1.NetworkPolicyEgressRule
	for _, e := range run.Spec.Egress {
		peer := networkingv1.NetworkPolicyPeer{PodSelector: e.PodSelector, NamespaceSelector: e.NamespaceSelector}
		egress = append(egress, networkingv1.NetworkPolicyEgressRule{
			To:    []networkingv1.NetworkPolicyPeer{peer},
			Ports: []networkingv1.NetworkPolicyPort{{Protocol: ptr.To(corev1.ProtocolTCP), Port: ptr.To(intstr.FromInt32(e.Port))}},
		})
	}
	if run.Spec.AllowDNS == nil || *run.Spec.AllowDNS {
		egress = append(egress, networkingv1.NetworkPolicyEgressRule{
			To: []networkingv1.NetworkPolicyPeer{{
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kube-system"}},
				PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": "kube-dns"}},
			}},
			Ports: []networkingv1.NetworkPolicyPort{
				{Protocol: ptr.To(corev1.ProtocolUDP), Port: ptr.To(intstr.FromInt32(53))},
				{Protocol: ptr.To(corev1.ProtocolTCP), Port: ptr.To(intstr.FromInt32(53))},
			},
		})
	}
	return networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{LabelRun: run.Name}},
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
		Egress:      egress, // empty slice + PolicyTypeEgress == deny all outbound
	}
}

// BuildJob renders the worker Job for a run.
func BuildJob(run *proctorv1.ProctorRun, shards int32) *batchv1.Job {
	per := run.Spec.RolloutsPerShard
	if per <= 0 {
		per = DefaultRolloutsPerShard
	}
	labels := workerLabels(run)
	privileged := run.Spec.Privileged == nil || *run.Spec.Privileged
	sc := &corev1.SecurityContext{
		AllowPrivilegeEscalation: ptr.To(privileged),
		Privileged:               ptr.To(privileged),
		// The execution core builds its own namespaces; the default runtime seccomp profile forbids that.
		SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined},
	}
	if !privileged {
		sc.Capabilities = &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}
	}
	env := []corev1.EnvVar{
		{Name: "PROCTOR_RUN", Value: run.Name},
		{Name: "PROCTOR_ENV_TYPE", Value: run.Spec.EnvType},
		{Name: "PROCTOR_POLICY", Value: defaulted(run.Spec.Policy, "hardened")},
		{Name: "PROCTOR_ROLLOUTS_PER_SHARD", Value: strconv.Itoa(int(per))},
		{Name: "PROCTOR_MAX_STEPS", Value: strconv.Itoa(int(run.Spec.Quota.MaxStepsPerEpisode))},
		{Name: "PROCTOR_MAX_EPISODES", Value: strconv.Itoa(int(run.Spec.Quota.MaxEpisodes))},
	}
	env = append(env, run.Spec.Env...)

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: run.Name, Namespace: run.Namespace, Labels: map[string]string{LabelRun: run.Name}},
		Spec: batchv1.JobSpec{
			Completions:             ptr.To(shards),
			Parallelism:             ptr.To(DesiredWorkers(shards, 0, run.Spec.Workers.Min, run.Spec.Workers.Max)),
			CompletionMode:          ptr.To(batchv1.IndexedCompletion),
			BackoffLimit:            ptr.To(int32(6)),
			TTLSecondsAfterFinished: ptr.To(int32(3600)),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyNever,
					// Workers get no Kubernetes API credentials and no service env injection.
					AutomountServiceAccountToken: ptr.To(false),
					EnableServiceLinks:           ptr.To(false),
					RuntimeClassName:             run.Spec.RuntimeClassName,
					NodeSelector:                 run.Spec.NodeSelector,
					Tolerations:                  run.Spec.Tolerations,
					TopologySpreadConstraints: []corev1.TopologySpreadConstraint{{
						MaxSkew:           1,
						TopologyKey:       "kubernetes.io/hostname",
						WhenUnsatisfiable: corev1.ScheduleAnyway,
						LabelSelector:     &metav1.LabelSelector{MatchLabels: map[string]string{LabelRun: run.Name}},
					}},
					Containers: []corev1.Container{{
						Name:            "worker",
						Image:           run.Spec.Image,
						Command:         []string{"proctor"},
						Args:            []string{"rollouts", "--shard-from-env", "--workers", "4"},
						Env:             env,
						Resources:       run.Spec.Resources,
						SecurityContext: sc,
					}},
				},
			},
		},
	}
	if s := run.Spec.Quota.MaxWallSeconds; s > 0 {
		job.Spec.ActiveDeadlineSeconds = ptr.To(s)
	}
	return job
}

func defaulted(v, d string) string {
	if v == "" {
		return d
	}
	return v
}
