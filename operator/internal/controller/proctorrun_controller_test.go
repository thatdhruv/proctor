package controller

import (
	"context"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	proctorv1 "proctor.dev/operator/api/v1alpha1"
)

func newRun() *proctorv1.ProctorRun {
	return &proctorv1.ProctorRun{
		ObjectMeta: metav1.ObjectMeta{Name: "r1", Namespace: "ns", UID: "uid-1"},
		Spec: proctorv1.ProctorRunSpec{
			EnvType: "coding", Rollouts: 1000, RolloutsPerShard: 50, Image: "proctor-runner:test", SkipEgressSelfTest: true,
			Workers: proctorv1.WorkerBounds{Min: 2, Max: 8},
			Quota:   proctorv1.RunQuota{MaxEpisodes: 5000, MaxStepsPerEpisode: 40, MaxWallSeconds: 600},
			Egress: []proctorv1.EgressRule{{
				PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "postgres"}}, Port: 5432}},
		},
	}
}

func setup(t *testing.T, objs ...client.Object) (*Reconciler, client.Client) {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := proctorv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).
		WithStatusSubresource(&proctorv1.ProctorRun{}, &batchv1.Job{}).Build()
	return &Reconciler{Client: c, Scheme: s}, c
}

func reconcile(t *testing.T, r *Reconciler) ctrl.Result {
	t.Helper()
	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: "r1"}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	return res
}

func get(t *testing.T, c client.Client, obj client.Object) {
	t.Helper()
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "ns", Name: obj.GetName()}, obj); err != nil {
		t.Fatalf("get %T %s: %v", obj, obj.GetName(), err)
	}
}

func TestNetworkPolicyDeniesEverythingExceptListedEgress(t *testing.T) {
	r, c := setup(t, newRun())
	reconcile(t, r)
	np := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "r1-egress"}}
	get(t, c, np)

	if np.Spec.PodSelector.MatchLabels[LabelRun] != "r1" {
		t.Fatalf("policy must select the run's pods, got %v", np.Spec.PodSelector)
	}
	has := map[networkingv1.PolicyType]bool{}
	for _, p := range np.Spec.PolicyTypes {
		has[p] = true
	}
	if !has[networkingv1.PolicyTypeEgress] || !has[networkingv1.PolicyTypeIngress] {
		t.Fatalf("must police both directions: %v", np.Spec.PolicyTypes)
	}
	if len(np.Spec.Ingress) != 0 {
		t.Fatalf("ingress must be empty (deny all): %v", np.Spec.Ingress)
	}
	if len(np.Spec.Egress) != 2 { // postgres + DNS
		t.Fatalf("want exactly the listed destination and DNS, got %d rules", len(np.Spec.Egress))
	}
	for _, rule := range np.Spec.Egress {
		for _, p := range rule.To {
			if p.IPBlock != nil {
				t.Fatalf("no IP blocks (internet / metadata endpoints) may ever be allowed: %v", p)
			}
		}
	}
	if np.Spec.Egress[0].Ports[0].Port.IntValue() != 5432 {
		t.Fatalf("first rule must be the datastore port: %v", np.Spec.Egress[0])
	}
	if len(np.OwnerReferences) != 1 || np.OwnerReferences[0].Kind != "ProctorRun" {
		t.Fatalf("policy must be garbage-collected with its run: %v", np.OwnerReferences)
	}
}

func TestAirGappedRunHasNoEgressRulesAtAll(t *testing.T) {
	run := newRun()
	run.Spec.Egress = nil
	run.Spec.AllowDNS = ptr.To(false)
	r, c := setup(t, run)
	reconcile(t, r)
	np := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "r1-egress"}}
	get(t, c, np)
	if len(np.Spec.Egress) != 0 || !containsEgress(np.Spec.PolicyTypes) {
		t.Fatalf("egress policy type with zero rules == deny all outbound; got %v / %v", np.Spec.PolicyTypes, np.Spec.Egress)
	}
}

func containsEgress(ts []networkingv1.PolicyType) bool {
	for _, t := range ts {
		if t == networkingv1.PolicyTypeEgress {
			return true
		}
	}
	return false
}

func TestJobShardsSpreadAndHardening(t *testing.T) {
	r, c := setup(t, newRun())
	reconcile(t, r)
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "r1"}}
	get(t, c, job)

	if *job.Spec.Completions != 20 || *job.Spec.CompletionMode != batchv1.IndexedCompletion {
		t.Fatalf("1000 rollouts / 50 per shard = 20 indexed shards, got %d", *job.Spec.Completions)
	}
	if *job.Spec.Parallelism != 8 {
		t.Fatalf("backlog 20 clamps to max 8, got %d", *job.Spec.Parallelism)
	}
	if job.Spec.ActiveDeadlineSeconds == nil || *job.Spec.ActiveDeadlineSeconds != 600 {
		t.Fatalf("wall-clock quota must become activeDeadlineSeconds")
	}
	pod := job.Spec.Template.Spec
	if *pod.AutomountServiceAccountToken {
		t.Fatalf("workers must not receive Kubernetes API credentials")
	}
	if len(pod.TopologySpreadConstraints) != 1 || pod.TopologySpreadConstraints[0].TopologyKey != "kubernetes.io/hostname" {
		t.Fatalf("workers must spread across nodes: %v", pod.TopologySpreadConstraints)
	}
	if job.Spec.Template.Labels[LabelRun] != "r1" {
		t.Fatalf("pod labels must match the network policy selector")
	}
	env := map[string]string{}
	for _, e := range pod.Containers[0].Env {
		env[e.Name] = e.Value
	}
	if env["PROCTOR_MAX_STEPS"] != "40" || env["PROCTOR_POLICY"] != "hardened" || env["PROCTOR_MAX_EPISODES"] != "5000" {
		t.Fatalf("quotas / policy must reach the worker: %v", env)
	}
}

func TestEpisodeQuotaRejectsRunBeforeAnythingStarts(t *testing.T) {
	run := newRun()
	run.Spec.Rollouts = 9000 // > maxEpisodes 5000
	r, c := setup(t, run)
	reconcile(t, r)
	got := &proctorv1.ProctorRun{ObjectMeta: metav1.ObjectMeta{Name: "r1"}}
	get(t, c, got)
	if got.Status.Phase != proctorv1.PhaseFailed || got.Status.Conditions[0].Reason != "EpisodeQuotaExceeded" {
		t.Fatalf("want Failed/EpisodeQuotaExceeded, got %+v", got.Status)
	}
	var jobs batchv1.JobList
	if err := c.List(context.Background(), &jobs); err != nil || len(jobs.Items) != 0 {
		t.Fatalf("no job may exist for a rejected run: %v %v", err, jobs.Items)
	}
}

func TestWorkersFollowTheBacklogDown(t *testing.T) {
	r, c := setup(t, newRun())
	reconcile(t, r)
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "r1"}}
	get(t, c, job)
	job.Status.Succeeded, job.Status.Active = 18, 8 // 2 shards left
	if err := c.Status().Update(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	reconcile(t, r)
	get(t, c, job)
	if *job.Spec.Parallelism != 2 {
		t.Fatalf("2 shards left and min=2 -> parallelism 2, got %d", *job.Spec.Parallelism)
	}
	job.Status.Succeeded = 19
	_ = c.Status().Update(context.Background(), job)
	reconcile(t, r)
	get(t, c, job)
	if *job.Spec.Parallelism != 2 {
		t.Fatalf("never below workers.min, got %d", *job.Spec.Parallelism)
	}
}

func TestScaleUpWhenMaxRaisedMidRun(t *testing.T) {
	r, c := setup(t, newRun())
	reconcile(t, r)
	run := &proctorv1.ProctorRun{ObjectMeta: metav1.ObjectMeta{Name: "r1"}}
	get(t, c, run)
	run.Spec.Workers.Max = 20
	if err := c.Update(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	reconcile(t, r)
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "r1"}}
	get(t, c, job)
	if *job.Spec.Parallelism != 20 {
		t.Fatalf("raising workers.max to 20 with 20 pending shards -> 20, got %d", *job.Spec.Parallelism)
	}
}

func TestCompletionAndDeadlineMapToPhases(t *testing.T) {
	for name, tc := range map[string]struct {
		cond    batchv1.JobCondition
		phase   proctorv1.Phase
		reason  string
		message string
	}{
		"complete": {batchv1.JobCondition{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}, proctorv1.PhaseSucceeded, "AllShardsDone", ""},
		"deadline": {batchv1.JobCondition{Type: batchv1.JobFailed, Status: corev1.ConditionTrue, Reason: "DeadlineExceeded"}, proctorv1.PhaseFailed, "WallClockQuotaExceeded", ""},
	} {
		t.Run(name, func(t *testing.T) {
			r, c := setup(t, newRun())
			reconcile(t, r)
			job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "r1"}}
			get(t, c, job)
			job.Status.Conditions = []batchv1.JobCondition{tc.cond}
			if err := c.Status().Update(context.Background(), job); err != nil {
				t.Fatal(err)
			}
			reconcile(t, r)
			got := &proctorv1.ProctorRun{ObjectMeta: metav1.ObjectMeta{Name: "r1"}}
			get(t, c, got)
			if got.Status.Phase != tc.phase || got.Status.Conditions[0].Reason != tc.reason {
				t.Fatalf("want %s/%s, got %s/%s", tc.phase, tc.reason, got.Status.Phase, got.Status.Conditions[0].Reason)
			}
			// terminal runs are never reconciled again
			if res := reconcile(t, r); res.RequeueAfter != 0 {
				t.Fatalf("terminal run must not requeue")
			}
		})
	}
}

func TestDesiredWorkersTable(t *testing.T) {
	cases := []struct{ shards, done, min, max, want int32 }{
		{20, 0, 2, 8, 8}, {20, 18, 2, 8, 2}, {20, 20, 1, 8, 1}, {3, 0, 1, 8, 3}, {100, 0, 4, 4, 4},
	}
	for _, c := range cases {
		if got := DesiredWorkers(c.shards, c.done, c.min, c.max); got != c.want {
			t.Errorf("DesiredWorkers(%d,%d,%d,%d)=%d want %d", c.shards, c.done, c.min, c.max, got, c.want)
		}
	}
}

func TestEgressSelfTestGatesTheJob(t *testing.T) {
	run := newRun()
	run.Spec.SkipEgressSelfTest = false
	r, c := setup(t, run)

	// 1st pass: policy + self-test pod exist, but no workers may start yet.
	if res := reconcile(t, r); res.RequeueAfter == 0 {
		t.Fatalf("must requeue while the self-test runs")
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "r1-selftest"}}
	get(t, c, pod)
	if pod.Labels[LabelRun] != "r1" || pod.Spec.Containers[0].Args[1] != "--strict" {
		t.Fatalf("self-test pod must carry the worker labels (so the policy applies) and run strict mode: %+v", pod.Spec)
	}
	var jobs batchv1.JobList
	_ = c.List(context.Background(), &jobs)
	if len(jobs.Items) != 0 {
		t.Fatalf("no worker job before the self-test passes")
	}
	got := &proctorv1.ProctorRun{ObjectMeta: metav1.ObjectMeta{Name: "r1"}}
	get(t, c, got)
	if got.Status.Phase != proctorv1.PhaseSelfTest {
		t.Fatalf("phase should be SelfTest, got %s", got.Status.Phase)
	}

	// Self-test pod succeeds -> the Job is created.
	pod.Status.Phase = corev1.PodSucceeded
	if err := c.Status().Update(context.Background(), pod); err != nil {
		t.Fatal(err)
	}
	reconcile(t, r)
	_ = c.List(context.Background(), &jobs)
	if len(jobs.Items) != 1 {
		t.Fatalf("job must exist once the policy is proven to be enforced")
	}
}

func TestFailedSelfTestFailsClosed(t *testing.T) {
	run := newRun()
	run.Spec.SkipEgressSelfTest = false
	r, c := setup(t, run)
	reconcile(t, r)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "r1-selftest"}}
	get(t, c, pod)
	pod.Status.Phase = corev1.PodFailed // the probe reached something it must not
	if err := c.Status().Update(context.Background(), pod); err != nil {
		t.Fatal(err)
	}
	reconcile(t, r)
	got := &proctorv1.ProctorRun{ObjectMeta: metav1.ObjectMeta{Name: "r1"}}
	get(t, c, got)
	if got.Status.Phase != proctorv1.PhaseFailed || got.Status.Conditions[0].Reason != "NetworkPolicyNotEnforced" {
		t.Fatalf("want Failed/NetworkPolicyNotEnforced, got %+v", got.Status)
	}
	var jobs batchv1.JobList
	_ = c.List(context.Background(), &jobs)
	if len(jobs.Items) != 0 {
		t.Fatalf("workers must never start when egress is not enforced")
	}
}
