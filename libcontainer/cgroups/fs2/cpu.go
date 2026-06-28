package fs2

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/cgroups/fscommon"
	"github.com/opencontainers/runc/libcontainer/configs"
)

func isCpuSet(r *configs.Resources) bool {
	return r.CpuWeight != 0 || r.CpuQuota != 0 || r.CpuPeriod != 0 ||
		r.CpuRtRuntime != 0 || r.CpuRtPeriod != 0
}

func setCpu(dirPath string, r *configs.Resources) error {
	if !isCpuSet(r) {
		return nil
	}

	// NOTE: .CpuShares is not used here. Conversion is the caller's responsibility.
	if r.CpuWeight != 0 {
		if err := cgroups.WriteFile(dirPath, "cpu.weight", strconv.FormatUint(r.CpuWeight, 10)); err != nil {
			return err
		}
	}

	if r.CpuQuota != 0 || r.CpuPeriod != 0 {
		str := "max"
		if r.CpuQuota > 0 {
			str = strconv.FormatInt(r.CpuQuota, 10)
		}
		period := r.CpuPeriod
		if period == 0 {
			// This default value is documented in
			// https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html
			period = 100000
		}
		str += " " + strconv.FormatUint(period, 10)
		if err := cgroups.WriteFile(dirPath, "cpu.max", str); err != nil {
			return err
		}
	}

	if err := setRtSched(dirPath, r); err != nil {
		return err
	}

	return nil
}

// setRtSched writes the HCBS real-time bandwidth for this cgroup on a unified
// (cgroup v2) hierarchy. The custom RT_GROUP_SCHED kernel exposes
// cpu.rt_period_us (scalar) and cpu.rt_runtime_us (a scalar OR a per-core list
// of "<runtime> <cpu> <runtime> <cpu> ..." pairs, with the runtime first and
// unlisted cores left at zero runtime) under cgroup v2. Upstream runc only
// handles these files on cgroup v1, so without this the realtimeRuntime /
// realtimePeriod from the OCI spec are silently dropped on a v2 node.
//
// runc owns the full RT cgroup chain: before writing this container's leaf
// scope it seeds the ancestor slices (kubepods.slice ->
// kubepods-besteffort.slice -> the pod slice) top-down, because the kernel
// requires every parent to already hold an RT budget >= the child's on each
// core. The parents are seeded with the SAME per-core list as the leaf (only
// this pod's cpuset cores), not a scalar: a scalar would reserve budget on
// every core and a second RT pod pinned to other cores would then exceed the
// parent's bandwidth and fail to seed. A per-core reservation lets pods on
// disjoint cores coexist; the leaf gets the exact per-core list too.
//
// Before writing the leaf, runc also reclaims any RT reservation that a sibling
// scope under the same pod slice is holding without actually running real-time
// tasks (the pod's pause/sandbox scope). See reclaimSandboxRtBudget for why
// this is required to avoid an intermittent EINVAL crash-loop on the second RT
// pod.
func setRtSched(dirPath string, r *configs.Resources) error {
	if r.CpuRtPeriod == 0 && r.CpuRtRuntime == 0 {
		return nil
	}

	period := ""
	if r.CpuRtPeriod != 0 {
		period = strconv.FormatUint(r.CpuRtPeriod, 10)
	}

	// Build the leaf's per-core runtime list "<runtime> <cpu> <runtime> <cpu> ...".
	runtime := ""
	if r.CpuRtRuntime != 0 {
		rt := strconv.FormatInt(r.CpuRtRuntime, 10)
		var b strings.Builder
		for _, cpu := range parseCpuset(r.CpusetCpus) {
			if b.Len() > 0 {
				b.WriteByte(' ')
			}
			b.WriteString(rt)
			b.WriteByte(' ')
			b.WriteString(strconv.Itoa(cpu))
		}
		if b.Len() == 0 {
			// No cpuset was provided: fall back to a scalar runtime.
			runtime = rt
		} else {
			runtime = b.String()
		}
	}

	// Seed only the ancestor slices that still have no RT budget, top-down, so
	// the leaf write below is allowed. The kubepods.slice /
	// kubepods-besteffort.slice already carry the node-wide RT budget (e.g.
	// 950000/1000000) and must NOT be overwritten; only the per-pod slice is
	// created at 0/0 and needs a reservation. The pod slice is seeded with the
	// SAME per-core list as the leaf (its own cpuset cores only) rather than a
	// scalar: a scalar reserves budget on every core, so a second RT pod pinned
	// to other cores would exceed the parent's bandwidth and fail to seed. A
	// per-core reservation lets pods on disjoint cores coexist. Parent writes
	// are best-effort so a pre-seeded or capped parent never fails this pod.
	if r.CpuRtRuntime != 0 && r.CpuRtPeriod != 0 {
		pod := filepath.Dir(dirPath)
		besteffort := filepath.Dir(pod)
		kubepods := filepath.Dir(besteffort)
		for _, parent := range []string{kubepods, besteffort, pod} {
			if rtRuntimeIsZero(parent) {
				_ = writeRtPair(parent, runtime, period)
			}
		}

		// Reclaim any RT reservation held by a sibling scope (the pod's
		// pause/sandbox) that is not running real-time tasks, so this
		// container's leaf write below stays within the pod-slice budget.
		reclaimSandboxRtBudget(dirPath)
	}

	// Leaf: write the exact per-core reservation for this container.
	return writeRtPair(dirPath, runtime, period)
}

// reclaimSandboxRtBudget zeros cpu.rt_runtime_us on any sibling scope of
// dirPath that holds an RT reservation but is not actually running real-time
// tasks.
//
// On a cgroup v2 H-CBS hierarchy the kernel enforces, per CPU,
// Sum(children rt_runtime) <= parent rt_runtime. containerd creates a pod's
// pause (sandbox) scope as a sibling of the workload container scope under the
// same per-pod slice. Intermittently the sandbox scope ends up holding the
// pod's entire RT reservation even though the OCI sandbox spec carries no
// realtimeRuntime and the pause process never runs as a real-time task. When
// that happens, the workload container's leaf write would push the per-CPU sum
// over the pod-slice budget and fail with EINVAL, crash-looping the pod
// (typically the second RT pod admitted to a node) until the stale cgroup
// state is cleared by deleting and recreating the pod.
//
// An RT reservation owned by a cgroup whose tasks are all SCHED_NORMAL is
// unused, so it is safe to reclaim before seeding this container. Sibling
// scopes that actually run real-time tasks (e.g. another RT workload container
// in a multi-container pod) are detected via their scheduling policy and left
// untouched. The reclaim is best-effort: any read/write error is ignored so a
// transient failure never blocks container creation.
func reclaimSandboxRtBudget(dirPath string) {
	pod := filepath.Dir(dirPath)
	entries, err := os.ReadDir(pod)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		sibling := filepath.Join(pod, e.Name())
		if sibling == dirPath {
			continue
		}
		if rtRuntimeIsZero(sibling) {
			continue // no RT budget to reclaim
		}
		if cgroupHasRtTask(sibling) {
			continue // genuine RT workload sibling: leave it alone
		}
		// Unused RT reservation held by a non-RT sibling (the sandbox):
		// reclaim it so this container's leaf has bandwidth.
		_ = cgroups.WriteFile(sibling, "cpu.rt_runtime_us", "0")
	}
}

// cgroupHasRtTask reports whether any task in dir's cgroup.procs is scheduled
// with a real-time policy (SCHED_FIFO, SCHED_RR or SCHED_DEADLINE). A cgroup
// with no tasks, or only SCHED_NORMAL/SCHED_BATCH/SCHED_IDLE tasks, is treated
// as not running real-time work.
func cgroupHasRtTask(dir string) bool {
	data, err := cgroups.ReadFile(dir, "cgroup.procs")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(data, "\n") {
		pid := strings.TrimSpace(line)
		if pid == "" {
			continue
		}
		if pidIsRealtime(pid) {
			return true
		}
	}
	return false
}

// pidIsRealtime reports whether the process pid is scheduled with a real-time
// policy. It reads field 41 (policy) of /proc/<pid>/stat. The comm field
// (field 2) is enclosed in parentheses and may itself contain spaces or
// parentheses, so parsing resumes after the final ')': the first field after
// it is field 3 (state), making policy index 41-3 = 38.
func pidIsRealtime(pid string) bool {
	data, err := os.ReadFile("/proc/" + pid + "/stat")
	if err != nil {
		return false
	}
	s := string(data)
	i := strings.LastIndexByte(s, ')')
	if i < 0 || i+1 >= len(s) {
		return false
	}
	fields := strings.Fields(s[i+1:])
	const policyIdx = 38 // field 41 minus the 3 leading fields consumed above
	if len(fields) <= policyIdx {
		return false
	}
	policy, err := strconv.Atoi(fields[policyIdx])
	if err != nil {
		return false
	}
	switch policy {
	case 1, 2, 6: // SCHED_FIFO, SCHED_RR, SCHED_DEADLINE
		return true
	default: // SCHED_NORMAL(0), SCHED_BATCH(3), SCHED_IDLE(5)
		return false
	}
}

// rtRuntimeIsZero reports whether dir's cpu.rt_runtime_us currently reads "0",
// i.e. the slice holds no RT budget yet and is safe to seed. If the file is
// missing or unreadable it returns false so an already-provisioned ancestor
// (e.g. kubepods.slice) is left untouched.
func rtRuntimeIsZero(dir string) bool {
	data, err := cgroups.ReadFile(dir, "cpu.rt_runtime_us")
	if err != nil {
		return false
	}
	return strings.TrimSpace(data) == "0"
}

// writeRtPair writes cpu.rt_period_us and cpu.rt_runtime_us to dir. Order
// matters: a fresh cgroup defaults to period=0, and writing a non-zero
// cpu.rt_runtime_us while the period is 0 fails with EINVAL (runtime/period is
// undefined). So the period is always written first, then the runtime.
func writeRtPair(dir, runtime, period string) error {
	if runtime == "" && period == "" {
		return nil
	}
	if period != "" {
		if err := cgroups.WriteFile(dir, "cpu.rt_period_us", period); err != nil {
			return err
		}
	}
	if runtime != "" {
		if err := cgroups.WriteFile(dir, "cpu.rt_runtime_us", runtime); err != nil {
			return err
		}
	}
	return nil
}

// parseCpuset expands a cpuset string such as "0,2-3" into []int{0,2,3}.
func parseCpuset(s string) []int {
	var cpus []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if i := strings.IndexByte(part, '-'); i >= 0 {
			lo, err1 := strconv.Atoi(part[:i])
			hi, err2 := strconv.Atoi(part[i+1:])
			if err1 != nil || err2 != nil {
				continue
			}
			for c := lo; c <= hi; c++ {
				cpus = append(cpus, c)
			}
		} else {
			c, err := strconv.Atoi(part)
			if err != nil {
				continue
			}
			cpus = append(cpus, c)
		}
	}
	return cpus
}

func statCpu(dirPath string, stats *cgroups.Stats) error {
	const file = "cpu.stat"
	f, err := cgroups.OpenFile(dirPath, file, os.O_RDONLY)
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		t, v, err := fscommon.ParseKeyValue(sc.Text())
		if err != nil {
			return &parseError{Path: dirPath, File: file, Err: err}
		}
		switch t {
		case "usage_usec":
			stats.CpuStats.CpuUsage.TotalUsage = v * 1000

		case "user_usec":
			stats.CpuStats.CpuUsage.UsageInUsermode = v * 1000

		case "system_usec":
			stats.CpuStats.CpuUsage.UsageInKernelmode = v * 1000

		case "nr_periods":
			stats.CpuStats.ThrottlingData.Periods = v

		case "nr_throttled":
			stats.CpuStats.ThrottlingData.ThrottledPeriods = v

		case "throttled_usec":
			stats.CpuStats.ThrottlingData.ThrottledTime = v * 1000
		}
	}
	if err := sc.Err(); err != nil {
		return &parseError{Path: dirPath, File: file, Err: err}
	}
	return nil
}
