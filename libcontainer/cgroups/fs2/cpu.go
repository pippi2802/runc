package fs2

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
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
// runc owns the full RT cgroup chain. Before writing this container's leaf
// scope it (1) seeds the node-wide ancestor slices (kubepods.slice ->
// kubepods-besteffort.slice) if they hold no RT budget yet, (2) reclaims any RT
// budget spuriously held by the pod's pause/sandbox scope, and (3) raises the
// per-pod slice to the SUM of every workload container's reservation. The
// kernel enforces, per CPU, Sum(children rt_runtime) <= parent rt_runtime, so
// every parent must already hold at least the children's combined budget. A
// per-core list (not a scalar) is used throughout so pods/containers pinned to
// disjoint cores never steal each other's bandwidth, and so that all containers
// of one pod fit under the pod slice simultaneously.
func setRtSched(dirPath string, r *configs.Resources) error {
	if r.CpuRtPeriod == 0 && r.CpuRtRuntime == 0 {
		return nil
	}

	period := ""
	if r.CpuRtPeriod != 0 {
		period = strconv.FormatUint(r.CpuRtPeriod, 10)
	}

	// Build the leaf's per-core runtime list "<runtime> <cpu> <runtime> <cpu>
	// ..." and a cpu->runtime map used to size the pod slice.
	runtime := ""
	leafRt := map[int]int64{}
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
			leafRt[cpu] = r.CpuRtRuntime
		}
		if b.Len() == 0 {
			// No cpuset was provided: fall back to a scalar runtime.
			runtime = rt
		} else {
			runtime = b.String()
		}
	}

	if r.CpuRtRuntime != 0 && r.CpuRtPeriod != 0 {
		pod := filepath.Dir(dirPath)
		besteffort := filepath.Dir(pod)
		kubepods := filepath.Dir(besteffort)

		// Seed only the node-wide ancestor slices that still have no RT budget.
		// kubepods.slice / kubepods-besteffort.slice normally already carry the
		// node RT budget (e.g. 950000/1000000) and must not be overwritten; the
		// per-pod slice is sized separately below.
		for _, parent := range []string{kubepods, besteffort} {
			if rtRuntimeIsZero(parent) {
				_ = writeRtPair(parent, runtime, period)
			}
		}

		// Reclaim RT budget spuriously held by the pod's pause/sandbox scope so
		// it does not count against the pod-slice budget.
		reclaimSandboxRtBudget(dirPath)

		// Size the per-pod slice to the SUM of all its workload containers'
		// reservations (existing sibling scopes + this leaf), per core, so that
		// every container in the pod fits under the parent budget at once. This
		// is raised before the leaf is written, so Sum(children) <= parent holds
		// throughout. Best-effort: a capped/pre-seeded parent never blocks here.
		if list := rtPairsList(podSliceBudget(pod, dirPath, leafRt)); list != "" {
			_ = writeRtPair(pod, list, period)
		}
	}

	// Leaf: write the exact per-core reservation for this container.
	return writeRtPair(dirPath, runtime, period)
}

// reclaimSandboxRtBudget zeros cpu.rt_runtime_us on the pod's pause/sandbox
// scope when it spuriously holds an RT reservation.
//
// On a cgroup v2 H-CBS hierarchy the kernel enforces, per CPU,
// Sum(children rt_runtime) <= parent rt_runtime. containerd creates a pod's
// pause (sandbox) scope as a sibling of the workload container scope under the
// same per-pod slice. Intermittently the sandbox scope ends up holding RT
// budget even though its OCI spec carries no realtimeRuntime and the pause
// process never runs as a real-time task; that budget would then count against
// the pod-slice and push a workload container's leaf write over the limit,
// failing with EINVAL and crash-looping the pod.
//
// Only the sandbox is reclaimed: it is identified by its "pause" process (see
// isPauseSandbox), so a workload container - even an idle one whose entrypoint
// is merely sleeping (SCHED_NORMAL) - is never stripped of its reservation.
// Best-effort: read/write errors are ignored so a transient failure never
// blocks container creation.
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
		if !isPauseSandbox(sibling) {
			continue // a workload container: keep its reservation
		}
		_ = cgroups.WriteFile(sibling, "cpu.rt_runtime_us", "0")
	}
}

// isPauseSandbox reports whether dir is a pod's pause/sandbox scope, identified
// by a task whose process name (/proc/<pid>/comm) is "pause". The sandbox holds
// no RT spec, so any RT budget it carries is spurious; a workload container is
// never matched, so its reservation is preserved.
func isPauseSandbox(dir string) bool {
	data, err := cgroups.ReadFile(dir, "cgroup.procs")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(data, "\n") {
		pid := strings.TrimSpace(line)
		if pid == "" {
			continue
		}
		comm, err := os.ReadFile("/proc/" + pid + "/comm")
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(comm)) == "pause" {
			return true
		}
	}
	return false
}

// podSliceBudget computes the per-core RT runtime the pod slice must hold: the
// sum of every workload container scope already present under pod (excluding
// this leaf and the pause sandbox) plus this leaf's own reservation. The result
// is keyed by CPU id.
func podSliceBudget(pod, leaf string, leafRt map[int]int64) map[int]int64 {
	budget := map[int]int64{}
	for cpu, v := range leafRt {
		budget[cpu] += v
	}
	entries, err := os.ReadDir(pod)
	if err != nil {
		return budget
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		sib := filepath.Join(pod, e.Name())
		if sib == leaf || isPauseSandbox(sib) {
			continue
		}
		for cpu, v := range readRtPerCore(sib) {
			budget[cpu] += v
		}
	}
	return budget
}

// readRtPerCore parses a cpu.rt_runtime_us READ value - a positional per-cpu
// array such as "100 0 0 100" where the index is the CPU id - into a
// cpu->runtime map, dropping zero entries. A single scalar value maps to cpu 0.
func readRtPerCore(dir string) map[int]int64 {
	out := map[int]int64{}
	data, err := cgroups.ReadFile(dir, "cpu.rt_runtime_us")
	if err != nil {
		return out
	}
	for cpu, f := range strings.Fields(strings.TrimSpace(data)) {
		v, err := strconv.ParseInt(f, 10, 64)
		if err != nil || v == 0 {
			continue
		}
		out[cpu] = v
	}
	return out
}

// rtPairsList turns a cpu->runtime map into the kernel write format
// "<runtime> <cpu> <runtime> <cpu> ...", sorted by CPU id for determinism.
func rtPairsList(perCore map[int]int64) string {
	if len(perCore) == 0 {
		return ""
	}
	cpus := make([]int, 0, len(perCore))
	for c := range perCore {
		cpus = append(cpus, c)
	}
	sort.Ints(cpus)
	var b strings.Builder
	for _, c := range cpus {
		if perCore[c] == 0 {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(strconv.FormatInt(perCore[c], 10))
		b.WriteByte(' ')
		b.WriteString(strconv.Itoa(c))
	}
	return b.String()
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
