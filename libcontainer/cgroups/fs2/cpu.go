package fs2

import (
	"bufio"
	"errors"
	"os"
	"strconv"
	"strings"

	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/cgroups/fscommon"
	"github.com/opencontainers/runc/libcontainer/configs"
	"golang.org/x/sys/unix"
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
// The parent slices (kubepods.slice etc.) must already have an RT budget for
// the write below to succeed; on this setup the DRA driver seeds those parents
// before the container is created.
func setRtSched(dirPath string, r *configs.Resources) error {
	if r.CpuRtPeriod == 0 && r.CpuRtRuntime == 0 {
		return nil
	}

	period := ""
	if r.CpuRtPeriod != 0 {
		period = strconv.FormatUint(r.CpuRtPeriod, 10)
	}

	// Build the per-core runtime list "<runtime> <cpu> <runtime> <cpu> ...".
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

	// Write order matters: the first cpu.rt_runtime_us write can fail with
	// EINVAL while cpu.rt_period_us is still 0, so we try runtime, then period,
	// then runtime again, tolerating the initial EINVAL.
	if runtime != "" {
		if err := cgroups.WriteFile(dirPath, "cpu.rt_runtime_us", runtime); err != nil {
			if !errors.Is(err, unix.EINVAL) || period == "" {
				return err
			}
		}
	}
	if period != "" {
		if err := cgroups.WriteFile(dirPath, "cpu.rt_period_us", period); err != nil {
			return err
		}
	}
	if runtime != "" {
		if err := cgroups.WriteFile(dirPath, "cpu.rt_runtime_us", runtime); err != nil {
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
