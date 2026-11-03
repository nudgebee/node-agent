package common

import (
	"regexp"
	"strings"
)

var (
	deploymentPodRegex  = regexp.MustCompile(`(/k8s/[a-z0-9-]+/[a-z0-9-]+)-[0-9a-f]{1,10}-[bcdfghjklmnpqrstvwxz2456789]{5}/.+`)
	daemonsetPodRegex   = regexp.MustCompile(`(/k8s/[a-z0-9-]+/[a-z0-9-]+)-[bcdfghjklmnpqrstvwxz2456789]{5}/.+`)
	statefulsetPodRegex = regexp.MustCompile(`(/k8s/[a-z0-9-]+/[a-z0-9-]+)-\d+/.+`)
	cronjobPodRegex     = regexp.MustCompile(`^/k8s-cronjob/([a-z0-9-]+/[a-z0-9-]+)/.+`)
)

func ContainerIdToOtelServiceName(containerId string) string {
	// A CronJob pod within its schedule window has a /k8s-cronjob/<ns>/<cronjob>/<container>
	// id (containers/registry.go); a run outside it keeps its pod name and maps to
	// /k8s/<ns>/<cronjob> below, so both get that name.
	if g := cronjobPodRegex.FindStringSubmatch(containerId); len(g) == 2 {
		return "/k8s/" + g[1]
	}
	if !strings.HasPrefix(containerId, "/k8s/") {
		return containerId
	}
	for _, r := range []*regexp.Regexp{deploymentPodRegex, daemonsetPodRegex, statefulsetPodRegex} {
		if g := r.FindStringSubmatch(containerId); len(g) == 2 {
			return g[1]
		}
	}
	return containerId
}
