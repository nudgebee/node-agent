package containers

import (
	"net/url"
	"strings"
)

const (
	// A Docker/containerd/CRI-O label or a systemd Environment= entry names the repository a
	// service was built from. The label names match the Kubernetes workload annotations the
	// Nudgebee platform already reads, so one convention covers every platform.
	gitRepoLabel   = "workloads.nudgebee.com/git.repo"
	gitBranchLabel = "workloads.nudgebee.com/git.branch"
	gitRepoEnv     = "NUDGEBEE_GIT_REPO"
	gitBranchEnv   = "NUDGEBEE_GIT_BRANCH"

	maxGitBranchLen = 255
)

// GitSource is the repository and branch a service declares it runs. Both are empty
// when the service declares nothing, or declares something that is not a plain URL.
type GitSource struct {
	Repo   string
	Branch string
}

// gitSourceFromLabels reads the declaration from container labels.
func gitSourceFromLabels(labels map[string]string) GitSource {
	return newGitSource(labels[gitRepoLabel], labels[gitBranchLabel])
}

// gitSourceFromEnv reads the declaration from KEY=VALUE entries, the form of a systemd
// unit's Environment property.
func gitSourceFromEnv(env []string) GitSource {
	var repo, branch string
	for _, e := range env {
		switch k, v, _ := strings.Cut(e, "="); k {
		case gitRepoEnv:
			repo = v
		case gitBranchEnv:
			branch = v
		}
	}
	return newGitSource(repo, branch)
}

func newGitSource(repo, branch string) GitSource {
	repo = cleanGitRepoURL(repo)
	if repo == "" {
		return GitSource{}
	}
	branch = strings.TrimSpace(branch)
	if len(branch) > maxGitBranchLen {
		branch = ""
	}
	return GitSource{Repo: repo, Branch: branch}
}

// cleanGitRepoURL keeps an http(s) URL and drops what must never become a metric label:
// credentials embedded in the URL (https://token@host/...), a query string (even an empty one) and a fragment.
// Anything else, such as an scp-style git@host:org/repo remote, yields "".
func cleanGitRepoURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return ""
	}
	u.User, u.RawQuery, u.Fragment, u.ForceQuery = nil, "", "", false
	return strings.TrimSuffix(u.String(), "/")
}

// gitSource is the declaration of this container: a systemd unit's Environment, else its labels.
func (m *ContainerMetadata) gitSource() GitSource {
	if m.systemd.Git.Repo != "" {
		return m.systemd.Git
	}
	return gitSourceFromLabels(m.labels)
}
