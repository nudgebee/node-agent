package containers

import "testing"

func TestGitSourceFromLabels(t *testing.T) {
	got := gitSourceFromLabels(map[string]string{
		gitRepoLabel:   "https://github.com/org/api",
		gitBranchLabel: " release ",
	})
	if want := (GitSource{Repo: "https://github.com/org/api", Branch: "release"}); got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestGitSourceFromEnv(t *testing.T) {
	got := gitSourceFromEnv([]string{"PATH=/usr/bin", "NUDGEBEE_GIT_REPO=https://gitlab.com/g/p", "NUDGEBEE_GIT_BRANCH=main"})
	if want := (GitSource{Repo: "https://gitlab.com/g/p", Branch: "main"}); got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestCleanGitRepoURL(t *testing.T) {
	for raw, want := range map[string]string{
		"https://github.com/org/repo":                 "https://github.com/org/repo",
		"https://github.com/org/repo/":                "https://github.com/org/repo",
		"https://ghp_secret@github.com/org/repo":      "https://github.com/org/repo",
		"https://user:pw@gitlab.com/g/p?token=x#frag": "https://gitlab.com/g/p",
		"https://github.com/org/repo?":                "https://github.com/org/repo",
		"git@github.com:org/repo.git":                 "",
		"ssh://git@github.com/org/repo":               "",
		"not a url":                                   "",
		"":                                            "",
		"https:///no-host":                            "",
	} {
		if got := cleanGitRepoURL(raw); got != want {
			t.Errorf("cleanGitRepoURL(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestGitSourceDropsBranchWithoutRepo(t *testing.T) {
	if got := gitSourceFromLabels(map[string]string{gitBranchLabel: "main"}); got != (GitSource{}) {
		t.Errorf("a branch without a usable repo must yield nothing, got %+v", got)
	}
}

func TestMetadataGitSourcePrefersSystemdEnvironment(t *testing.T) {
	md := &ContainerMetadata{
		labels:  map[string]string{gitRepoLabel: "https://github.com/org/from-label"},
		systemd: SystemdProperties{Git: GitSource{Repo: "https://github.com/org/from-env", Branch: "b"}},
	}
	if got := md.gitSource().Repo; got != "https://github.com/org/from-env" {
		t.Errorf("got %q", got)
	}
	md.systemd = SystemdProperties{}
	if got := md.gitSource().Repo; got != "https://github.com/org/from-label" {
		t.Errorf("got %q", got)
	}
}
