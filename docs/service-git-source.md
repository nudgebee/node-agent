# Declaring a service's source repository

A service can tell the platform which repository and branch it runs, so an investigation of
that service can read its code. The agent exports the declaration as two labels on
`container_info`:

```
container_info{container_id="/system.slice/api.service", git_repo="https://github.com/org/api", git_branch="release", ...}
```

Every `container_info` line now carries the two labels, empty when a service declares nothing. Prometheus treats an empty label as absent, so the stored series of services that declare nothing are unchanged.

## Docker, containerd, CRI-O

Set labels on the container. They are the same keys the platform reads from Kubernetes
workload annotations:

```sh
docker run --label workloads.nudgebee.com/git.repo=https://github.com/org/api \
           --label workloads.nudgebee.com/git.branch=release  org/api
```

## systemd

Add a drop-in with `Environment=` entries:

```ini
# /etc/systemd/system/api.service.d/nudgebee.conf
[Service]
Environment=NUDGEBEE_GIT_REPO=https://github.com/org/api
Environment=NUDGEBEE_GIT_BRANCH=release
```

Then `systemctl daemon-reload && systemctl restart api`. Entries from `EnvironmentFile=` are
not read. A unit's `Environment=` wins over container labels.

## What is accepted

- `git_repo` must be an `http(s)` URL. Credentials in the URL (`https://token@host/...`), a
  query string and a fragment are dropped before export, so a token placed in the URL never
  becomes a metric label. Other forms, such as `git@host:org/repo.git`, are ignored.
- `git_branch` is optional (empty means the repository's default branch) and is ignored when
  there is no usable repository.
