# Installing on a fleet of hosts

`install.sh` installs the agent on one host. To put it on many hosts in one go, run
it from a tool that already reaches them. This page covers Ansible (recommended) and
an SSH loop.

## Before you start

- **Hosts:** Linux with systemd, amd64 or arm64, kernel 5.8 or newer. Windows and
  macOS aren't supported.
- **Where the data goes:** the agent pushes to storage you run. Have these ready:
  - a Prometheus remote-write receiver for metrics (`METRICS_ENDPOINT`)
  - an OTLP/HTTP endpoint for traces and logs (`TRACES_ENDPOINT`, `LOGS_ENDPOINT`)
  - an `API_KEY`, if your endpoints need one
- **Network:** each host needs outbound access to GitHub to download the release, and to
  your storage endpoints.
- **Access:** SSH to each host as a user with passwordless `sudo`.
- **What is tracked:** each systemd unit and each Docker or containerd container is a
  service. A process started outside a unit or container, such as with `nohup`, is not.

## Settings

The agent reads its settings from environment variables. On a host they live in
`/etc/default/nudgebee-node-agent`, which the systemd unit loads on start. Both methods
below write that file, so any setting works, and the key stays out of the process list
and `sudo` logs. The variable names are listed in [`flags/flags.go`](../flags/flags.go).

The ones a fleet usually sets:

| Variable | What it does |
|---|---|
| `METRICS_ENDPOINT` | Prometheus remote-write URL. |
| `TRACES_ENDPOINT`, `LOGS_ENDPOINT` | OTLP/HTTP URLs. |
| `API_KEY` | Sent to the endpoints. |
| `TRACES_SAMPLING` | Fraction of traces kept, `0.0` to `1.0`. Default `1.0`. |
| `CA_FILE` | CA bundle for endpoints signed by a private CA. |

Set `METRICS_ENDPOINT`, `TRACES_ENDPOINT` and `LOGS_ENDPOINT` individually. `COLLECTOR_ENDPOINT`
sets all of them from one base URL, but it sends metrics to `<base>/v1/metrics` as Prometheus
remote-write, which an otel-collector doesn't accept.

When a metrics endpoint is set, the agent serves its own `/metrics` on `127.0.0.1:10300`.
This can't be changed with `LISTEN`.

## Ansible

The files are in [`examples/ansible`](../examples/ansible).

1. Copy `inventory.example.ini` to `inventory.ini` and list your hosts under `[node_agent]`.
2. Copy `vars.example.yml` to `vars.yml`. Set your endpoints and a release version.
3. Keep `API_KEY` in [ansible-vault](https://docs.ansible.com/ansible/latest/vault_guide/index.html).
   Create the vaulted value without leaving the key in your shell history:

   ```sh
   ansible-vault encrypt_string --stdin-name api_key
   ```

   Paste the result into a file such as `secrets.yml`, and uncomment the `API_KEY` line in `vars.yml`.
4. Try one host first, then run on the fleet:

   ```sh
   cd examples/ansible
   ansible-playbook -i inventory.ini -e @vars.yml -e @secrets.yml --ask-vault-pass install-node-agent.yml --limit orders-web
   ansible-playbook -i inventory.ini -e @vars.yml -e @secrets.yml --ask-vault-pass install-node-agent.yml
   ```

   Leave out `-e @secrets.yml --ask-vault-pass` if you don't use a vault.

The playbook checks each host meets the requirements, writes the settings file, runs the
installer, and then checks the agent is running and hasn't restarted. It works through the
fleet in batches of 20% and stops if more than 10% of a batch fails. Change that with
`-e node_agent_serial=5`. Variables can also come from `group_vars` or `host_vars`, which
lets you set per-host values such as `REGION`.

**Upgrade:** change `node_agent_version` and run the playbook again.

**Remove:**

```sh
ansible-playbook -i inventory.ini -e @vars.yml install-node-agent.yml -e node_agent_state=absent
```

**Check the fleet:**

```sh
ansible node_agent -i inventory.ini -b -m command -a 'systemctl is-active nudgebee-node-agent'
```

## Without Ansible

Any tool that can run a command over SSH works. Put the settings in a file, one
`NAME='value'` per line, and send it to each host along with the installer:

```sh
# node-agent.env
METRICS_ENDPOINT='http://metrics.example.com:8428/api/v1/write'
TRACES_ENDPOINT='http://otel.example.com:4318/v1/traces'
LOGS_ENDPOINT='http://otel.example.com:4318/v1/logs'
TRACES_SAMPLING='0.1'
```

```sh
VERSION=v0.1.9
while read -r host <&3; do
  ssh "$host" "sudo sh -c 'umask 077; cat > /etc/default/nudgebee-node-agent' &&
    curl -fsSL https://raw.githubusercontent.com/nudgebee/node-agent/$VERSION/install.sh |
    sudo sh -s -- -v $VERSION" < node-agent.env
done 3< hosts.txt
```

The installer comes from the release tag, so the script and the binary always match. `sudo` must
not ask for a password, because there's no terminal to type one into.

For hosts you create from a template or autoscaling group, run the same steps from
cloud-init `runcmd` or the instance user data, so every new host installs itself on first boot.

## Good to know

- **Pin a version** for a fleet. With `latest`, hosts installed on different days run
  different releases, and every host queries the GitHub API on its own, which can hit
  GitHub's rate limit when many share one public IP.
- **Re-running restarts the agent** on every host, even when nothing changed, which leaves a
  short gap in metrics. With the default `latest` it also upgrades.
- **Troubleshooting a host:** `journalctl -u nudgebee-node-agent`.
