# Security Policy

## Supported Versions

We provide security updates for the latest minor release.

| Version | Supported |
| ------- | --------- |
| latest  | yes       |
| older   | no        |

## Reporting a Vulnerability

If you believe you have found a security vulnerability in nudgebee-node-agent,
please report it privately. Do **not** open a public GitHub issue.

Email: **security@nudgebee.com**

Please include:

- A description of the issue and its potential impact
- Steps to reproduce (proof-of-concept code is welcome)
- The version / commit you tested against
- Any suggested remediation

We will acknowledge receipt within 3 business days, provide an initial
assessment within 10 business days, and aim to ship a fix within 90 days
of confirmation. We will credit you in the release notes unless you
request otherwise.

## Scope

In scope:

- Code in this repository (Go agent and eBPF probes)
- Default configurations shipped in `manifests/` and `install.sh`
- Container images published from this repository's release workflow

Out of scope:

- Issues in third-party dependencies (please report upstream)
- Vulnerabilities that require root access on the host where the agent
  is already running with `privileged: true` and `hostPID: true` (this
  is the documented operating model)
