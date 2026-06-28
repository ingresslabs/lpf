# Jenkins CI for lpf

All lpf CI jobs live under the **lpf** folder (UI: *New Item → Folder*).
If using `jc` CLI, create the folder then register jobs underneath it.

## Job inventory

| Job | Script | Purpose |
|---|---|---|
| `lpf/lpf-main` | `Jenkinsfile` | OCaml build, tests, Docker image, Vagabond runs |
 | `lpf/lpf-five-distro-e2e` | `ci/five-distro-e2e.groovy` | 5-distro Docker + Ansible + eBPF E2E pipeline |
 | `lpf/lpf-auto-release` | `ci/jenkins/auto-release.groovy` | Auto-release on merge to main: tags, pushes, cleans old GitHub Releases |

## Pipeline stages (lpf-main, 13 stages)

The `Jenkinsfile` runs every subsystem end-to-end:

| # | Stage | Default | Tests |
|---|-------|---------|-------|
| 1 | Build CI images | `debian,alpine` | Parallel docker build per distro |
| 2 | Unit + feature gate | on | `dune runtest` + `feature-suite.sh` per image |
| 3 | eBPF conformance | on | BPF prog_test_run, kernel datapath in privileged Docker |
| 4 | L7 BPF filtering | on | DNS QNAME, HTTP host/method, TLS SNI BPF sections |
| 5 | Service LB | on | Maglev consistent hashing, connection affinity, backend health |
| 6 | CNI sandbox | on | Docker CNI ADD/DEL/CHECK lifecycle, config parsing, error handling |
| 7 | Z3 formal verification | off | `lpf-verify check-all` on all `.lpf` policy files |
| 8 | CNI k3s E2E | off | k3d cluster: pod-to-pod, NetworkPolicy translation |
| 9 | CNI kind E2E | off | kind 3-node: cross-node traffic, 500-pod stress |
| 10 | Kernel matrix | on (when mapped) | eBPF in Firecracker microVMs, one per kernel version |
| 11 | E2E matrix | on (when mapped) | Live veth + apply/rollback + iperf3 in Firecracker |
| 12 | Vagabond isolation | on | Feature suite in Vagabond sandbox (nomad.container) |
| 13 | Security scan | off | tsunami-dry-run in Vagabond |

### Suite scripts (invoked by Jenkins stages)

| Script | Purpose | JUnit output |
|--------|---------|-------------|
| `ci/jenkins/cni-sandbox-suite.sh` | CNI binary: VERSION, config parse, ADD/DEL/CHECK, error handling | `junit-cni-sandbox.xml` |
| `ci/jenkins/l7-bpf-suite.sh` | L7 BPF: DNS/HTTP/TLS parsers, ELF sections, map definitions | `junit-l7-bpf.xml` |
| `ci/jenkins/svc-lb-suite.sh` | Service LB: Maglev hash, lpf_svc_lookup, backend health, XDP integration | `junit-svc-lb.xml` |
| `ci/jenkins/verify-suite.sh` | Z3 verification: consistency + coverage on all policies | `junit-verify.xml` |

## Setup via Jenkins UI

1. **Create folder**: *New Item → Folder*, name `lpf`
2. **Create `lpf-main`** inside the folder using `Jenkinsfile` from the repo root as Pipeline script path
3. **Create `lpf-five-distro-e2e`** using `ci/five-distro-e2e.groovy` as Pipeline script path
4. **Create `lpf-auto-release`** using `ci/jenkins/auto-release.groovy` as Pipeline script path

## Auto-release pipeline

The `lpf-auto-release` job polls the main branch every 5 minutes. When it detects
new commits, it:

1. Reads the latest version from `CHANGELOG.md`
2. Creates an annotated git tag (`vX.Y.Z`)
3. Pushes the tag to GitHub (triggers the GitHub Actions release workflow)
4. Waits for the release workflow to complete
5. Deletes all old GitHub Releases, keeping only the latest

Requires a Jenkins credential `github-lpf-release-token` (GitHub PAT with `repo` and `delete_repo` scopes) bound to the `GH_TOKEN` environment variable.

## Prerequisites (Jenkins controller)

- `cloudbees-folder` plugin (for folder support)
- Vagabond plugin (`apps/jenkins-plugin`)
- Secret-text credential `vagabond-api-key`
- Secret-text credential `github-lpf-release-token`
- Docker installed on Jenkins agent
- `gh` CLI installed on Jenkins agent
