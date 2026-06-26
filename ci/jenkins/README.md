# Jenkins CI for lpf

All lpf CI jobs live under the **lpf** folder (UI: *New Item → Folder*).
If using `jc` CLI, create the folder then register jobs underneath it.

## Job inventory

| Job | Script | Purpose |
|---|---|---|
| `lpf/lpf-main` | `Jenkinsfile` | OCaml build, tests, Docker image, Vagabond runs |
| `lpf/lpf-five-distro-e2e` | `ci/five-distro-e2e.groovy` | 5-distro Docker + Ansible + eBPF E2E pipeline |

## Setup via Jenkins UI

1. **Create folder**: *New Item → Folder*, name `lpf`
2. **Create `lpf-main`** inside the folder with the XML from `ci/jenkins/lpf-job.xml`
3. **Create `lpf-five-distro-e2e`** using `ci/five-distro-e2e.groovy` as the Pipeline script path

## Setup via `jc` CLI

```sh
# Create jobs at root (folder creation unsupported by jc)
jc job apply lpf-main  -f ci/jenkins/lpf-job.xml
jc job apply lpf-five-distro-e2e \
  --config "$(sed 's|ci/jenkins/five-distro-e2e.groovy|ci/five-distro-e2e.groovy|' ci/jenkins/five-distro-e2e.xml)"

# Build
jc job build lpf-five-distro-e2e
```

## Prerequisites (Jenkins controller)

- `cloudbees-folder` plugin (for folder support)
- Vagabond plugin (`apps/jenkins-plugin`)
- Secret-text credential `vagabond-api-key`
- Docker installed on Jenkins agent
