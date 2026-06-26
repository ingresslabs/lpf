# Jenkins CI for lpf

All lpf CI jobs live under the **lpf** folder (UI: *New Item → Folder*).
If using `jc` CLI, create the folder then register jobs underneath it.

## Job inventory

| Job | Script | Purpose |
|---|---|---|
| `lpf/lpf-main` | `Jenkinsfile` | OCaml build, tests, Docker image, Vagabond runs |
 | `lpf/lpf-five-distro-e2e` | `ci/five-distro-e2e.groovy` | 5-distro Docker + Ansible + eBPF E2E pipeline |
| `lpf/lpf-auto-release` | `ci/jenkins/auto-release.groovy` | Auto-release on merge to main: tags, pushes, cleans old GitHub Releases |

## Setup via Jenkins UI

1. **Create folder**: *New Item → Folder*, name `lpf`
2. **Create `lpf-main`** inside the folder with the XML from `ci/jenkins/lpf-job.xml`
3. **Create `lpf-five-distro-e2e`** using `ci/five-distro-e2e.groovy` as the Pipeline script path
4. **Create `lpf-auto-release`** inside the folder with the XML from `ci/jenkins/auto-release.xml`

## Setup via `jc` CLI

```sh
# Create jobs at root (folder creation unsupported by jc)
jc job apply lpf-main  -f ci/jenkins/lpf-job.xml
jc job apply lpf-five-distro-e2e \
  --config "$(sed 's|ci/jenkins/five-distro-e2e.groovy|ci/five-distro-e2e.groovy|' ci/jenkins/five-distro-e2e.xml)"
jc job apply lpf-auto-release -f ci/jenkins/auto-release.xml

# Build
jc job build lpf-five-distro-e2e
```

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
