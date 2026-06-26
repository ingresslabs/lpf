// lpf 5-distro End-to-End Pipeline
//
// Builds lpf CI images for 5 Linux distributions, runs the full userspace
// feature suite on each, and optionally exercises the eBPF datapath in
// Firecracker microVMs across paired kernels.
//
// Distro × Kernel matrix (5 images):
//   debian    × linux-6.1   (LTS)     – apt, glibc
//   ubuntu-22 × linux-6.6   (LTS)     – apt, glibc
//   ubuntu-24 × linux-6.12  (longterm)– apt, glibc
//   alpine    × linux-5.15  (LTS)     – apk, musl
//   fedora    × linux-7.1   (mainline)– dnf, glibc
//
// Stages:
//   1. Build all 5 Docker images in parallel.
//   2. Run dune runtest + feature suite in Docker on each image.
//   3. (opt-in) Run Firecracker eBPF conformance + full E2E on each distro
//      with its assigned kernel.
//   4. Collect and archive JUnit XML.

pipeline {
  agent any

  options {
    timeout(time: 180, unit: 'MINUTES')
    disableConcurrentBuilds()
  }

  parameters {
    string(name: 'VAGABOND_API_URL', defaultValue: 'http://vagabond.141.105.65.227.sslip.io',
           description: 'Vagabond control-plane base URL')
    string(name: 'VAGABOND_CREDENTIALS_ID', defaultValue: 'vagabond-api-key',
           description: 'Jenkins Secret-text credential holding the Vagabond API key')
    string(name: 'SCAN_TARGET', defaultValue: '141.105.65.227',
           description: 'Allowlisted target host for the Vagabond jobs')
    string(name: 'FIRECRACKER_ROOTFS', defaultValue: '',
           description: 'Path to the lpf rootfs image for Firecracker microVMs. Empty disables Firecracker stages.')
    booleanParam(name: 'RUN_FIRECRACKER', defaultValue: false,
           description: 'Run Firecracker microVM stages (requires rootfs + kernel mappings)')
    string(name: 'KERNEL_DEBIAN', defaultValue: '',
           description: 'debian kernel image path (e.g. /images/vmlinux-6.1)')
    string(name: 'KERNEL_UBUNTU22', defaultValue: '',
           description: 'ubuntu-22 kernel image path (e.g. /images/vmlinux-6.6)')
    string(name: 'KERNEL_UBUNTU24', defaultValue: '',
           description: 'ubuntu-24 kernel image path (e.g. /images/vmlinux-6.12)')
    string(name: 'KERNEL_ALPINE', defaultValue: '',
           description: 'alpine kernel image path (e.g. /images/vmlinux-5.15)')
    string(name: 'KERNEL_FEDORA', defaultValue: '',
           description: 'fedora kernel image path (e.g. /images/vmlinux-7.1)')
  }

  // ── distro × kernel matrix definition ─────────────────────────────────────
  // Each entry: [label, opam_base_image, kernel_param, kernel_label]
  // kernel_label is the Firecracker kernel uname label for JUnit reporting.

  environment {
    DISTROS = '''\
debian    ocaml/opam:debian-12-ocaml-5.1           KERNEL_DEBIAN   linux-6.1
ubuntu-22 ocaml/opam:ubuntu-22.04-ocaml-5.1        KERNEL_UBUNTU22 linux-6.6
ubuntu-24 ocaml/opam:ubuntu-24.04-ocaml-5.1        KERNEL_UBUNTU24 linux-6.12
alpine    ocaml/opam:alpine-ocaml-5.1              KERNEL_ALPINE   linux-5.15
fedora    ocaml/opam:fedora-41-ocaml-5.1           KERNEL_FEDORA   linux-7.1'''.trim()
  }

  stages {
    stage('Build 5 distro images') {
      parallel {
        stage('debian') {
          steps {
            sh 'docker build -f Dockerfile.ci --build-arg BASE=ocaml/opam:debian-12-ocaml-5.1 -t lpf-ci:debian .'
          }
        }
        stage('ubuntu-22') {
          steps {
            sh 'docker build -f Dockerfile.ci --build-arg BASE=ocaml/opam:ubuntu-22.04-ocaml-5.1 -t lpf-ci:ubuntu-22 .'
          }
        }
        stage('ubuntu-24') {
          steps {
            sh 'docker build -f Dockerfile.ci --build-arg BASE=ocaml/opam:ubuntu-24.04-ocaml-5.1 -t lpf-ci:ubuntu-24 .'
          }
        }
        stage('alpine') {
          steps {
            sh 'docker build -f Dockerfile.ci --build-arg BASE=ocaml/opam:alpine-ocaml-5.1 -t lpf-ci:alpine .'
          }
        }
        stage('fedora') {
          steps {
            sh 'docker build -f Dockerfile.ci --build-arg BASE=ocaml/opam:fedora-41-ocaml-5.1 -t lpf-ci:fedora .'
          }
        }
      }
    }

    stage('Userspace E2E: unit tests + feature suite (5 distros)') {
      parallel {
        stage('debian') {
          steps {
            catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
              sh 'docker run --rm lpf-ci:debian opam exec -- dune runtest'
              sh 'docker run --rm lpf-ci:debian bash -lc "cd /home/opam/src && LPF_FEATURE_JUNIT=junit-lpf-feature-debian.xml ci/vagabond/feature-suite.sh"'
            }
          }
        }
        stage('ubuntu-22') {
          steps {
            catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
              sh 'docker run --rm lpf-ci:ubuntu-22 opam exec -- dune runtest'
              sh 'docker run --rm lpf-ci:ubuntu-22 bash -lc "cd /home/opam/src && LPF_FEATURE_JUNIT=junit-lpf-feature-ubuntu22.xml ci/vagabond/feature-suite.sh"'
            }
          }
        }
        stage('ubuntu-24') {
          steps {
            catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
              sh 'docker run --rm lpf-ci:ubuntu-24 opam exec -- dune runtest'
              sh 'docker run --rm lpf-ci:ubuntu-24 bash -lc "cd /home/opam/src && LPF_FEATURE_JUNIT=junit-lpf-feature-ubuntu24.xml ci/vagabond/feature-suite.sh"'
            }
          }
        }
        stage('alpine') {
          steps {
            catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
              sh 'docker run --rm lpf-ci:alpine opam exec -- dune runtest'
              sh 'docker run --rm lpf-ci:alpine bash -lc "cd /home/opam/src && LPF_FEATURE_JUNIT=junit-lpf-feature-alpine.xml ci/vagabond/feature-suite.sh"'
            }
          }
        }
        stage('fedora') {
          steps {
            catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
              sh 'docker run --rm lpf-ci:fedora opam exec -- dune runtest'
              sh 'docker run --rm lpf-ci:fedora bash -lc "cd /home/opam/src && LPF_FEATURE_JUNIT=junit-lpf-feature-fedora.xml ci/vagabond/feature-suite.sh"'
            }
          }
        }
      }
    }

    stage('Firecracker E2E: eBPF conformance (5 distros × 5 kernels)') {
      when {
        expression { return params.RUN_FIRECRACKER && params.FIRECRACKER_ROOTFS?.trim() }
      }
      steps {
        script {
          def firecracker_jobs = [:]

          def distros = [
            [label: 'debian',    kernel_param: 'KERNEL_DEBIAN',   kernel_label: 'linux-6.1'],
            [label: 'ubuntu-22', kernel_param: 'KERNEL_UBUNTU22', kernel_label: 'linux-6.6'],
            [label: 'ubuntu-24', kernel_param: 'KERNEL_UBUNTU24', kernel_label: 'linux-6.12'],
            [label: 'alpine',    kernel_param: 'KERNEL_ALPINE',   kernel_label: 'linux-5.15'],
            [label: 'fedora',    kernel_param: 'KERNEL_FEDORA',   kernel_label: 'linux-7.1'],
          ]

          for (d in distros) {
            def distro = d.label
            def kernelParam = d.kernel_param
            def kernelLabel = d.kernel_label
            def kernelImage = params[kernelParam]

            if (!kernelImage?.trim()) {
              echo "Firecracker E2E: skipping ${distro} — no kernel image for ${kernelParam}"
              continue
            }

            firecracker_jobs["firecracker:${distro}"] = {
              stage("ebpf:${distro}") {
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                  timeout(time: 30, unit: 'MINUTES') {
                    def f = vagabondRun(
                      image: "lpf-ci:${distro}",
                      target: params.SCAN_TARGET,
                      runtime: 'nomad.firecracker',
                      kernel: kernelImage,
                      rootfs: params.FIRECRACKER_ROOTFS,
                      vcpu: 2,
                      memoryMiB: 2048,
                      network: 'host',
                      dryRun: false,
                      waitForCompletion: true,
                      apiUrl: params.VAGABOND_API_URL,
                      credentialsId: params.VAGABOND_CREDENTIALS_ID,
                      command: ['bash', '-lc', "cd /home/opam/src && LPF_KERNEL_LABEL=${kernelLabel} LPF_EBPF_LAYERS=0,1,2,3 ci/vagabond/ebpf-e2e-suite.sh"])
                    echo "Firecracker E2E ${distro} (${kernelLabel}): job=${f.jobId} status=${f.status}"
                  }
                }
              }
            }
          }

          if (firecracker_jobs.isEmpty()) {
            echo 'No Firecracker kernels mapped; provide KERNEL_* params + FIRECRACKER_ROOTFS.'
          } else {
            parallel firecracker_jobs
          }
        }
      }
    }
  }

  post {
    always {
      junit testResults: 'junit-lpf-*.xml', allowEmptyResults: true
      archiveArtifacts artifacts: 'junit-lpf-*.xml, vagabond-report-*.json, vagabond-artifacts/**', allowEmptyArchive: true, fingerprint: true
    }
    success {
      echo "5-distro E2E pipeline PASSED: debian, ubuntu-22, ubuntu-24, alpine, fedora"
    }
    failure {
      echo "5-distro E2E pipeline FAILED — check JUnit reports"
    }
  }
}
