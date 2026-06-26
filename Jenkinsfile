// lpf CI/CD pipeline — end-to-end test matrix covering every subsystem.
//
// Exercises lpf across six axes:
//
//   * IMAGE matrix      — userspace feature suite in Docker sandboxes (Debian/Ubuntu/Alpine)
//   * UNIT+VAGABOND      — OCaml unit tests + feature suite in Vagabond isolation
//   * eBPF conformance   — privileged Docker: BPF prog_run, kernel datapath
//   * KERNEL matrix     — eBPF datapath in Firecracker microVMs (one per kernel)
//   * E2E matrix        — full Firecracker E2E: live veth, apply/rollback, iperf3
//   * CNI SANDBOX        — Docker CNI ADD/DEL/CHECK lifecycle with real traffic
//   * CNI k3s E2E        — k3d cluster: pod-to-pod policy, NetworkPolicy translation
//   * CNI kind E2E       — kind multi-node: cross-node traffic, 500-pod stress
//   * L7 BPF filter      — DNS QNAME, HTTP host/method, TLS SNI in BPF
//   * Service LB         — Maglev backend selection, connection affinity
//   * Z3 VERIFICATION    — formal proof: consistency, coverage, minimize, eBPF equiv
//
// Stages are conditionally enabled via parameters with sensible defaults.

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
    string(name: 'IMAGE_MATRIX', defaultValue: 'debian,alpine',
           description: 'Comma list of userspace labels to test (debian,ubuntu,alpine)')
    string(name: 'AVAILABLE_KERNELS', defaultValue: '',
           description: 'Kernel image mappings: "label=/path;label2=/path". Empty disables kernel matrix.')
    string(name: 'E2E_KERNELS', defaultValue: '',
           description: 'Kernel subset for full E2E (veth+iperf3)')
    string(name: 'FIRECRACKER_ROOTFS', defaultValue: '',
           description: 'Path to the lpf rootfs image for Firecracker microVMs')

    booleanParam(name: 'RUN_CNI_SANDBOX', defaultValue: true,
           description: 'Run Docker CNI ADD/DEL/CHECK lifecycle tests')
    booleanParam(name: 'RUN_CNI_K3S', defaultValue: false,
           description: 'Run k3d cluster CNI E2E tests (requires k3d installed)')
    booleanParam(name: 'RUN_CNI_KIND', defaultValue: false,
           description: 'Run kind 3-node CNI E2E tests (requires kind installed)')
    booleanParam(name: 'RUN_L7_BPF', defaultValue: true,
           description: 'Run L7 BPF filtering tests (DNS/HTTP/TLS)')
    booleanParam(name: 'RUN_SVC_LB', defaultValue: true,
           description: 'Run Maglev service LB tests in BPF')
    booleanParam(name: 'RUN_VERIFY', defaultValue: false,
           description: 'Run Z3 formal verification on all policies (requires z3 installed)')
    booleanParam(name: 'RUN_SECURITY_SCAN', defaultValue: false,
           description: 'Optional: run a security scan (tsunami)')
  }

  stages {
    // ═══════════════════════════════════════════════════════════════════════
    // STAGE 1: Build all CI images (shared across subsequent stages)
    // ═══════════════════════════════════════════════════════════════════════
    stage('Build CI images') {
      steps {
        script {
          def bases = [
            debian: 'ocaml/opam:debian-12-ocaml-5.1',
            ubuntu: 'ocaml/opam:ubuntu-22.04-ocaml-5.1',
            alpine: 'ocaml/opam:alpine-ocaml-5.1',
          ]
          def labels = params.IMAGE_MATRIX.split(',').collect { it.trim() }.findAll { it }
          def builds = [:]
          for (lbl in labels) {
            def label = lbl
            def base = bases[label]
            if (base == null) continue
            builds["build:${label}"] = {
              sh "docker build -f Dockerfile.ci --build-arg BASE=${base} -t lpf-ci:${label} ."
            }
          }
          parallel builds
        }
      }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // STAGE 2: Unit tests + feature suite per image (gate)
    // ═══════════════════════════════════════════════════════════════════════
    stage('Unit tests + feature suite (gate)') {
      steps {
        script {
          def labels = params.IMAGE_MATRIX.split(',').collect { it.trim() }.findAll { it }
          def branches = [:]
          for (lbl in labels) {
            def label = lbl
            branches["gate:${label}"] = {
              catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                sh "docker run --rm lpf-ci:${label} opam exec -- dune runtest"
                sh "docker run --rm lpf-ci:${label} bash -lc 'cd /home/opam/src && ci/vagabond/feature-suite.sh'"
              }
            }
          }
          parallel branches
        }
      }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // STAGE 3: eBPF conformance in privileged Docker
    // ═══════════════════════════════════════════════════════════════════════
    stage('eBPF conformance (Docker, privileged)') {
      steps {
        script {
          catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
            sh '''
              docker run --rm --privileged --user root \
                -v /sys/fs/bpf:/sys/fs/bpf \
                -v /sys/kernel/btf:/sys/kernel/btf:ro \
                --tmpfs /tmp \
                lpf-ci:debian \
                bash -lc "cd /home/opam/src && ci/vagabond/ebpf-suite.sh"
            '''
          }
        }
      }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // STAGE 4: L7 BPF filtering tests (DNS QNAME, HTTP host, TLS SNI)
    // ═══════════════════════════════════════════════════════════════════════
    stage('L7 BPF filtering (DNS / HTTP / TLS)') {
      when { expression { return params.RUN_L7_BPF } }
      steps {
        script {
          catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
            sh '''
              docker run --rm --privileged --user root \
                -v /sys/fs/bpf:/sys/fs/bpf \
                -v /sys/kernel/btf:/sys/kernel/btf:ro \
                --tmpfs /tmp \
                lpf-ci:debian \
                bash -lc "cd /home/opam/src && bash ci/jenkins/l7-bpf-suite.sh"
            '''
          }
        }
      }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // STAGE 5: Maglev service LB tests
    // ═══════════════════════════════════════════════════════════════════════
    stage('Service LB (Maglev consistent hashing)') {
      when { expression { return params.RUN_SVC_LB } }
      steps {
        script {
          catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
            sh '''
              docker run --rm --privileged --user root \
                -v /sys/fs/bpf:/sys/fs/bpf \
                -v /sys/kernel/btf:/sys/kernel/btf:ro \
                --tmpfs /tmp \
                lpf-ci:debian \
                bash -lc "cd /home/opam/src && bash ci/jenkins/svc-lb-suite.sh"
            '''
          }
        }
      }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // STAGE 6: CNI sandbox tests (Docker ADD/DEL/CHECK lifecycle)
    // ═══════════════════════════════════════════════════════════════════════
    stage('CNI sandbox (ADD/DEL/CHECK lifecycle)') {
      when { expression { return params.RUN_CNI_SANDBOX } }
      steps {
        script {
          catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
            sh '''
              docker run --rm --privileged --user root \
                -v /var/run/docker.sock:/var/run/docker.sock \
                -v /sys/fs/bpf:/sys/fs/bpf \
                -v /sys/kernel/btf:/sys/kernel/btf:ro \
                --tmpfs /tmp \
                --network host \
                lpf-ci:debian \
                bash -lc "cd /home/opam/src && bash ci/jenkins/cni-sandbox-suite.sh"
            '''
          }
        }
      }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // STAGE 7: Z3 formal verification on all policy files
    // ═══════════════════════════════════════════════════════════════════════
    stage('Z3 formal verification') {
      when { expression { return params.RUN_VERIFY } }
      steps {
        script {
          catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
            sh '''
              docker run --rm lpf-ci:debian \
                bash -lc "cd /home/opam/src && bash ci/jenkins/verify-suite.sh"
            '''
          }
        }
      }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // STAGE 8: CNI k3s cluster E2E (pod-to-pod, NetworkPolicy translation)
    // ═══════════════════════════════════════════════════════════════════════
    stage('CNI k3s E2E (pod policy, NP translation)') {
      when { expression { return params.RUN_CNI_K3S } }
      steps {
        script {
          catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
            timeout(time: 30, unit: 'MINUTES') {
              sh 'bash ci/cni/k3s-e2e.sh'
            }
          }
        }
      }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // STAGE 9: CNI kind 3-node E2E (cross-node, stress)
    // ═══════════════════════════════════════════════════════════════════════
    stage('CNI kind 3-node E2E (cross-node, stress)') {
      when { expression { return params.RUN_CNI_KIND } }
      steps {
        script {
          catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
            timeout(time: 45, unit: 'MINUTES') {
              sh 'bash ci/cni/kind-e2e.sh'
            }
          }
        }
      }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // STAGE 10: Kernel matrix — eBPF in Firecracker microVMs
    // ═══════════════════════════════════════════════════════════════════════
    stage('Kernel matrix: eBPF in Firecracker microVMs') {
      when { expression { return params.AVAILABLE_KERNELS?.trim() } }
      steps {
        script {
          def desired = []
          readFile('ci/kernels/kernel-matrix.tsv').split('\n').each { line ->
            if (line.startsWith('#') || !line.trim()) { return }
            def f = line.split('\t')
            if (f.length >= 7 && f[2] != 'baseline' && f[6] != 'optional') { desired << f[0].trim() }
          }
          def mapping = [:]
          params.AVAILABLE_KERNELS.split(';').each { pair ->
            def kv = pair.split('=')
            if (kv.length == 2) { mapping[kv[0].trim()] = kv[1].trim() }
          }
          def branches = [:]
          for (k in desired) {
            def label = k
            def kernelImage = mapping[label]
            if (kernelImage == null) continue
            branches["kernel:${label}"] = {
              stage("eBPF on kernel:${label}") {
                timeout(time: 15, unit: 'MINUTES') {
                  def f = vagabondRun(
                    image: 'lpf-ci:debian',
                    target: params.SCAN_TARGET,
                    runtime: 'nomad.firecracker',
                    kernel: kernelImage,
                    rootfs: params.FIRECRACKER_ROOTFS,
                    vcpu: 2,
                    memoryMiB: 1024,
                    dryRun: false,
                    waitForCompletion: true,
                    apiUrl: params.VAGABOND_API_URL,
                    credentialsId: params.VAGABOND_CREDENTIALS_ID,
                    command: ['bash', '-lc', "cd /home/opam/src && LPF_KERNEL_LABEL=${label} LPF_EBPF_LAYERS=0,1,2 ci/vagabond/ebpf-suite.sh"])
                  echo "eBPF on kernel ${label}: job=${f.jobId} status=${f.status}"
                }
              }
            }
          }
          if (branches.isEmpty()) {
            echo 'No mapped kernels; supply AVAILABLE_KERNELS + FIRECRACKER_ROOTFS.'
          } else {
            parallel branches
          }
        }
      }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // STAGE 11: Full E2E — live veth + apply/rollback + iperf3
    // ═══════════════════════════════════════════════════════════════════════
    stage('E2E matrix: live veth + apply/rollback') {
      when { expression { return params.E2E_KERNELS?.trim() } }
      steps {
        script {
          def e2e_mapping = [:]
          params.E2E_KERNELS.split(';').each { pair ->
            def kv = pair.split('=')
            if (kv.length == 2) { e2e_mapping[kv[0].trim()] = kv[1].trim() }
          }
          def branches = [:]
          for (kv in e2e_mapping) {
            def label = kv.key
            def kernelImage = kv.value
            if (kernelImage == null) continue
            branches["e2e:${label}"] = {
              catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                def f = vagabondRun(
                  image: 'lpf-ci:debian',
                  target: params.SCAN_TARGET,
                  runtime: 'nomad.firecracker',
                  kernel: kernelImage,
                  rootfs: params.FIRECRACKER_ROOTFS,
                  vcpu: 2,
                  memoryMiB: 2048,
                  network: 'host',
                  dryRun: false,
                  waitForCompletion: false,
                  apiUrl: params.VAGABOND_API_URL,
                  credentialsId: params.VAGABOND_CREDENTIALS_ID,
                  command: ['bash', '-lc', "cd /home/opam/src && LPF_KERNEL_LABEL=${label} LPF_EBPF_LAYERS=0,1,2,3 ci/vagabond/ebpf-e2e-suite.sh"])
                echo "e2e on kernel ${label}: job=${f.jobId} status=${f.status}"
              }
            }
          }
          if (branches.isEmpty()) {
            echo 'No E2E kernels; supply E2E_KERNELS + FIRECRACKER_ROOTFS.'
          } else {
            parallel branches
          }
        }
      }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // STAGE 12: Vagabond feature suite in isolated sandboxes
    // ═══════════════════════════════════════════════════════════════════════
    stage('Vagabond isolation: feature suite') {
      steps {
        script {
          def labels = params.IMAGE_MATRIX.split(',').collect { it.trim() }.findAll { it }
          def branches = [:]
          for (lbl in labels) {
            def label = lbl
            branches["vagabond:${label}"] = {
              def r = vagabondRun(
                image: "lpf-ci:${label}",
                target: params.SCAN_TARGET,
                runtime: 'nomad.container',
                network: 'none',
                dryRun: false,
                waitForCompletion: false,
                apiUrl: params.VAGABOND_API_URL,
                credentialsId: params.VAGABOND_CREDENTIALS_ID,
                command: ['bash', '-lc', 'cd /home/opam/src && ci/vagabond/feature-suite.sh'])
              echo "Vagabond feature suite (${label}): job=${r.jobId}"
            }
          }
          if (branches.isEmpty()) {
            echo 'No images for Vagabond isolation.'
          } else {
            parallel branches
          }
        }
      }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // STAGE 13: Security scan (optional)
    // ═══════════════════════════════════════════════════════════════════════
    stage('Security scan (tsunami)') {
      when { expression { return params.RUN_SECURITY_SCAN } }
      steps {
        script {
          def r = vagabondJob(
            template: 'tsunami-dry-run',
            target: params.SCAN_TARGET,
            runtime: 'nomad.container',
            dryRun: true,
            apiUrl: params.VAGABOND_API_URL,
            credentialsId: params.VAGABOND_CREDENTIALS_ID,
            failOn: 'high',
            archiveReport: true,
            timeoutSeconds: 1200)
          echo "Vagabond scan job=${r.jobId} status=${r.status} findings=${r.findings}"
        }
      }
    }
  }

  post {
    always {
      junit testResults: 'junit-lpf-*.xml, junit-cni-*.xml, junit-l7-*.xml, junit-svc-lb-*.xml, junit-verify-*.xml', allowEmptyResults: true
      archiveArtifacts artifacts: 'vagabond-report-*.json, vagabond-artifacts/**, verify-report-*.json, cni-report-*.json, l7-report-*.json, svc-lb-report-*.json', allowEmptyArchive: true, fingerprint: true
    }
    success {
      echo "lpf matrix OK — images=[${params.IMAGE_MATRIX}] cni_sandbox=${params.RUN_CNI_SANDBOX} l7=${params.RUN_L7_BPF} svc_lb=${params.RUN_SVC_LB} cni_k3s=${params.RUN_CNI_K3S} cni_kind=${params.RUN_CNI_KIND} verify=${params.RUN_VERIFY}"
    }
    failure {
      echo "lpf pipeline FAILED — check stage logs"
    }
  }
}
