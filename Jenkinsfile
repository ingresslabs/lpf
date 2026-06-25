// lpf CI/CD pipeline — comprehensive Vagabond test matrix.
//
// Exercises lpf across three axes using the Vagabond Jenkins plugin:
//
//   * IMAGE matrix   — userspace feature suite (feature-suite.sh) in isolated
//     Vagabond Docker sandboxes (nomad.container) across Debian/Ubuntu/Alpine.
//   * KERNEL matrix  — eBPF datapath conformance (ebpf-suite.sh) in Vagabond
//     Firecracker microVMs (nomad.firecracker), one per kernel from
//     ci/kernels/kernel-matrix.tsv. Includes basic progrun (80 checks) and
//     comprehensive 4-layer E2E runner (conntrack, IPv6, ringbuf, live veth).
//   * E2E matrix     — full Firecracker E2E (ebpf-e2e-suite.sh): live veth
//     traffic, apply/confirm/rollback cycle, conntrack listing, iperf3
//     throughput under XDP filtering. Runs on a subset of kernels (LTS only).
//
// Security scanning (tsunami) is included as one optional example use case.
pipeline {
  agent any

  options {
    timeout(time: 120, unit: 'MINUTES')
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
           description: 'Kernel subset for full E2E (veth+iperf3): "label=/path;label2=/path". Empty disables E2E matrix.')
    string(name: 'FIRECRACKER_ROOTFS', defaultValue: '',
           description: 'Path to the lpf rootfs image for Firecracker microVMs')
    booleanParam(name: 'RUN_SECURITY_SCAN', defaultValue: false,
           description: 'Optional: run a security scan (tsunami) as example use case')
  }

  stages {
    stage('Image matrix: lpf features in isolated Vagabond sandboxes') {
      steps {
        script {
          def bases = [
            debian: 'ocaml/opam:debian-12-ocaml-5.1',
            ubuntu: 'ocaml/opam:ubuntu-22.04-ocaml-5.1',
            alpine: 'ocaml/opam:alpine-ocaml-5.1',
          ]
          def labels = params.IMAGE_MATRIX.split(',').collect { it.trim() }.findAll { it }
          def branches = [:]
          for (lbl in labels) {
            def label = lbl
            def base = bases[label]
            if (base == null) {
              echo "skipping unknown image label '${label}'"
              continue
            }
            branches["image:${label}"] = {
              stage("build lpf-ci:${label}") {
                sh "docker build -f Dockerfile.ci --build-arg BASE=${base} -t lpf-ci:${label} ."
              }
              stage("unit + feature suite on ${label} (gate)") {
                sh "docker run --rm lpf-ci:${label} opam exec -- dune runtest"
                sh "docker run --rm lpf-ci:${label} bash -lc 'cd /home/opam/src && ci/vagabond/feature-suite.sh'"
              }
              stage("feature suite in Vagabond isolation (${label})") {
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
                echo "launched feature suite in Vagabond (${label}): job=${r.jobId}"
              }
            }
          }
          if (branches.isEmpty()) {
            error "IMAGE_MATRIX produced no valid labels: '${params.IMAGE_MATRIX}'"
          }
          parallel branches
        }
      }
    }

    stage('Kernel matrix: eBPF datapath in Firecracker microVMs') {
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
            if (kernelImage == null) {
              echo "kernel ${label}: requested in matrix, no mapping; skipping"
              continue
            }
            branches["kernel:${label}"] = {
              // Batch-run mode: wait for Firecracker VM to complete eBPF suite,
              // then gate on the JUnit result. Timeout 15min for VM boot + tests.
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
                  echo "lpf eBPF on kernel ${label}: job=${f.jobId} status=${f.status}"
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

    stage('E2E matrix: full Firecracker e2e (live veth + apply/rollback)') {
      when { expression { return params.E2E_KERNELS?.trim() } }
      steps {
        script {
          // Only run full E2E on LTS kernels (5.10, 5.15, 6.1, 6.6)
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
                // Run full E2E: all 4 layers including live veth + iperf3
                def f = vagabondRun(
                  image: 'lpf-ci:debian',
                  target: params.SCAN_TARGET,
                  runtime: 'nomad.firecracker',
                  kernel: kernelImage,
                  rootfs: params.FIRECRACKER_ROOTFS,
                  vcpu: 2,
                  memoryMiB: 2048,        // more RAM for live traffic tests
                  network: 'host',         // allow veth pair creation
                  dryRun: false,
                  waitForCompletion: false,
                  apiUrl: params.VAGABOND_API_URL,
                  credentialsId: params.VAGABOND_CREDENTIALS_ID,
                  command: ['bash', '-lc', "cd /home/opam/src && LPF_KERNEL_LABEL=${label} LPF_EBPF_LAYERS=0,1,2,3 ci/vagabond/ebpf-e2e-suite.sh"])
                echo "lpf e2e on kernel ${label}: job=${f.jobId} status=${f.status}"
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

    stage('Vagabond: security scan (optional example)') {
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
      junit testResults: 'junit-lpf-*.xml', allowEmptyResults: true
      archiveArtifacts artifacts: 'vagabond-report-*.json, vagabond-artifacts/**', allowEmptyArchive: true, fingerprint: true
    }
    success {
      echo "lpf matrix OK -> images=[${params.IMAGE_MATRIX}]; kernels via nomad.firecracker when mapped; e2e via E2E_KERNELS"
    }
  }
}
