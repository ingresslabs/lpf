// lpf CI/CD pipeline -- comprehensive Vagabond test matrix.
//
// Exercises lpf across two axes using the Vagabond Jenkins plugin:
//
//   * IMAGE matrix  (userspace features, all of them): the full lpf feature
//     suite (ci/vagabond/feature-suite.sh) runs inside isolated Vagabond Docker
//     sandboxes (nomad.container) built on different Linux userspaces
//     (Debian/Ubuntu/Alpine -> glibc & musl).
//   * KERNEL matrix (eBPF datapath): the eBPF conformance suite
//     (ci/vagabond/ebpf-suite.sh) runs in Vagabond Firecracker microVMs
//     (nomad.firecracker), one per kernel from ci/kernels/kernel-matrix.tsv,
//     matching lpf's "validated via isolated Firecracker microVM" model.
//
// Security scanning (tsunami) is included only as one optional example use case.
// Vagabond derives tenant/workspace from the API key (a Jenkins Secret-text
// credential); jobs gate the build via the plugin's waitForCompletion.
pipeline {
  agent any

  options {
    timeout(time: 90, unit: 'MINUTES')
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
           description: 'Kernel image mappings for the Firecracker matrix: "label=/path/vmlinux;label2=/path/vmlinux". Empty disables the kernel matrix.')
    string(name: 'FIRECRACKER_ROOTFS', defaultValue: '',
           description: 'Path to the lpf rootfs image for Firecracker microVMs (kernel matrix)')
    booleanParam(name: 'RUN_SECURITY_SCAN', defaultValue: false,
           description: 'Optional: run a security scan (tsunami) as one example Vagabond use case')
  }

  stages {
    stage('Build (OCaml / dune)') {
      steps { sh 'docker build --target builder -t lpf-builder:ci .' }
    }

    stage('Unit tests (dune runtest)') {
      steps { sh 'docker run --rm lpf-builder:ci opam exec -- dune runtest' }
    }

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
              stage("features on ${label}") {
                def r = vagabondRun(
                  image: "lpf-ci:${label}",
                  target: params.SCAN_TARGET,
                  runtime: 'nomad.container',
                  network: 'none',
                  dryRun: false,
                  waitForCompletion: true,
                  failOnJobFailure: true,
                  timeoutSeconds: 1800,
                  apiUrl: params.VAGABOND_API_URL,
                  credentialsId: params.VAGABOND_CREDENTIALS_ID,
                  command: ['bash', '-lc', 'cd /home/opam/src && ci/vagabond/feature-suite.sh'])
                echo "lpf features on ${label}: job=${r.jobId} status=${r.status}"
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
          // Desired kernels from the committed matrix (skip comments/baseline/optional).
          def desired = []
          readFile('ci/kernels/kernel-matrix.tsv').split('\n').each { line ->
            if (line.startsWith('#') || !line.trim()) { return }
            def f = line.split('\t')
            if (f.length >= 7 && f[2] != 'baseline' && f[6] != 'optional') { desired << f[0].trim() }
          }
          // Operator-supplied kernel image mappings "label=/path;label2=/path".
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
              echo "kernel ${label}: requested in matrix but no image mapping supplied; skipping"
              continue
            }
            branches["kernel:${label}"] = {
              catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
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
                  failOnJobFailure: true,
                  timeoutSeconds: 2400,
                  apiUrl: params.VAGABOND_API_URL,
                  credentialsId: params.VAGABOND_CREDENTIALS_ID,
                  command: ['bash', '-lc', "cd /home/opam/src && LPF_KERNEL_LABEL=${label} ci/vagabond/ebpf-suite.sh"])
                echo "lpf eBPF on kernel ${label}: job=${f.jobId} status=${f.status}"
              }
            }
          }
          if (branches.isEmpty()) {
            echo 'No mapped kernels to run; supply AVAILABLE_KERNELS + FIRECRACKER_ROOTFS to enable the kernel matrix.'
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
      echo "lpf matrix OK -> images=[${params.IMAGE_MATRIX}] via Vagabond (nomad.container); kernels via nomad.firecracker when mapped"
    }
  }
}
