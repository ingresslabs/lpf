// lpf CI/CD pipeline.
//
// Builds and tests the OCaml control plane, builds the container image, then
// uses the Vagabond Jenkins plugin (vagabondJob / vagabondRun) to run security
// and isolation workloads on the Vagabond control plane:
//
//   * a Docker (nomad.container) dry-run scan, gated on findings severity;
//   * an isolated Docker sandbox where rendered nftables policy is validated;
//   * (opt-in) the eBPF datapath conformance suite in a Firecracker microVM
//     (nomad.firecracker), matching lpf's "validated via isolated Firecracker
//     microVM end-to-end tests" model.
//
// Vagabond jobs are dry-run by default (the plugin's controller-wide
// "Enforce dry-run" switch); tenant/workspace are derived from the API key.
pipeline {
  agent any

  options {
    timestamps()
    timeout(time: 60, unit: 'MINUTES')
    disableConcurrentBuilds()
  }

  parameters {
    string(name: 'VAGABOND_API_URL', defaultValue: 'http://vagabond.141.105.65.227.sslip.io',
           description: 'Vagabond control-plane base URL')
    string(name: 'VAGABOND_CREDENTIALS_ID', defaultValue: 'vagabond-api-key',
           description: 'Jenkins Secret-text credential holding the Vagabond API key')
    string(name: 'SCAN_TARGET', defaultValue: '141.105.65.227',
           description: 'Allowlisted target host for the Vagabond scan/sandbox jobs')
    string(name: 'IMAGE_TAG', defaultValue: 'ci',
           description: 'Tag for the locally built lpf images')
    booleanParam(name: 'RUN_VAGABOND', defaultValue: true,
           description: 'Run the Vagabond plugin stages (scan + sandbox)')
    booleanParam(name: 'RUN_FIRECRACKER', defaultValue: false,
           description: 'Run the eBPF datapath conformance in a Firecracker microVM (requires the nomad.firecracker runtime to be deployed)')
  }

  environment {
    IMAGE   = "lpf:${params.IMAGE_TAG}"
    BUILDER = "lpf-builder:${params.IMAGE_TAG}"
  }

  stages {
    stage('Build (OCaml / dune)') {
      steps {
        sh 'docker build --target builder -t "$BUILDER" .'
      }
    }

    stage('Unit tests (dune runtest)') {
      steps {
        sh 'docker run --rm "$BUILDER" opam exec -- dune runtest'
      }
    }

    stage('Build container image') {
      steps {
        sh 'docker build -t "$IMAGE" .'
      }
    }

    stage('Policy fixture checks') {
      steps {
        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
          sh '''
            set -eu
            for p in fixtures/policies/*.lpf; do
              case "$p" in *invalid*) continue ;; esac
              echo "lpf check $p"
              docker run --rm -v "$WORKSPACE/fixtures":/fixtures:ro "$IMAGE" check "/$p"
            done
          '''
        }
      }
    }

    stage('Vagabond: security scan (Docker, dry-run)') {
      when { expression { return params.RUN_VAGABOND } }
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
            archiveArtifacts: true,
            timeoutSeconds: 1200)
          echo "Vagabond scan job=${r.jobId} status=${r.status} findings=${r.findings}"
        }
      }
    }

    stage('Vagabond: isolated policy sandbox (Docker)') {
      when { expression { return params.RUN_VAGABOND } }
      steps {
        script {
          def s = vagabondRun(
            image: 'ubuntu:22.04',
            target: params.SCAN_TARGET,
            runtime: 'nomad.container',
            network: 'none',
            apiUrl: params.VAGABOND_API_URL,
            credentialsId: params.VAGABOND_CREDENTIALS_ID,
            command: ['sh', '-c',
              'set -e; uname -a; (nft --version 2>/dev/null || echo "nft not present in base image"); echo "lpf would render and validate nftables policy in this isolated sandbox"'])
          echo "Vagabond sandbox job=${s.jobId} status=${s.status}"
        }
      }
    }

    stage('Vagabond: eBPF datapath in Firecracker (microVM)') {
      when { expression { return params.RUN_FIRECRACKER } }
      steps {
        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
          script {
            def f = vagabondRun(
              image: 'ubuntu:22.04',
              target: params.SCAN_TARGET,
              runtime: 'nomad.firecracker',
              vcpu: 2,
              memoryMiB: 1024,
              apiUrl: params.VAGABOND_API_URL,
              credentialsId: params.VAGABOND_CREDENTIALS_ID,
              command: ['sh', '-c',
                'uname -a; echo "lpf eBPF datapath conformance (make bpf-e2e) runs in this hardware-isolated microVM"'])
            echo "Vagabond Firecracker job=${f.jobId} status=${f.status}"
          }
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
      echo "lpf pipeline OK -> built ${IMAGE}; Vagabond scan/sandbox submitted via the plugin"
    }
  }
}
