// lpf auto-release pipeline
//
// Triggered automatically on changes to main via SCM polling.
// Extracts the latest version from CHANGELOG.md, creates a git tag,
// pushes it to GitHub (which triggers the GitHub Actions release workflow),
// and cleans up old GitHub Releases so only the latest remains.
//
// Prerequisites:
//   - gh CLI installed and authenticated on the Jenkins agent
//   - Git remotes: origin (GitHub) and lab (private server)

pipeline {
  agent any

  options {
    timeout(time: 30, unit: 'MINUTES')
    disableConcurrentBuilds()
  }

  triggers {
    pollSCM('H/5 * * * *')
  }

  environment {
    GH_TOKEN = credentials('github-lpf-release-token')
  }

  stages {
    stage('Auto-release') {
      when {
        branch 'main'
      }
      steps {
        sh '''#!/bin/bash
          set -euo pipefail

          if [ ! -f ci/jenkins/auto-release.sh ]; then
            echo "auto-release.sh not found, skipping."
            exit 0
          fi

          chmod +x ci/jenkins/auto-release.sh
          bash ci/jenkins/auto-release.sh
        '''
      }
    }
  }

  post {
    success {
      echo "Auto-release check complete."
    }
    failure {
      echo "Auto-release failed — check logs."
    }
  }
}
