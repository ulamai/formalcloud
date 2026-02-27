# CI Templates

Starter CI templates are available in `examples/ci/`:

1. `github-actions-formal-cloud.yml`
2. `gitlab-ci-formal-cloud.yml`
3. `Jenkinsfile.formal-cloud`

## Included review artifacts

Templates produce:

1. Canonical certificate JSON.
2. Trace logs.
3. JUnit report for pipeline test views.
4. SARIF for code-scanning review workflows.

## Artifact retention examples

1. GitHub Actions: `retention-days: 30`.
2. GitLab CI: `expire_in: 30 days`.
3. Jenkins: `archiveArtifacts` + `junit`.

Adjust retention based on your audit and privacy requirements.
