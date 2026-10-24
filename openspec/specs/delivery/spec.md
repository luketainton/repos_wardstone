## Purpose

Specify continuous verification and release delivery for Wardstone on its self-hosted Gitea instance.

## Requirements

### Requirement: Continuous integration
The repository SHALL run formatting checks, vetting, race-enabled Go tests, release tooling tests, reachable-vulnerability checks, standalone builds, and container HTTPS smoke tests on branch pushes and pull requests.

#### Scenario: Container verification
- **WHEN** CI builds Wardstone
- **THEN** it verifies that anonymous admin access is denied, the generated P12 authenticates successfully, and restart preserves the credential without logging its password again

### Requirement: Versioned releases
The full release workflow SHALL use published Gitea releases as its only automatic build trigger. A separate lightweight tag-creation workflow SHALL create a published release only if one is absent, covering both Git tag pushes and Gitea UI/API tag creation without redundant builds. It SHALL verify the checked-out commit matches the requested tag and SHALL reject malformed versions.

#### Scenario: New version tag
- **WHEN** a tag matching vMAJOR.MINOR.PATCH or a prerelease variant is pushed
- **THEN** the workflow revalidates source, builds release archives, and publishes the matching container image and Gitea assets

#### Scenario: Three notifications for one tag and release
- **WHEN** Gitea emits push, create, and release-published notifications for the same version
- **THEN** exactly one full release workflow is triggered; the create notification only prepares a release if necessary and push does not trigger another full build

#### Scenario: Existing draft or concurrent release
- **WHEN** a tag's release already exists or is created concurrently through Gitea
- **THEN** tag preparation preserves its notes and draft state without publishing it again

### Requirement: Release artifacts
Each complete release SHALL include amd64 and arm64 binaries for Linux, macOS, and Windows, deterministic archive metadata, SHA256 checksums, build version and commit information, and a manifest identifying the published container digest.

#### Scenario: Retry
- **WHEN** a completed release is triggered again for the same commit
- **THEN** the pipeline preserves the existing artifacts instead of replacing them

### Requirement: Container delivery
The pipeline SHALL publish linux/amd64 and linux/arm64 images to the repository's Gitea container registry. Only the newest stable release SHALL promote the latest alias; prereleases SHALL NOT promote it.

#### Scenario: Older stable version is released
- **WHEN** a stable release is published after a newer stable release exists
- **THEN** its versioned image is available while the latest alias remains on the newer stable version

### Requirement: Safe release rehearsal
The workflow SHALL support manual dry runs without creating tags, releases, release attachments, or registry packages.

#### Scenario: Manual dry run
- **WHEN** the workflow is dispatched with publishing disabled
- **THEN** it builds all six archives, tests the container, and exports a multi-platform OCI image without publishing
