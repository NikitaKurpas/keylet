# Releases

## Setup

The repository owner must enable **Settings → Actions → General → Allow GitHub Actions to create and approve pull requests**. Keep the existing `release` environment credentials configured; see [the release workflow](.github/workflows/release.yml). No additional token is needed.

Use Conventional Commits: `fix:` bumps the patch version, `feat:` the minor version, and `!` marks a breaking change. If a bot PR shows **Approve workflows to run**, approve its checks before merging.

## Publication

Merge the generated release PR when ready. Release Please creates a hidden draft and version tag, then explicitly dispatches **Release** because `GITHUB_TOKEN`-created tags do not trigger tag-push workflows. These tags are created by GitHub Actions, not signed with the maintainer’s local Keylet key.

Publication requires successful `main` CI for the exact tagged commit. The workflow tests that source, signs and notarizes the build, uploads verified assets, publishes, and updates the Homebrew tap. Ordinary feature merges do not publish releases.

## Recovery

Run **Release** on `main` with the existing tag:

- A draft retry replaces unfinished assets.
- A published-release retry reuses its archive and checksum after verifying the configured Developer ID certificate, signature, and notarization. Certificate changes fail closed; older retries cannot downgrade the tap.
- If dispatch failed after draft creation, run **Release** directly. Rerunning **Release PR** does not redispatch an existing draft.

Manual trusted tags remain supported. Routine releases need only the release PR merge.
