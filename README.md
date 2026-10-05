# keylet

A standalone Swift CLI for dedicated Secure Enclave P256 keys and a foreground OpenSSH agent. The intended job is Git SSH signing and SSH authentication after the first manual login/unlock following reboot, including while the user session is screen-locked. **That locked-screen/post-reboot behavior is a hypothesis, not yet verified for this CLI.** The process must remain running in the logged-in user session; this does not provide pre-login, logged-out, sleeping or powered-off signing.

One executable owns one identity (`me.kurpas.keylet`) and one data-protection Keychain service (`me.kurpas.keylet.keys.v1`). It has no Secretive runtime dependency, GUI, XPC, updater, login item, smartcard, migration, private-key export, GitHub token or remote configuration. [NOTICE.md](NOTICE.md) records the exact Secretive and PR #819 source revisions; [LICENSE](LICENSE) retains MIT notices.

## Build and safe checks

Requires macOS 26.4+, an available Secure Enclave for eventual credential operations, and Swift 6.2+ (built here on macOS 27.0.1 with the installed Swift 6.4/Xcode toolchain).

```sh
make test
swift build -c release
make unsigned-bundle
make smoke
```

Apple Swift Argument Parser 1.8.2 is pinned in Package.resolved; audit storage uses system SQLite. Tests use public fixtures, mock signers, temporary SQLite databases/files and local socketpairs; they never create a private key, access Keychain, launch the credentialed agent or contact GitHub. `make unsigned-bundle` and `make smoke` use `dist/unsigned/Keylet.app`, preserving the retained signed `dist/Keylet.app`. `make bundle` intentionally rebuilds that deployment destination and requires subsequent signing. A plain SwiftPM binary supports offline commands and dry-runs; credential commands require the signed bundle.

```sh
BIN="$(swift build -c release --show-bin-path)/keylet"
"$BIN" --help
"$BIN" --json doctor
"$BIN" --json keys create --label 'Git unattended' --policy after-first-unlock --dry-run
"$BIN" --json protocol decode --hex 0b
```

`doctor` performs no Keychain reads and no signature. `signature_shape_ready` means a valid self-signature with the expected identifier, team-derived dedicated group, sandbox, Enhanced Security entitlement, hardened-runtime flag and no debugging entitlement. Provisioning authorization and credential access remain explicitly unverified by doctor. It does not prove that the signed tool can persist or use a key.

## Command contract

| Command | Effect |
|---|---|
| `--help`, `--version`, `doctor` | Offline discovery; no credential operation |
| `keys list` | Public records only from the dedicated namespace, with partial-class status |
| `keys resolve --label LABEL` | Exact unique label to UUID; requires complete inventory |
| `keys public --id UUID` | Public OpenSSH key; an accessible exact UUID works even with another class unavailable |
| `keys create --label LABEL --policy POLICY --dry-run` | Validate/preview; never generates a key |
| `keys create --label LABEL --policy POLICY` | Explicit credential creation; requires separate authorization |
| `agent --key UUID [--socket PATH]` | Foreground, one selected UUID; no installation/persistence |
| `protocol decode --hex HEX` | Read-only bounded payload type/length inspection; does not execute or fully validate the request |
| `audit list [--limit 20] [--before EVENT_ID]` | Read-only newest events; exclusive event-ID pagination, maximum 200 |
| `audit top [--limit 20]` | Most successful signatures per key in the retained window, maximum 200 |

The two unattended agent policies are `after-first-unlock` and `when-unlocked`. The former sets **both** the Secure Enclave access-control protection and the opaque representation's Keychain accessibility to `AfterFirstUnlockThisDeviceOnly`, with `.privateKeyUsage` and no user-presence requirement. The latter uses `WhenUnlockedThisDeviceOnly` with `.privateKeyUsage`. `user-presence` preserves a stricter creation policy for explicit future use, but this noninteractive agent refuses to sign with such a key. Policies and public metadata are immutable; there is no update, rename, delete or migration API. Only P256 is implemented.

Every inventory request queries WhenUnlocked and AfterFirstUnlock separately. A failed/invalid class is marked unavailable while the other remains usable. The next request retries both, without relying on a stale cache. Sign requests re-read the selected UUID in its exact class, check immutable metadata and the reconstructed public key, and prohibit authentication UI. There is no automatic signature retry.

With `--json`, successful commands use `{ "ok": true, ... }`; errors use `{ "ok": false, "error": { "code": "...", "message": "..." } }` and exit 1. Success exits 0. Public record fields are `id`, `label`, `policy`, `algorithm`, `fingerprint`, `public_key`. List returns `keys`, `complete`, `unavailable_classes`; resolve/public returns `key`. Dry-run returns `dry_run: true`, `key_created: false`. Without JSON, `keys public` emits one standard OpenSSH public-key line. No output includes the opaque key representation, private key material or profiles. Agent mode is a long-running service and does not emit a one-shot JSON success envelope.

## Local audit

The agent writes `~/Library/Containers/me.kurpas.keylet/Data/audit/audit.sqlite3` in a user-owned 0700 directory with 0600 database/sidecars. Schema version 1 uses indexed SQLite transactions, FULL synchronous rollback journaling, a 250 ms busy timeout and retention of the newest 10,000 **events** (a successful signing attempt normally has intent and completion events). Reads do not create a database or run migrations; an absent audit directory/database under an existing container returns an empty result; missing container ancestors report a setup/path error. Unsupported schema or detectable path/mode/link tampering fails closed.

Events contain UTC time, request UUID, action/outcome, public key UUID/fingerprint, signing-data byte count and fixed error codes. Peer UID/GID come from the kernel at connection; optional PID is captured at connection and is a hint, not proof of the later process. Inherited/passed descriptors and PID reuse prevent reliable attribution to a human, Codex, Git or a repository. Process path/name, ancestors, repository identity, request payloads, signatures, opaque representations and private material are never recorded. This local log is not tamper-proof against its owner or a compromised same-user process.

Signing starts only after its intent commits. Completion must commit before a signature is returned. If completion logging fails, a signature may already have been computed but is withheld; a lone intent is an ambiguous attempt. A success event records computation, not receipt by the caller or remote acceptance. Identities and rejected/unsupported protocol messages are recorded too. `audit top` counts successful signature events once; it does not count intents or rejected attempts. Pagination is over retained rows and concurrent pruning can remove older pages.

```sh
keylet --json audit list --limit 20
keylet --json audit list --limit 20 --before EVENT_ID
keylet --json audit top --limit 10
```

## Signing and deployment gate

The tool deliberately rejects an unsigned/ad-hoc/wrong-identity executable before Keychain operations. Keep the app-like bundle intact. `packaging/Entitlements.plist.in` is a template, not authorization. It requires the explicit restricted group `TEAM_ID.me.kurpas.keylet`, sandbox and Enhanced Security; signing also needs hardened runtime. A team/App ID prefix that differs from the enforced team-derived group needs an explicit reviewed design change, not a weakened guard.

For local manual signing, use one **Mac App Development** provisioning profile for this explicit App ID. The restricted Keychain group requires a profile; no new certificate is needed if a valid Apple Development identity already exists. If absent, manually select/register `me.kurpas.keylet` in Apple Developer Certificates, Identifiers & Profiles, create a Mac App Development profile with the existing development certificate and this registered Mac, and download it. See [Apple profile instructions](https://developer.apple.com/help/account/provisioning-profiles/create-a-development-provisioning-profile/) and [TN3125](https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles). The profile must permit `com.apple.security.hardened-process=true` and Enhanced Security version `2` (or `*`); the helper rejects missing/mismatched claims. If the downloaded profile lacks them, obtain a matching profile using the Enhanced Security capability for this one app identity rather than removing the checks. The helper never performs portal or profile/certificate creation.

```sh
cd ~/Developer/keylet
security find-identity -v -p codesigning
make bundle
make sign PROFILE="$HOME/Downloads/Keylet.provisionprofile" \
  IDENTITY='EXISTING_CERTIFICATE_SHA1_FROM_THE_LOOKUP' TEAM_ID='YOUR_TEAM_ID'
dist/Keylet.app/Contents/MacOS/keylet --json doctor
```

`make sign` signs an already-built bundle by running `scripts/sign_bundle.py` only because signing was explicitly requested. It deliberately has no build/copy prerequisite, so validation runs before any bundle mutation. Run `make bundle` separately first. Inputs are frozen as literal Make values before export, then passed through the environment; expressions such as `$(shell ...)` in a filename are not evaluated. It validates the exact profile bytes it embeds: explicit App ID/team/prefix, Keychain-group authorization, expiry, selected certificate membership and the current Mac's provisioning ID (hardware UUID fallback for older hardware). It also rejects symlinks, special files and hard links throughout the bundle (including old signature metadata), and requires an existing valid local signing identity and unchanged bundled MIT notices. It generates entitlements from the maintained template, embeds the profile, signs this single bundle with hardened runtime and no debugging entitlement, then verifies the signature. Decoded profile metadata stays in memory; the generated entitlements plist and read-once profile copy exist only in a temporary ignored `dist` directory, removed on exit; the embedded profile stays with the signed app. It does not launch the app, create a key, install persistence, or configure Git/SSH. Invalid inputs stop with a short error. Metadata preflight and `codesign --verify` do not replace the operating system's provisioning authorization or a later approved credential test.

Enhanced Security version `2` is an **explicit policy pin**, not a fix for a demonstrated runtime failure. Apple documents that an absent version uses the latest policy; its version entitlement is available on macOS 26.4+. The package, bundle minimum and credential-operation runtime guard therefore require 26.4+. The maintained entitlement is based on [Apple's version documentation](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.hardened-process.enhanced-security-version-string) and [Enhanced Security guide](https://developer.apple.com/documentation/xcode/enabling-enhanced-security-for-your-app). This CLI opts into the listed runtime entitlements; it does not claim every Xcode Enhanced Security compiler mitigation. Build/pure-test evidence here is from 27.0.1, and signed policy enforcement remains unverified. `doctor` reports static signature shape, OS eligibility and an explicit `security_policy_enforcement_verified:false`; it does not certify active OS mitigations.

Do not copy the old `org.local.SecretiveProto` profile/key or weaken the group. No key import/migration exists. Use `make unsigned-bundle` for isolated review; `make bundle` overwrites the deployment product and requires signing again.

After separate explicit runtime approval, one dedicated `after-first-unlock` P256 key was created. Local stock OpenSSH SSHSIG verification, altered-data/wrong-namespace rejection, one signed temporary Git commit and same-key reuse after foreground-agent restart passed. The agent is stopped and the single key retained; see [VALIDATION.md](VALIDATION.md) for public identity and evidence. Remote registration/push, persistent startup and locked-screen/post-reboot behavior remain untested and require separate authorization. The user concluded earlier lock testing; no repetition is implied.

A personal PATH installation must point to the executable inside the maintained signed bundle. Copying only the binary loses the intended packaging/profile context. No PATH change or personal companion-skill activation is part of this prototype; `skills/keylet/SKILL.md` is staged for review. Updates are manual; replacing the signed product/identity requires revalidation.

## Foreground lifecycle and stock-client integration

Following the relevant approvals, invoke the signed executable directly:

```sh
# Illustrative only: requires an approved key UUID and signed deployment.
keylet agent --key KEY_UUID
```

Default endpoint: the real user's home plus `Library/Containers/me.kurpas.keylet/Data/agent/socket.ssh`. The sandbox container must already exist; only the immediate `agent` directory is created (0700). The socket is 0600 and peers must have the same UID. Explicit paths must be absolute, contain no NUL and fit Darwin's 104-byte sun_path including its terminator. The final directory must be user-owned, 0700 and not a symlink. Existing endpoints are refused; the tool never guesses that an existing socket is stale or deletes it. On normal SIGINT/SIGTERM exit, it removes only its own unchanged socket inode. Abrupt termination may leave a stale socket requiring a separately verified manual cleanup.

The server multiplexes up to 16 same-user connections in one nonblocking event loop. Idle retained OpenSSH connections have no lifetime or request-count cutoff. A fresh eight-second absolute deadline begins with the first request byte and covers its complete header/payload and response backpressure; drip-fed bytes cannot renew it. A partial or idle client does not block other clients. Frames are bounded to 256 KiB; coalesced requests remain in the kernel stream until consumed exactly. Empty/oversized/truncated requests fail closed. Connection admission is capped: when all 16 slots are occupied, a new client is refused rather than evicting an existing retained connection. Native Keychain/Secure Enclave calls prohibit UI but their execution time is not bounded by socket deadlines. SIGINT/SIGTERM ends the poll loop and closes all clients; SIGKILL cannot run cleanup. The earlier signed bundle passed local OpenSSH/Git tests; the new parser/audit source has only credential-free validation until a separately approved signing/runtime update.

The agent supports identities and P256 sign requests only. Mutation, lock/unlock, certificate, session-binding and destination-constrained extensions fail. It exposes one UUID and signs the exact requested bytes; **the socket is a same-user signing oracle, not a Git-only or repository-only authorization boundary**. Non-exportability protects key material, not what callers can request the live key to sign. Do not forward the socket.

Git and SSH remain stock clients. Once integration is authorized, use a public-key file outside protected app-container paths and scope configuration per invocation:

```sh
# Examples; local signing was tested in a temporary repository. No remote push was tested.
SSH_AUTH_SOCK=SOCKET_PATH git -c gpg.format=ssh \
  -c user.signingkey=PUBLIC_KEY_FILE commit -S
SSH_AUTH_SOCK=SOCKET_PATH GIT_SSH_COMMAND='ssh -o ForwardAgent=no -o IdentitiesOnly=yes -i PUBLIC_KEY_FILE' \
  git push
```

GitHub authentication and signature verification require separately approved registration of the corresponding public key(s). This CLI performs neither registration nor Git/SSH settings changes.

## Evidence boundaries

The earlier isolated Secretive GUI prototype established local SSHSIG verification/restart using its old identity. Its timed probe verified signatures but native session logs showed the session unlocked during that window. Those results do **not** establish locked-screen, post-reboot, actual Git commit or GitHub push behavior, and do not transfer to this new CLI. The old namespace/test key and the Inbo staged migration are untouched.

Apple's [Keychain/Secure Enclave explanation](https://developer.apple.com/forums/thread/724013) and [CryptoKit signing initializer](https://developer.apple.com/documentation/cryptokit/secureenclave/p256/signing/privatekey/init(compactrepresentable:accesscontrol:authenticationcontext:)) motivate the chosen model. PR #819's author reports locked-session behavior; that is external evidence, not verification of this CLI's identity or deployment.

## Rename and historical review

The user selected Keylet and registered `me.kurpas.keylet`. At rename time no CLI credentials existed and no migration was performed. The Secretive prototype namespace/key remains untouched. The independent pre-rename review is preserved verbatim in [reviews/enclave-git-2026-10-05.md](reviews/enclave-git-2026-10-05.md); its old names, paths and hashes are historical evidence, not current deployment instructions. Current paths and hashes are in REVIEW-HANDOFF.md and SNAPSHOT.sha256.

## Release and personal Homebrew tap

The public source repository is [NikitaKurpas/keylet](https://github.com/NikitaKurpas/keylet) and the tap is [NikitaKurpas/homebrew-tap](https://github.com/NikitaKurpas/homebrew-tap). Both were created empty; no release is published. No release, formula publication, commit or push was performed by this source worker; the user owns the initial commits/pushes. `packaging/keylet.rb.in` remains a template until a real notarized release and checksum exist.

Ordinary `.github/workflows/ci.yml` runs credential-free Swift/Python/CLI checks on GitHub's arm64 `macos-26` runner and refuses an SDK older than 26.4 or Swift older than 6.2. `.github/workflows/release.yml` handles trusted `vMAJOR.MINOR.PATCH` tags or a manual existing-tag release from main; tagged source must be reachable from main. It tests/builds first, signs with **Developer ID Application** and a matching all-devices profile, notarizes, staples/assesses the app, ZIPs it, publishes the ZIP/checksum to GitHub Releases and updates the tap only after verifying the public assets. No hosted Secure Enclave credential test is included.

Before adding secrets, configure the GitHub **release** environment with a required reviewer and deployment restrictions to main and version tags. Protect main and restrict version-tag creation to the release owner; forbid tag updates/deletion. Review the immutable tagged source/workflow before approving an environment run. These protections are account settings, not enforced by this repository: a modified workflow could remove its own checks. The workflow does not expose secrets to pull requests.

In that environment, enter these **secrets** manually (nothing here exports or uploads credentials):

| Secret | Supplied value |
|---|---|
| `DEVELOPER_ID_P12_BASE64` | Base64 of the user-provided Developer ID Application identity P12 |
| `DEVELOPER_ID_P12_PASSWORD` | That P12's password |
| `DEVELOPER_ID_PROFILE_BASE64` | Base64 Developer ID profile for this App ID/group and Enhanced Security claims |
| `NOTARY_KEY_BASE64` | Base64 team App Store Connect API P8 authorized for notarization |
| `TAP_TOKEN` | Fine-grained GitHub token limited to tap repository Contents write |

Set environment **variables** `DEVELOPER_ID_IDENTITY` (certificate SHA-1), `APPLE_TEAM_ID`, `NOTARY_KEY_ID`, and `NOTARY_ISSUER_ID`. GitHub supplies its short-lived release token; no additional source-repository PAT is needed. Individual notary keys without a team issuer are not supported by this workflow. The runner imports only the supplied signing identity into a temporary keychain, restores its search list and deletes the keychain/files on normal success/failure. It never creates a certificate, profile or SSH key.

Obtain inputs manually in the Apple Developer account: create or select a **Developer ID Application** certificate, export its identity from Keychain Access as a password-protected P12, and create/download a Developer ID provisioning profile for `me.kurpas.keylet` with the required Keychain group and Enhanced Security capabilities. Existing development profiles do not qualify. Use the certificate SHA-1 shown by `security find-identity -v -p codesigning` for `DEVELOPER_ID_IDENTITY` and the membership Team ID for `APPLE_TEAM_ID`. If Apple does not authorize those capabilities for public distribution, release remains blocked; do not weaken the app's checks.

For notarization, have the Account Holder or Admin create a **team** API key in [App Store Connect → Users and Access → Integrations → Team Keys](https://appstoreconnect.apple.com/access/integrations/api), selecting a role authorized for notarization. The Account Holder must first request API access if it is unavailable. [Apple's API-key setup instructions](https://developer.apple.com/help/app-store-connect/get-started/app-store-connect-api/) explain these account requirements. Download the P8 once; its Key ID and the team's Issuer ID become `NOTARY_KEY_ID` and `NOTARY_ISSUER_ID`. Encode each supplied P12/profile/P8 as a single-line base64 value locally and enter it only into its corresponding GitHub environment secret. Never commit these files/values. Create the fine-grained token under [GitHub personal access tokens](https://github.com/settings/personal-access-tokens/new), choosing resource owner `NikitaKurpas`, only `homebrew-tap`, repository permission **Contents: Read and write** (Metadata read is automatic), and an expiry. Enter it as `TAP_TOKEN`. Add inputs at [Keylet → Settings → Environments → release](https://github.com/NikitaKurpas/keylet/settings/environments), after configuring review/deployment restrictions; configure main/tag rules under [Rulesets](https://github.com/NikitaKurpas/keylet/settings/rules).

Public-release signing is separate from development: it requires `ProvisionsAllDevices=true`, no registered-device list, the selected Developer ID certificate in the profile, current expiry, exact App ID/team/prefix/group and authorized Enhanced Security version 2. It uses a secure timestamp; development retains its registered-Mac check and no-network timestamp policy. Recipients do not need their own developer account or registered Mac under Apple's Developer ID model, but actual profile authorization, notarization/Gatekeeper acceptance and recipient key operations remain to be verified. See [Apple Developer ID](https://developer.apple.com/developer-id/) and [provisioning rules](https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles).

A rendered **prebuilt formula** installs the intact app under `libexec/Keylet.app` and symlinks `keylet` into Homebrew's bin: `brew install NikitaKurpas/tap/keylet`. It publishes to `Formula/keylet.rb` only after a real release ZIP/checksum has been verified against this run's prepared archive. The formula embeds the exact signed executable SHA256; `post_install` verifies it and strict code signing after Homebrew linkage handling. Release preparation uses an AppleDouble-free ZIP and checks an extracted copy for exact binary bytes, strict signing, stapled-ticket validity and Gatekeeper acceptance before publishing. The installer handles either an intact `Keylet.app` or Homebrew’s flattened `Contents` staging layout. Cleaning skips the sealed bundle, and the external service wrapper repeats both gates before launch. No ad-hoc signature repair is allowed. Do not create/repackage bottles for this distribution without reviewing relocation and signature preservation.

The service contract is `KEYLET_KEY_ID=<existing UUID>` in Homebrew’s user configuration directory: `$XDG_CONFIG_HOME/homebrew/services/keylet.env` when `XDG_CONFIG_HOME` is set, otherwise `$HOMEBREW_XDG_CONFIG_HOME/homebrew/services/keylet.env` when that variable is set, otherwise `~/.homebrew/services/keylet.env`. Use the same environment when invoking `brew services`. Homebrew reads that file on service start/restart; it is not sourced as shell code. With separately authorized configuration, run `brew services start keylet` **without sudo** to register a user login service. The external `keylet-agent-service` wrapper executes the intact app via the stable Homebrew `opt` path and validates the UUID before passing it to `agent --key`. Installation itself creates no credential and starts no service. A missing/invalid UUID or changed signature/hash fails closed. Setup of an existing local development archive belongs to the separate setup worker and is not a public release.

Initial releases target Apple Silicon, macOS 26.4+; Homebrew's major-release restriction is supplemented by the bundle/CLI guard. Keep the bundle ID, team/group, Keychain service and record format stable. User-created keys stay local and are never shipped. Stop the service before upgrades, verify installation, then restart it. Development-to-Developer-ID and release-to-release key reuse, actual Homebrew byte preservation, login service behavior and screen-locked/post-reboot signing need explicit runtime verification. Uninstall performs no Keychain/container deletion. See [Homebrew services](https://docs.brew.sh/Manpage#services-subcommand) and [service formula DSL](https://docs.brew.sh/Formula-Cookbook#service-files).
