# Local Docker references: export, then scan

`1337 image export-local` supports a selected local Docker image on Linux.
It exports one exact tagged local reference or full `sha256:` config ID through
an explicitly selected trusted Docker client and physical Unix socket. The
export is a separate governed operation; it does not run a vulnerability scanner.
ADR [0114](adr/0114-governed-local-image-reference-export.md) describes the boundary.

## Select and plan the source

Use an existing workspace, explicit read-consent actor/reference, trusted absolute
Docker executable and actual physical local socket. The default socket is
`/run/docker.sock`; an alias such as `/var/run/docker.sock` is refused when its
parent is a symlink. Ambient `DOCKER_HOST`, contexts, credential configuration,
proxy variables and implicit `latest` tags are not selected.

```sh
1337 image export-local /absolute/workspace \
  --reference owned/example:reviewed \
  --owner actor:operator \
  --executable /usr/bin/docker \
  --socket /run/docker.sock \
  --read-consent-reference read:local-image-approval \
  --plan --json
```

Planning does not read selected material, contact Docker, create a workspace,
register scope or issue a grant. Review the exact descriptor and its
`target.value`. Register that target with independently recorded operator consent:

```sh
1337 scope create /absolute/workspace --id local-source \
  --allow-artifact 'manifest-sha256:<reviewed-source-target-digest>' \
  --grant-consent --owner attester:separate-operator \
  --consent-reference consent:local-source \
  --valid-from '<aware-ISO8601-start>' --valid-until '<aware-ISO8601-end>'
```

Replace the explicit placeholders with reviewed values. The source policy is a
separate strict `ImpactPolicy` document, for example:

```json
{
  "max_authorization_seconds": 300,
  "maximum_impact": "SAFE",
  "permissions": [{
    "adapter_id": "native.docker-local",
    "capability_id": "image.local-reference-export",
    "granted_privileges": ["local-docker-read"],
    "maximum_impact": "SAFE"
  }],
  "policy_id": "local-source",
  "revision": 0
}
```

## Approve the bounded export

Repeat the same selected inputs, replacing `--plan` with the independently
registered source scope, policy file and explicit workflow approval:

```sh
1337 image export-local /absolute/workspace \
  --reference owned/example:reviewed --owner actor:operator \
  --executable /usr/bin/docker --socket /run/docker.sock \
  --read-consent-reference read:local-image-approval \
  --scope local-source --policy /absolute/local-source-policy.json \
  --approve-local-image --json
```

The product inspects the supplied local reference, saves only its resolved full
config ID, verifies the selected config bytes in the bounded Docker-save archive,
and inspects the original reference again. A reassigned reference refuses
acceptance. It never pulls an image, talks to a registry, creates/starts a
container, loads/builds an image or extracts archive paths.

Each command requires its own original grant and durable one-use claim, with
current source scope, policy, actor, material and expiry rechecked before launch,
acceptance and final publication. Commands use a private empty config/environment
and the existing Linux descendant executor. Inspect stdout is capped at 1 MiB,
export stdout at 64 MiB and stderr at 64 KiB; command deadlines are 10/30/10
seconds. These boundaries are observations and finite process/output budgets,
not a hostile-writer exclusion or a real-time filesystem guarantee.

A successful summary reports `state: completed`, `workspace_acknowledged: true`,
`archive_relative_path`, `archive_sha256`, `image_config_id`, `archive_manifest`,
`archive_target`, and the original evidence record references. The complete
archive is created exclusively under the owning workspace. Archive byte hash,
image config ID and source descriptor target have different meanings. Failure,
unknown cleanup or uncertain persistence never returns an accepted archive pin;
original acquisitions may remain as failed-job evidence. A generated archive
file surviving a later failed acknowledgement is not proof of accepted export.

## Independently approve and scan the archive

Review the accepted archive target, byte hash and config ID. Register the returned
`archive_target.value` in a **separate** explicit `local-archive` scope using the
same `scope create` command pattern. Supply a separate policy permission for
`native.trivy` / `image.archive-vulnerabilities`, with an empty
`granted_privileges` array. Export authority never registers or approves this
second target.

Use the existing native archive workflow with the returned workspace-relative
archive path and the expected config ID from the verified export summary:

```sh
1337 scan image /absolute/workspace --profile native \
  --archive '<archive_relative_path-from-accepted-export>' \
  --cache-directory trivy-cache --executable /absolute/trusted-trivy \
  --owner actor:operator --read-consent-reference read:native-archive \
  --scope local-archive --policy /absolute/native-image-policy.json \
  --expected-config-id 'sha256:<accepted-export-config-digest>' \
  --approve-safe-image --json
1337 workspace open /absolute/workspace --json
```

The operator selects the already provisioned trusted native binary and cache;
this recipe does not provision or update scanner material. Native planning also
accepts `--expected-config-id`, preserving it in immutable admission intent.
The fresh verified native report's `Metadata.ImageID` must equal that exact config
identity **before** candidates are projected or the model is saved. A preexisting
Asset cannot satisfy the comparison. Omitting the optional pin preserves the
existing archive-only behavior; the documented local-reference recipe requires it.

The dedicated ordinary CI lane builds and installs the wheel, provisions a private
containerd/Docker pair in a no-egress namespace, and uses only the two existing
inert package-metadata images. Its selected advisory/config/package/model/reopen
assertions and actual lifecycle/JUnit receipts are required for genuine product
acceptance. Source, inert unit outcomes, collection, or a draft marker alone do
not establish that acceptance or general image-scan completeness.

The test owner pins Linux process handles before signaling, keeps direct child
wait statuses with their original process owner, and places temporary daemon
state under the physical root-owned `/run` parent. The unprivileged test actor
cannot replace that directory entry during cleanup. The artifact retains the
actual bounded saved workspace/model/scope stores and evidence, including partial
stores after a test failure; selected scanner binaries, caches and standalone
`image.tar` files are excluded. Original acquired archive stdout remains in
evidence. A successful case reopens the retained copy before claiming its
saved model result. This describes the owned CI fixture, not a product daemon.
