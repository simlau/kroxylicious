# Levior patch set

This branch (`levior`) is upstream Kroxylicious `v0.25.1` plus a small patch set for the Levior platform.
It adds the `HeaderRecordEncryption` filter, which picks the KEK from a record header, for per-user crypto-shredding.
Design: `simlau-lab/docs` (code.levior.io), `specs/2026-10-22-openbao-crypto-shredding-design.md`, section 3.

Only the record-encryption filter module and the HashiCorp Vault KMS provider are changed.
The project version stays `0.25.1`. Never push to `main` of the fork.

## Changes

Vault KMS provider: only a missing key is "not found". For `decrypt` and `datakey` (`decryptEdek`, `generateDekPair`),
only HTTP 400 whose body contains `encryption key not found` is `UnknownKeyException`. For reading a key (`resolveAlias`),
only HTTP 404 with an empty `errors` list is `UnknownAliasException`. Every other non-200 is a plain `KmsException`: other
400s such as `cipher: message authentication failed`, 403 (wrong namespace or policy), 5xx, and a 404 `no handler for route`,
which Vault and OpenBao return for a wrong mount or path, so a misconfigured `transitEnginePath` never looks like shredded
data. Stock Kroxylicious treats every 400 and 404 as not found.

Decrypt: deliver shredded records. `InBandDecryptionManager` takes a `deliverShredded` flag. When it is set, EDEKs are resolved
per cache key, and a record whose KEK the KMS reports as unknown (`UnknownKeyException`, see above) is delivered as shredded:
value `null`, the `kroxylicious.io/encryption` header removed, all other headers in their order, then `X-Shredded: true`
(UTF-8) appended; key, offset and timestamp unchanged. Other records of the same partition decrypt as usual, and unencrypted
records and tombstones pass through unchanged. Any other KMS error still fails the fetch, and so does a DEK load that
completes without a DEK (a `KmsException`): only `UnknownKeyException` yields a shredded record, because consumers delete data
when they see one. The counter
`kroxylicious_filter_record_encryption_shredded_records` (tags `virtual_cluster`, `topic_name`) counts shredded records.
`DecryptionManager.decrypt` takes a listener for the shredded count, and the filter feeds the counter. The stock `RecordEncryption` filter passes
`false` and keeps the upstream behaviour (`RESOURCE_NOT_FOUND`).

Decrypted-DEK lifetime. New experimental option `decryptedDekExpireAfterWriteSeconds`: how long after being loaded a decrypted
DEK is dropped, however often it is read. It applies to both decrypt-side caches (`DecryptionDekCache` and the decrypted-DEK
cache in `CachingKms`). For the stock `RecordEncryption`, unset means the upstream behaviour: `DecryptionDekCache` has no size
bound and no expiry, so a decrypted DEK stays cached until the proxy restarts. For `HeaderRecordEncryption`, unset means 3600 s
(also when the key is misspelt, since unknown `experimental` keys are ignored), a value of 0 or less is a config error, and the
factory logs the effective lifetime at INFO on start (`Decrypted DEK lifetime: ...`, with `decryptedDekExpireAfterWriteSeconds`
and `defaulted`).

Filter `HeaderRecordEncryption`: the KEK per record from a header. A second filter factory next to the stock
`RecordEncryption`, registered the same way (`@Plugin`, `META-INF/services/io.kroxylicious.proxy.filter.FilterFactory`). It
builds the same KMS stack (instrumented, resilient, caching) and DEK caches from the same `kms`, `kmsConfig` and `experimental`
options (the parsing is shared through `CommonEncryptionConfig`, so `decryptedDekExpireAfterWriteSeconds` reaches both decrypt
caches here too). On produce, every record of the request is checked first: the header value must be 1 to 64 characters from
`[A-Za-z0-9_-]` and occur once; a record carrying `X-Shredded` (any value, any letter case) is a forged shredded marker; a record
carrying `kroxylicious.io/encryption` is a forged encryption header (it could name a missing KEK and be delivered as shredded); with
`missingHeader: REJECT` a record without the header is invalid. Any of these rejects the whole produce request with
`INVALID_RECORD` before any KMS call. Then the distinct aliases (`template` with `$(headerValue)` replaced) are resolved through the
KMS, an unknown alias rejects the request with `INVALID_RECORD` (`unresolvedKeyPolicy: REJECT`, the default here), and each
partition is encrypted in one pass, each record with the current DEK of its own KEK (`EncryptionManager.encryptPerRecord`). Only
the record value is encrypted; the headers, including `X-Kek-Id`, stay in plaintext. A tombstone (`null` value) gets the same
header checks, but its alias is not resolved: it passes through unencrypted, even if its key is gone, and counts as a plain record. On fetch it delivers shredded records
(`deliverShredded`, see above). The proxy never creates keys.

Fetch: the proxy owns `X-Shredded`. With `deliverShredded` (that is, under `HeaderRecordEncryption`), `RecordDecryptor` removes
every `X-Shredded` header, in any letter case, from every fetched record: unencrypted records, decrypted records, and shredded
records before it appends its own. This matches the produce side, which rejects `X-Shredded` in any letter case. The stock
filter leaves headers as they are.

Integration test `HeaderRecordEncryptionOpenBaoIT` runs the filter against OpenBao 2.7.1 (`quay.io/openbao/openbao`, digest
pinned in `OpenBaoTestServer`) and Kafka. It covers two users in one batch, a deleted key (shredded, the consumer reaches the
end offset), a foreign `X-Shredded`, a re-created key and OpenBao down (both fail the fetch, nothing is shredded), and a bad
`X-Kek-Id`. The proxy uses a token with only the proxy policy of `levior/openbao` `tofu/modules/transit-app`, in namespace
`simlau-playground`.

## Consumer contract

What a consumer reading through `HeaderRecordEncryption` gets:

- A shredded record on fetch: value `null`, header `X-Shredded` with value `true` (UTF-8), the encryption header removed, record
  key, offset, timestamp and all other headers (including `X-Kek-Id`) unchanged, in order. It means *cryptographically erased*:
  the record can never be decrypted again. It does not mean that data already materialized from the record downstream is gone.
- The proxy owns `X-Shredded`. Under `HeaderRecordEncryption` a produced record carrying an `X-Shredded` header is rejected
  (`INVALID_RECORD`), and on fetch any `X-Shredded` header already on a record (written by a client that bypassed the proxy, or
  before the proxy existed) is removed. The proxy adds exactly one `X-Shredded: true`, and only to records it shredded. So a
  fetched `X-Shredded: true` always means the proxy found the KEK gone. (Both directions match the header name in any letter
  case.) A produced record carrying `kroxylicious.io/encryption` is rejected the same way, so a client cannot make the proxy
  shred a record by naming a missing KEK in its own encryption header. This guarantee holds for records written through the
  proxy with `missingHeader: REJECT` and `unresolvedKeyPolicy: REJECT`. A client that writes to the brokers directly can store
  an encrypted-looking record naming a missing KEK, and the proxy delivers it as shredded.
- One bad record fails the whole produce request: an invalid or missing `X-Kek-Id`, a reserved header or an unknown key rejects
  every record in the request with `INVALID_RECORD` (non-retriable), including records of other users that the producer batched
  with it. A producer whose send fails with `INVALID_RECORD` may retry that record once on its own.

`null` plus `X-Shredded: true` therefore means cryptographically erased: OpenBao answered that the record's KEK does not exist.
The proxy delivers the record instead of failing the fetch, so the consumer keeps its position and reads on.

A consumer that treats a `null` value as a tombstone gets tombstone-like semantics: a table or cache keyed by the record key
drops the entry. But erasing the KEK does not remove data already materialized downstream. For example, a Kafka Streams
aggregation that ignores `null` values keeps the earlier contributions of the erased records, and a projection that copied the
value into a database keeps that copy. Such apps must handle `X-Shredded` themselves.

A deleted key takes effect on fetch once the proxy's decrypted DEKs of that key have expired, at most
`decryptedDekExpireAfterWriteSeconds` after the fetch that loaded them (3600 s in the Levior config, and the default for
`HeaderRecordEncryption`). Until then, records still decrypt.

Tombstones: a record with a `null` value is never encrypted and passes through unchanged in both directions (on fetch only a
foreign `X-Shredded` is removed). On produce it gets the same header checks as any other record: under `missingHeader: REJECT`
a tombstone without `X-Kek-Id`, a tombstone with an invalid or repeated `X-Kek-Id`, or one carrying `X-Shredded` or
`kroxylicious.io/encryption`, rejects the whole produce request with `INVALID_RECORD`. But its key is not looked up: a
tombstone whose `X-Kek-Id` names a key OpenBao no longer has is accepted, so a compaction delete after the user's key is gone
works.

Other KMS failures are not shredding. A re-created key (OpenBao answers 400 `cipher: message authentication failed`), a wrong
mount (404 `no handler for route`), a wrong namespace or policy (403), 5xx and an unreachable OpenBao fail the fetch: the proxy
closes the connection and the client retries without progress until the cause is fixed. No record is marked shredded.

The proxy policy is a safety interlock, not just least privilege. The proxy token may use only `<mount>/.../user-kek-*` of its
own transit mount. If it could reach another transit mount, a `transitEnginePath` pointing there would answer 400
`encryption key not found` for every key, and every record would be delivered as shredded, so consumers would delete their
state. Keep the policy scoped to the one mount and the `user-kek-` prefix.

## Behaviour change for the stock filter

The Vault KMS provider jar is shared by both filters, so the stricter not-found mapping (see "Changes") also applies to the stock
`RecordEncryption` filter with `kms: VaultKmsService`:

| Vault/OpenBao answer | Upstream | This branch |
|---|---|---|
| `decrypt`/`datakey`: 400 `encryption key not found` | `UnknownKeyException` | same |
| `decrypt`/`datakey`: other 400, e.g. `cipher: message authentication failed` (key re-created under the same name) | `UnknownKeyException`: the fetch answers `RESOURCE_NOT_FOUND` (91) | `KmsException`: the proxy closes the connection |
| `decrypt`/`datakey`: 404 `no handler for route` (wrong mount or path) | `UnknownKeyException`: 91 | `KmsException`: the proxy closes the connection |
| read `keys/<name>`: 404 with an empty `errors` list | `UnknownAliasException` | same |
| read `keys/<name>`: 404 `no handler for route`, or any 400 | `UnknownAliasException`: with the stock default `unresolvedKeyPolicy: PASSTHROUGH_UNENCRYPTED` the records are stored unencrypted | `KmsException`: the produce request fails |

Why: a wrong `transitEnginePath` or a re-created key is a configuration or operations error, not a missing key. Upstream
reports it as a missing key, so on fetch it looks like deleted data, and on produce a mistyped mount silently stores plaintext
under the stock default policy. For `HeaderRecordEncryption` it would be worse: a missing key means shredded, so a wrong mount
would deliver every record as erased. Now these errors fail loudly and the client retries.

This is a bug fix independent of the header KEK. It goes upstream as a separate pull request (Vault provider only), before or
without the `HeaderRecordEncryption` filter.

## Config reference: `HeaderRecordEncryption`

```yaml
filterDefinitions:
  - name: encrypt
    type: HeaderRecordEncryption
    config:
      kms: VaultKmsService
      kmsConfig:
        vaultUrl: http://openbao-active.openbao.svc:8200
        vaultNamespace: simlau-lab   # or the path prefix /v1/simlau-lab
        transitEnginePath: transit
        credentials:
          kubernetes:
            vaultRole: proxy
      selector: HeaderKekSelector
      selectorConfig:
        header: X-Kek-Id
        template: "user-kek-$(headerValue)"
        missingHeader: REJECT
      unresolvedKeyPolicy: REJECT
      experimental:
        decryptedDekExpireAfterWriteSeconds: 3600
defaultFilters: [encrypt]
```

| Field | Required | Default | Meaning |
|---|---|---|---|
| `kms`, `kmsConfig` | yes | | As for `RecordEncryption`. |
| `selector` | yes | | Must be `HeaderKekSelector`; anything else is a config error. |
| `selectorConfig.header` | yes | | Record header holding the KEK id, matched case-sensitively. |
| `selectorConfig.template` | yes | | KEK alias; must contain `$(headerValue)` exactly once and no other placeholder. |
| `selectorConfig.missingHeader` | no | `REJECT` | `REJECT` or `PASSTHROUGH_UNENCRYPTED` for a record without the header. |
| `unresolvedKeyPolicy` | no | `REJECT` | `REJECT` or `PASSTHROUGH_UNENCRYPTED` for a header naming a key the KMS doesn't have (stock default is `PASSTHROUGH_UNENCRYPTED`). |
| `experimental` | no | | The same options as `RecordEncryption`, including `decryptedDekExpireAfterWriteSeconds`, which here defaults to `3600` and must be positive. |

Caches still apply on produce: a resolved alias is cached for up to `resolvedAliasExpireAfterWriteSeconds` (10 min) and the
current DEK of a KEK for up to `encryptionDekExpireAfterWriteSeconds` (2 h). A record produced shortly after its key was deleted
can therefore still be encrypted with the cached DEK instead of being rejected. OpenBao can no longer decrypt its EDEK, so it
reads as shredded.

## Build and test

Java 21 (Temurin), Maven 3.9, Docker for Testcontainers. The repo has no Maven wrapper.

    export TESTCONTAINERS_RYUK_DISABLED=true

Build and unit test the two modules (and what they depend on):

    mvn -B -pl kroxylicious-filters/kroxylicious-record-encryption,kroxylicious-kms-providers/kroxylicious-kms-provider-hashicorp-vault -am -DskipITs verify

Integration tests of record encryption:

    mvn -B -pl kroxylicious-integration-tests -am -DskipUTs -Dit.test='RecordEncryption*IT,HeaderRecordEncryptionOpenBaoIT' -Dsurefire.failIfNoSpecifiedTests=false -Dfailsafe.failIfNoSpecifiedTests=false verify

The `RecordEncryption*IT` tests run once per KMS test facade (Vault and others in Testcontainers). Five runs of one test are
skipped by upstream assumptions. `HeaderRecordEncryptionOpenBaoIT` runs against its own OpenBao 2.7.1 container.
On macOS with Docker Desktop also set `DOCKER_HOST=unix:///Users/<you>/.docker/run/docker.sock`.
The workflow `.github/workflows/levior.yaml` runs the same two commands on every push and pull request to `levior`.
The steps live in the composite action `.github/actions/levior-build`, shared with the release workflow.

## Rebase onto a new upstream tag

    git fetch upstream tag <new tag> --no-tags
    git rebase --onto <new tag> v0.25.1 levior

Then update the version everywhere it is hardcoded, and run the build above:

- this file (the `v0.25.1` and `0.25.1` mentions);
- `.github/workflows/levior-release.yaml`: the tag filter `v0.25.1-levior.*` and the jar paths `...-0.25.1.jar` in the
  "Collect assets" step. If the tag filter is not updated, a `v<new>-levior.1` tag triggers no release, and nothing reports it.

## Release

Pushing a tag `v0.25.1-levior.<N>` runs `.github/workflows/levior-release.yaml`. It fails unless the tagged commit is
reachable from `origin/levior`, runs the same build and tests as `levior.yaml`, and creates the GitHub Release with
`kroxylicious-record-encryption-0.25.1-levior.<N>.jar`, `kroxylicious-kms-provider-hashicorp-vault-0.25.1-levior.<N>.jar`
and `SHA256SUMS`. It uses only `GITHUB_TOKEN`, and only the "Create release" step gets it: the checkout does not persist
credentials, so the build and tests run without a write-scoped token.

To release: wait for a green `levior` run on the commit (`gh run list -R simlau/kroxylicious -b levior`; `cancel-in-progress`
can cancel runs, so tag only a commit with a successful run), then

    git tag -a v0.25.1-levior.<N> -m "levior release <N>"
    git push origin v0.25.1-levior.<N>
