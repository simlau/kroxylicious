# Levior patch set

This branch (`levior`) is upstream Kroxylicious `v0.25.1` plus a small patch set for the Levior platform.
It adds the `HeaderRecordEncryption` filter, which picks the KEK from a record header, for per-user crypto-shredding.
Design: `levior/infra`, `docs/superpowers/specs/2026-10-22-openbao-crypto-shredding-design.md`, section 3.

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
records and tombstones pass through unchanged. Any other KMS error still fails the fetch. The counter
`kroxylicious_filter_record_encryption_shredded_records` (tags `virtual_cluster`, `topic_name`) counts shredded records.
`DecryptionManager.decrypt` takes a listener for the shredded count, and the filter feeds the counter. The stock `RecordEncryption` filter passes
`false` and keeps the upstream behaviour (`RESOURCE_NOT_FOUND`).

Decrypted-DEK lifetime. New experimental option `decryptedDekExpireAfterWriteSeconds`: how long after being loaded a decrypted
DEK is dropped, however often it is read. It applies to both decrypt-side caches (`DecryptionDekCache` and the decrypted-DEK
cache in `CachingKms`). Unset means the upstream behaviour (no hard lifetime).

Filter `HeaderRecordEncryption`: the KEK per record from a header. A second filter factory next to the stock
`RecordEncryption`, registered the same way (`@Plugin`, `META-INF/services/io.kroxylicious.proxy.filter.FilterFactory`). It
builds the same KMS stack (instrumented, resilient, caching) and DEK caches from the same `kms`, `kmsConfig` and `experimental`
options (the parsing is shared through `CommonEncryptionConfig`, so `decryptedDekExpireAfterWriteSeconds` reaches both decrypt
caches here too). On produce, every record of the request is checked first: the header value must be 1 to 64 characters from
`[A-Za-z0-9_-]` and occur once; a record carrying `X-Shredded` (any value, any letter case) is a forged shredded marker; with
`missingHeader: REJECT` a record without the header is invalid. Any of these rejects the whole produce request with
`INVALID_RECORD` before any KMS call. Then the distinct aliases (`template` with `$(headerValue)` replaced) are resolved through the
KMS, an unknown alias rejects the request with `INVALID_RECORD` (`unresolvedKeyPolicy: REJECT`, the default here), and each
partition is encrypted in one pass, each record with the current DEK of its own KEK (`EncryptionManager.encryptPerRecord`). Only
the record value is encrypted; the headers, including `X-Kek-Id`, stay in plaintext. On fetch it delivers shredded records
(`deliverShredded`, see above). The proxy never creates keys.

More entries are added by later tasks.

## Config reference: `HeaderRecordEncryption`

```yaml
filterDefinitions:
  - name: encrypt
    type: HeaderRecordEncryption
    config:
      kms: VaultKmsService
      kmsConfig:
        vaultUrl: http://openbao-active.openbao.svc:8200
        vaultNamespace: simlau-playground   # or the path prefix /v1/simlau-playground
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
| `experimental` | no | | The same options as `RecordEncryption`, including `decryptedDekExpireAfterWriteSeconds`. |

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

    mvn -B -pl kroxylicious-integration-tests -am -DskipUTs -Dit.test='RecordEncryption*IT' -Dsurefire.failIfNoSpecifiedTests=false -Dfailsafe.failIfNoSpecifiedTests=false verify

The tests run once per KMS test facade (Vault and others in Testcontainers). Five runs of one test are skipped by upstream assumptions.
On macOS with Docker Desktop also set `DOCKER_HOST=unix:///Users/<you>/.docker/run/docker.sock`.
The workflow `.github/workflows/levior.yaml` runs the same two commands on every push and pull request to `levior`.

## Rebase onto a new upstream tag

    git fetch upstream tag <new tag> --no-tags
    git rebase --onto <new tag> v0.25.1 levior

Then update the `v0.25.1` mentions in this file and run the build above.

## Release

Described by Task 6 of the plan (tags `v0.25.1-levior.<N>`). Not set up yet.
