# Levior patch set

This branch (`levior`) is upstream Kroxylicious `v0.25.1` plus a small patch set for the Levior platform.
It adds the `HeaderRecordEncryption` filter, which picks the KEK from a record header, for per-user crypto-shredding.
Design: `levior/infra`, `docs/superpowers/specs/2026-10-22-openbao-crypto-shredding-design.md`, section 3.

Only the record-encryption filter module and the HashiCorp Vault KMS provider are changed.
The project version stays `0.25.1`. Never push to `main` of the fork.

## Changes

Vault KMS provider: only a missing key is "not found". `VaultKms` maps HTTP 404, and HTTP 400 whose body contains
`encryption key not found`, to `UnknownKeyException` / `UnknownAliasException`. Every other non-200 (other 400s such as
`cipher: message authentication failed`, 403, 5xx) is a plain `KmsException`. Stock Kroxylicious treats every 400 as not found.

More entries are added by later tasks.

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

Then update the `v0.25.1` mentions in this file and in `.github/workflows/levior.yaml`, and run the build above.

## Release

Described by Task 6 of the plan (tags `v0.25.1-levior.<N>`). Not set up yet.
