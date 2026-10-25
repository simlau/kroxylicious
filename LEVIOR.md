# Levior patch set

This branch (`levior`) is upstream Kroxylicious `v0.25.1` plus a small patch set for the Levior platform.
It adds the `HeaderRecordEncryption` filter, which picks the KEK from a record header, for per-user crypto-shredding.
Design: `levior/infra`, `docs/superpowers/specs/2026-10-22-openbao-crypto-shredding-design.md`, section 3.

Only the record-encryption filter module and the HashiCorp Vault KMS provider are changed.
The project version stays `0.25.1`. Never push to `main` of the fork.

## Changes

Filled in by later tasks. Empty so far.

## Build and test

Java 21 (Temurin), Maven 3.9, Docker for Testcontainers. The repo has no Maven wrapper.

    export TESTCONTAINERS_RYUK_DISABLED=true

Build and unit test the two modules (and what they depend on):

    mvn -B -pl kroxylicious-filters/kroxylicious-record-encryption,kroxylicious-kms-providers/kroxylicious-kms-provider-hashicorp-vault -am -DskipITs verify

Integration tests of record encryption:

    mvn -B -pl kroxylicious-integration-tests -am -DskipUTs -Dit.test='RecordEncryption*IT' -Dsurefire.failIfNoSpecifiedTests=false -Dfailsafe.failIfNoSpecifiedTests=false verify

The tests run once per KMS test facade (5 runs of 22 tests, Vault and others in Testcontainers). Five runs of one test are skipped by upstream assumptions.
On macOS with Docker Desktop also set `DOCKER_HOST=unix:///Users/<you>/.docker/run/docker.sock`.
The workflow `.github/workflows/levior.yaml` runs the same two commands on every push and pull request to `levior`.

## Rebase onto a new upstream tag

    git fetch upstream tag <new tag> --no-tags
    git rebase --onto <new tag> v0.25.1 levior

Then update the tag in this file and in the workflow expectations, and run the build above.

## Release

Described by Task 6 of the plan (tags `v0.25.1-levior.<N>`). Not set up yet.
