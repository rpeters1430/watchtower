# Upstream review and backport log

This fork tracks [nicholas-fedor/watchtower](https://github.com/nicholas-fedor/watchtower), but has substantial fork-specific work in the API, web UI, security scanning, and update orchestration. Review upstream changes individually; do not merge upstream wholesale.

## Review checkpoint

- **Reviewed through:** upstream `main` commit [10e23dc](https://github.com/nicholas-fedor/watchtower/commit/10e23dc45b0390f493f16cd69de766718467a7df)
- **Review date:** 2026-11-10
- **Fork:** [rpeters1430/watchtower](https://github.com/rpeters1430/watchtower)
- **Compare:** upstream has moved substantially beyond the fork, so commit counts alone are not a useful measure of missing fixes. Check the fork for equivalent behavior before backporting.

## Reviewed fixes

| Upstream change | Decision | Notes |
| --- | --- | --- |
| [#3361](https://github.com/nicholas-fedor/watchtower/commit/6ec954fcd5192d0fa90a9d38543d4def56cc6821) — redact notification service URLs in send errors | **Merged** in [fork PR #191](https://github.com/rpeters1430/watchtower/pull/191) | Uses the fork's existing `redactServiceURL` helper so credentials embedded in service hostnames are not exposed. |
| [#3053](https://github.com/nicholas-fedor/watchtower/pull/3053) — skip health waiting when health checks are disabled | **Already covered** | Fork's `pkg/container/client.go` recognizes Docker health-check config `Test: ["NONE"]`. |
| [#3032](https://github.com/nicholas-fedor/watchtower/pull/3032) — protect registry credentials and redact redirect URLs | **Already substantially covered** | Fork's registry auth client redacts redirect errors, and the digest client has redirect retry handling. Recheck token forwarding if that code is changed. |
| [#3675](https://github.com/nicholas-fedor/watchtower/commit/c4c25ea882c44e4065a8476f0e99b7cda147ea23) — stop an update session when its dependency graph cannot be built | **Implementing on branch** | Adapted to return before pre-check lifecycle hooks and registry/image checks. See the accompanying change to `internal/actions/update.go`. |
| [#3679](https://github.com/nicholas-fedor/watchtower/commit/2caed6e92f5f983b0993c5affa0ddc1dc723ea7d) — skip self-dependent containers fully | **Deferred** | The fork already skips explicit label-based self-dependencies. Upstream also detects Compose service self-references and changes which indirect restarts are allowed; that needs a focused review of the fork's graph and reporting behavior. |
| [#3657](https://github.com/nicholas-fedor/watchtower/commit/fd298d9cbd170bec588c01f06f13b4f166503f92) — distinguish exec'd health probes from the main process on OpenVZ | **Deferred** | This changes process detection using `/proc/1/task/1/children`. The fork has custom startup and self-update behavior; port only with coverage for supported kernels and restart-policy handling. |

## Follow-up

When reviewing new upstream changes, record the upstream commit or PR, the fork behavior checked, and whether the change was merged, already covered, adapted, or deferred. Keep backports small enough to review independently.
