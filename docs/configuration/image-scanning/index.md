# Image Scanning

Watchtower can scan the new image of each pending update with [Trivy](https://trivy.dev) or [Grype](https://github.com/anchore/grype) before it replaces a container.
Scanning is on by default; set `--scan=false` to update without it. See [Image Scanning](../../advanced-features/image-scanning/index.md) for how it works.

`scan`, `scan-gate`, and `scanner` set the starting values. All three can be changed while Watchtower runs, from the web UI's Settings page or the [settings endpoint](../../http-api/endpoints/settings/index.md).

## Scan

Scans the new image of each pending update, and the image it replaces, for known vulnerabilities (and, with Trivy, secrets and image configuration problems).
Notifications then list the vulnerabilities each update fixed, the web UI shows each scan's progress on the Containers view while the update runs, and the Security view lists what the update fixed and brought in.
Images are scanned one at a time, so an update of many containers takes longer with scanning on.

```text
            Argument: --scan
Environment Variable: WATCHTOWER_SCAN
                Type: Boolean
             Default: true
```

!!! Note
    A scan that fails or times out never stops an update. Watchtower logs a warning and updates without a review.

## Scan Gate

Holds an update when its new image adds findings at or above this severity that the running image does not have.
A held container keeps running its current image and is reported as skipped, with the findings that held it.
Findings both images share never hold an update, since skipping it would not remove them.

```text
            Argument: --scan-gate
Environment Variable: WATCHTOWER_SCAN_GATE
     Possible Values: off, low, medium, high, critical
             Default: off
```

## Scanner

The scanner that scans images. Trivy also checks images for leaked secrets and risky settings; Grype checks for known vulnerabilities only, using Anchore's database.
Each scanner keeps its own results cache and vulnerability database volume, so switching back and forth does not mix their findings.

```text
            Argument: --scanner
Environment Variable: WATCHTOWER_SCANNER
     Possible Values: trivy, grype
             Default: trivy
```

!!! Note
    Watchtower pulls the scanner image again once a day, so a tag such as `latest` follows new scanner releases, and removes the image it replaced.
    If that pull fails, the image already present is used. An image pinned by digest (`name@sha256:…`) is never pulled again.

## Scan Image

The Trivy image Watchtower runs to scan images. Pin a version, or point at a mirror, to control which scanner runs.

```text
            Argument: --scan-image
Environment Variable: WATCHTOWER_SCAN_IMAGE
                Type: String
             Default: aquasec/trivy:latest
```

## Scan Grype Image

The Grype image Watchtower runs when the scanner is `grype`. Grype's vulnerability database is kept in the `watchtower-grype-cache` volume.

```text
            Argument: --scan-grype-image
Environment Variable: WATCHTOWER_SCAN_GRYPE_IMAGE
                Type: String
             Default: anchore/grype:latest
```

## Scan Timeout

Bounds the scan of one image. The first scan also downloads the scanner's vulnerability database, so allow time for it.
Scans run one at a time, because every scan shares the cache volume, and the timeout only starts once a scan's turn comes.
Large images, such as ones bundling machine learning models, can take longer than the default on slow disks; raise this if a scan fails with "scan did not finish in time".

```text
            Argument: --scan-timeout
Environment Variable: WATCHTOWER_SCAN_TIMEOUT
                Type: Duration
             Default: 15m
```

## Scan Ignore Unfixed

Leaves out vulnerabilities that have no published fix, so reports and the gate only count findings an update could fix.

```text
            Argument: --scan-ignore-unfixed
Environment Variable: WATCHTOWER_SCAN_IGNORE_UNFIXED
                Type: Boolean
             Default: false
```

## Scan Secrets

Checks each image for secrets, such as private keys, passwords, and API tokens, left in its files. Only Trivy checks for secrets. The check reads every file of every layer, which is often most of a scan's time on large images, so turning it off makes Trivy scans much faster. Vulnerabilities and image configuration problems are still checked.

The setting can also be changed while Watchtower runs, from the web UI's Settings page or through [`/v1/settings`](../../http-api/endpoints/settings/index.md). Results with and without the check are cached separately, so a scan of one kind is never compared with the other.

```text
            Argument: --scan-secrets
Environment Variable: WATCHTOWER_SCAN_SECRETS
                Type: Boolean
             Default: true
```

## Scan Cache Volume

The Docker volume that keeps Trivy's vulnerability database between scans. Docker creates it on first use. Grype always uses `watchtower-grype-cache`.

```text
            Argument: --scan-cache-volume
Environment Variable: WATCHTOWER_SCAN_CACHE_VOLUME
                Type: String
             Default: watchtower-trivy-cache
```

## Scan Docker Socket

The host path of the Docker socket mounted into the scanner container, so the scanner reads images from the local daemon.
Change it when the daemon's socket lives elsewhere on the host, for example with rootless Docker.

```text
            Argument: --scan-docker-socket
Environment Variable: WATCHTOWER_SCAN_DOCKER_SOCKET
                Type: String
             Default: /var/run/docker.sock
```
