# Image Scanning

Watchtower can scan the new image of each pending update with [Trivy](https://trivy.dev) before it replaces a container.
Scanning is off by default. See [Image Scanning](../../advanced-features/image-scanning/index.md) for how it works.

`scan` and `scan-gate` set the starting values. Both can be changed while Watchtower runs, from the web UI's Settings page or the [settings endpoint](../../http-api/endpoints/settings/index.md).

## Scan

Scans the new image of each pending update, and the image it replaces, for known vulnerabilities, secrets, and image configuration problems.
Notifications then list the vulnerabilities each update fixed.

```text
            Argument: --scan
Environment Variable: WATCHTOWER_SCAN
                Type: Boolean
             Default: false
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

## Scan Image

The Trivy image Watchtower runs to scan images. Pin a version, or point at a mirror, to control which scanner runs.

```text
            Argument: --scan-image
Environment Variable: WATCHTOWER_SCAN_IMAGE
                Type: String
             Default: aquasec/trivy:latest
```

## Scan Timeout

Bounds the scan of one image. The first scan also downloads Trivy's vulnerability database, so allow time for it.

```text
            Argument: --scan-timeout
Environment Variable: WATCHTOWER_SCAN_TIMEOUT
                Type: Duration
             Default: 5m
```

## Scan Ignore Unfixed

Leaves out vulnerabilities that have no published fix, so reports and the gate only count findings an update could fix.

```text
            Argument: --scan-ignore-unfixed
Environment Variable: WATCHTOWER_SCAN_IGNORE_UNFIXED
                Type: Boolean
             Default: false
```

## Scan Cache Volume

The Docker volume that keeps Trivy's vulnerability database between scans. Docker creates it on first use.

```text
            Argument: --scan-cache-volume
Environment Variable: WATCHTOWER_SCAN_CACHE_VOLUME
                Type: String
             Default: watchtower-trivy-cache
```

## Scan Docker Socket

The host path of the Docker socket mounted into the scanner container, so Trivy reads images from the local daemon.
Change it when the daemon's socket lives elsewhere on the host, for example with rootless Docker.

```text
            Argument: --scan-docker-socket
Environment Variable: WATCHTOWER_SCAN_DOCKER_SOCKET
                Type: String
             Default: /var/run/docker.sock
```
