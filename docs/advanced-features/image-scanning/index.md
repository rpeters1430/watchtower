# Image Scanning

With `--scan` turned on, Watchtower scans images with [Trivy](https://trivy.dev) during each update cycle and tells you which known vulnerabilities an update fixes.
Configuration options are listed under [Image Scanning](../../configuration/image-scanning/index.md).

## How It Works

1. Watchtower checks containers for updates and pulls new images as usual.
2. For each container that will update, Watchtower scans the new image and the running image.
   It runs Trivy in a short-lived container on the same Docker daemon, with the Docker socket mounted so Trivy reads the local images.
3. Watchtower compares the two scans: findings the new image no longer has are **fixed**, findings only the new image has are **introduced**.
4. With a [scan gate](../../configuration/image-scanning/index.md#scan-gate) set, an update whose new image introduces findings at or above the gate is held.
   The container keeps running and is reported as skipped with the findings that held it.
5. After the update, notifications list the vulnerabilities it fixed, for example:

    ```text
    Updated web fixed 2 known vulnerabilities: CVE-2024-0001 (critical), CVE-2024-0003 (high)
    ```

Results are cached by image ID, so an image is scanned once even if its update waits across several cycles.

## Requirements

- Watchtower must be able to create containers on the Docker daemon, which it already does to update them.
- The first scan downloads Trivy's vulnerability database (a few hundred MB) into the `watchtower-trivy-cache` volume.
- Scanner containers are labelled `com.centurylinklabs.watchtower.enable=false` and `com.centurylinklabs.watchtower.scanner=true`, so Watchtower never tries to update them. They are removed after each scan.

## Example

```yaml
services:
  watchtower:
    image: ghcr.io/rpeters1430/watchtower:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      WATCHTOWER_SCAN: "true"
      WATCHTOWER_SCAN_GATE: critical
```

## Failure Handling

Scanning never blocks an update on its own. If the scanner image cannot be pulled, a scan times out, or Trivy fails, Watchtower logs a warning and updates without a security review.
Only the opt-in scan gate can hold an update, and only when a scan succeeded.
If the running image cannot be scanned, every finding of the new image counts as introduced, which errs on the side of holding when a gate is set.

## Limitations

- Trivy is the only scanner so far.
- Containers built from a Git source are not scanned, because their new image does not exist until it is built.
- Scanning needs the Docker socket on the host. A remote daemon or socket proxy without a local socket is not supported yet.
